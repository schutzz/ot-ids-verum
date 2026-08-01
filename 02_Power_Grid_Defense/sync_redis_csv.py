#!/usr/bin/env python3
import urllib.request
import urllib.parse
import json
import time
import os
import traceback

WEBDIS_URL = "http://localhost:7379"
CSV_PATH = "vector/webdis_cache.csv"

def sync_redis_to_csv():
    print("[Sync] Starting Redis to CSV synchronizer for Vector...")
    if not os.path.exists("vector"):
        os.makedirs("vector")
        
    while True:
        try:
            # Get all keys
            req = urllib.request.Request(f"{WEBDIS_URL}/KEYS/*")
            with urllib.request.urlopen(req, timeout=1) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                keys = data.get("KEYS", [])
            
            records = []
            for k in keys:
                # Webdis returns keys, get values
                v_req = urllib.request.Request(f"{WEBDIS_URL}/GET/{k}")
                with urllib.request.urlopen(v_req, timeout=1) as v_resp:
                    v_data = json.loads(v_resp.read().decode('utf-8'))
                    val_str = v_data.get("GET")
                    if val_str:
                        try:
                            # Parse inner JSON payload: {"trace_id": "...", "parent_span_id": "..."}
                            # import urllib.parse  (Moved to top)
                            decoded_val_str = urllib.parse.unquote(val_str)
                            val = json.loads(decoded_val_str)
                            trace_id = val.get("trace_id", "")
                            parent_span_id = val.get("parent_span_id", "")
                            records.append(f"{k},{trace_id},{parent_span_id}")
                        except json.JSONDecodeError:
                            # Fallback if it's just a raw trace_id (for backward compatibility)
                            records.append(f"{k},{val_str},")
            
            # Write atomically always, even if empty, so TTL expirations clear the cache
            temp_path = f"{CSV_PATH}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                f.write("hash_key,trace_id,parent_span_id\n")
                if records:
                    f.write("\n".join(records) + "\n")
            os.replace(temp_path, CSV_PATH)
            
            # --- Trigger Vector Enrichment Table Reload ---
            import subprocess
            try:
                subprocess.run(
                    ["docker", "exec", "vector", "wget", "-q", "-O", "-", "--post-data", "", "http://localhost:8686/enrichment_tables/webdis_table/reload"],
                    check=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception as re:
                print(f"Failed to trigger Vector reload: {re}")
                
        except Exception as e:
            print(f"Sync error: {e}")
            pass
            
        time.sleep(1)

if __name__ == "__main__":
    sync_redis_to_csv()
