#!/usr/bin/env python3
import json
import os
import subprocess
import time
import urllib.request
import urllib.parse
import uuid

# IT Sensor Agent (Mock for XDP/eBPF Context Binder)
# This script monitors the IT network (e.g., jump_server interface) for incoming attack traffic,
# generates a Trace ID, and stores the Context (Attacker IP -> Internal IP) into Webdis.

def monitor_and_bind():
    print("[*] Starting IT Sensor Agent (Context Binder) on JumpServer ingress...", flush=True)
    webdis_base = os.environ.get("WEBDIS_URL", "http://10.0.10.15:7379")
    
    cmd = ["docker", "exec", "jump_server", "tcpdump", "-l", "-i", "eth0", "-n", "udp", "dst", "port", "20000"]
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    print("[*] Listening for DNP3 traffic on JumpServer (eth0)...", flush=True)
    
    try:
        for line in process.stdout:
            if " UDP, length " in line:
                parts = line.split()
                try:
                    src_ip_port = parts[2]
                    dst_ip_port = parts[4].strip(":")
                    
                    attacker_ip = ".".join(src_ip_port.split(".")[:-1])
                    jumpserver_ip = ".".join(dst_ip_port.split(".")[:-1])
                    
                    trace_id = uuid.uuid4().hex
                    parent_span_id = uuid.uuid4().hex[:16]
                    
                    ot_target_ip = "10.0.30.10"
                    raw_key = f"{jumpserver_ip}-{ot_target_ip}-5"
                    
                    context_data = {
                        "trace_id": trace_id,
                        "parent_span_id": parent_span_id,
                        "attacker_ip": attacker_ip,
                        "pivot_ip": jumpserver_ip
                    }
                    
                    payload = json.dumps(context_data)
                    encoded_payload = urllib.parse.quote(payload)
                    webdis_url = f"{webdis_base}/SET/{raw_key}/{encoded_payload}/EX/30"
                    
                    req = urllib.request.Request(webdis_url, method="GET")
                    with urllib.request.urlopen(req, timeout=2) as resp:
                        pass
                        
                    print(f"[+] Pivot Detected! Bound {attacker_ip} -> {jumpserver_ip} with TraceID {trace_id}", flush=True)
                    
                except Exception as e:
                    print(f"[-] Error processing packet: {e}", flush=True)
                    
    except KeyboardInterrupt:
        print("[*] Stopping IT Sensor Agent.")
    finally:
        process.terminate()

if __name__ == "__main__":
    monitor_and_bind()
