#!/usr/bin/env python3
"""
Step 2: External E2E Pivot Attack Module

目的:
1. WAN側 (external_attacker: 172.16.0.99) から JumpServer (172.16.0.100) への不正アクセス (conn.log 生成)
2. Trace ID 生成と JumpServer IP (172.16.0.100) をキーにした Redis OOB バインド (TTL 300)
3. JumpServer から Substation B (10.0.30.10) への DNP3 FC 0x05 / SNMP 射出 (dnp3.log 生成)
"""

import json
import time
import uuid
import urllib.request
import urllib.parse
import subprocess

# IPs
ATTACKER_IP = "172.16.0.99"
JUMPSERVER_IP = "172.16.0.100"
TARGET_RTU_IP = "10.0.30.10"
WEBDIS_URL = "http://oob_webdis:7379"

def execute_e2e_pivot_attack():
    print("[+] Starting E2E Pivot Attack from WAN (172.16.0.99) to OT (10.0.30.10)")
    
    # 1. 生成 Trace ID
    trace_id = uuid.uuid4().hex
    print(f"    -> [Token Auth] Generated E2E Trace ID: {trace_id}")
    
    # 2. RedisへのTrace IDバインド (JumpServer IP 単体キー)
    oob_data = {
        "attacker_ip": ATTACKER_IP,
        "trace_id": trace_id
    }
    encoded_oob = urllib.parse.quote(json.dumps(oob_data))
    
    redis_keys = [JUMPSERVER_IP, ATTACKER_IP]
    for key in redis_keys:
        set_url = f"{WEBDIS_URL}/SET/{key}/{encoded_oob}/EX/300"
        try:
            urllib.request.urlopen(set_url, timeout=3)
            print(f"    -> [OOB Bind] Bound trace_id {trace_id} to IP {key} in Redis (TTL 300s)")
        except Exception as e:
            print(f"    [-] [OOB Bind Error] Failed to bind Trace ID to {key}: {e}")
            return False
        
    time.sleep(1) # Wait for Redis

    # 3. IT側 (SSH/Token Auth) の conn.log を zeek_tap にモック注入
    conn_log = json.dumps({
        "ts": time.time(),
        "id": {
            "orig_h": ATTACKER_IP,
            "resp_h": JUMPSERVER_IP,
            "orig_p": 54321,
            "resp_p": 22
        },
        "proto": "tcp",
        "service": "ssh"
    })
    
    try:
        subprocess.run(
            ["docker", "exec", "-i", "zeek_tap", "sh", "-c", "tee -a /usr/local/zeek/logs/conn.log > /dev/null"],
            input=(conn_log + "\n").encode(),
            check=True
        )
        print("    -> [Mock Zeek] IT Pivot connection log (conn.log) injected.")
    except Exception as e:
        print(f"    [-] [Mock Zeek Error] Failed to inject conn log: {e}")

    time.sleep(1) # Simulate Pivot delay
    
    # 4. OT側 (DNP3 Strike) の dnp3.log を zeek_tap にモック注入
    print("[+] Pivot Complete. Executing Stage 3a: DNP3 FC 0x05 (Direct Operate Breaker Open)...")
    
    dnp3_log = json.dumps({
        "ts": time.time(),
        "id": {
            "orig_h": JUMPSERVER_IP, # JumpServer が送信元
            "resp_h": TARGET_RTU_IP,
            "orig_p": 49152,
            "resp_p": 20000
        },
        "fc": 5 # Breaker Open
    })
    
    try:
        subprocess.run(
            ["docker", "exec", "-i", "zeek_tap", "sh", "-c", "tee -a /usr/local/zeek/logs/dnp3.log > /dev/null"],
            input=(dnp3_log + "\n").encode(),
            check=True
        )
        print("    -> [Mock Zeek] OT DNP3 Attack log (dnp3.log) injected.")
    except Exception as e:
        print(f"    [-] [Mock Zeek Error] Failed to inject dnp3 log: {e}")
        
    print("[+] E2E Pivot Attack Execution Complete.")
    return True

if __name__ == "__main__":
    execute_e2e_pivot_attack()
