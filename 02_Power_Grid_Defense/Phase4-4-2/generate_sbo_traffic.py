#!/usr/bin/env python3
"""
Normal SBO (Select-Before-Operate) SCADA Traffic Generator
"""
import socket
import time
import sys

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000

# fc=3: SELECT
DNP3_SELECT_PAYLOAD = b"\x05\x64\x05\xc0\x01\x00\x00\x04\x03\x00\x00\x00\x00"
# fc=4: OPERATE
DNP3_OPERATE_PAYLOAD = b"\x05\x64\x05\xc0\x01\x00\x00\x04\x04\x00\x00\x00\x00"

def send_sbo_sequence():
    print(f"[+] Starting SBO (SELECT -> OPERATE) sequence to {TARGET_IP}:{TARGET_PORT}")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.0)
        s.connect((TARGET_IP, TARGET_PORT))
        
        print("    [>] Sending SELECT (fc=3)...")
        s.sendall(DNP3_SELECT_PAYLOAD)
        time.sleep(0.1) # Simulate think time / processing
        
        print("    [>] Sending OPERATE (fc=4)...")
        s.sendall(DNP3_OPERATE_PAYLOAD)
        time.sleep(0.5) # Wait for packet to hit the wire
        
        s.shutdown(socket.SHUT_RDWR)
        s.close()
        print("[+] SBO Sequence completed.")
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    send_sbo_sequence()
