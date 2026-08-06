#!/usr/bin/env python3
"""
Normal SCADA Traffic & Health Check Polling Generator (Genuine TCP Socket Version)
"""

import socket
import time
import sys
import ctypes

try:
    libc = ctypes.CDLL('libc.so.6')
    # PR_SET_NAME = 15
    libc.prctl(15, b"scada_mtu_srv", 0, 0, 0)
except Exception as e:
    print(f"    [-] Could not set process name: {e}")

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000
POLL_COUNT = 100

DNP3_READ_PAYLOAD = b"\x05\x64\x05\xc0\x01\x00\x00\x04\x01\x00\x00\x00\x00"

def generate_real_normal_traffic():
    print(f"[+] Starting GENUINE SCADA Master Polling to {TARGET_IP}:{TARGET_PORT} (Process: scada_mtu_srv)")
    
    success_count = 0
    for i in range(POLL_COUNT):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            
            s.connect((TARGET_IP, TARGET_PORT))
            s.sendall(DNP3_READ_PAYLOAD)
            s.close()
            
            success_count += 1
            time.sleep(0.01)
            
        except ConnectionRefusedError:
            pass # Keep it quiet for normal polling simulation
        except Exception as e:
            print(f"    [-] Poll {i+1} error: {e}")

    print(f"[+] Normal SCADA Traffic Generation Complete. Successful connections: {success_count}/{POLL_COUNT}")
    if success_count == 0:
        print("[!] Warning: All connections failed. Is the RTU listening on port 20000?")
        sys.exit(1)

if __name__ == "__main__":
    generate_real_normal_traffic()
