#!/usr/bin/env python3
"""
Phase10-2: 前作(「Dockerで挑む次世代電力網構築」PowerGrid)との条件揃え用UDP版フラッドテスト。

背景(決定事項#51への追記)：
flood_test_dnp3.py(TCP版)で実測したCPU 41.60%ピーク・パケットロス0という結果は、
「Zeek自体の限界に達していない」可能性を否定できない。理由は2つ：
1. 前作の16,000+ pps測定はUDP生パケット連射であり、Zeekにとっての処理コストの質
   (コネクション追跡・weird.log異常検知の有無)がTCP接続チャーンと異なる。
2. TCP版では、モックRTU(target_rtu.py)がシングルスレッド+backlog=5で捌ききれず
   接続失敗(274件)が発生しており、Zeek自体にたどり着く前にアプリ層で律速されて
   いた可能性がある。

このスクリプトは前作と条件を揃えるため、DNP3フレーム自体は
Phase-ex/dnp3_frame.py(CRC完備)を流用しつつ、送信方式のみUDP(SOCK_DGRAM)に
変更する。UDPは接続レスなので、RTU側に実際に届いて処理される必要はない
(そもそもtarget_rtu.pyはTCPサーバーでUDPは受け付けない)——ミラーリング経由で
zeek_tap/suricata_idsのインターフェースにパケットとして到達し観測されることだけを
再現できればよい。connect()せず生のsendto()を使うことで、宛先ポートに
リスナーが存在しないことによるICMP Port Unreachable起因のエラーが
アプリケーション側の例外として伝播しないようにする(TCP版で踏んだRST関連の
落とし穴と同種の問題を未然に回避)。
"""

import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "Phase-ex"))
from dnp3_frame import build_dnp3_frame  # noqa: E402

TARGET_IP = os.environ.get("FLOOD_TARGET_IP", "10.0.30.10")
TARGET_PORT = int(os.environ.get("FLOOD_TARGET_PORT", "20000"))
DEFAULT_DURATION_SEC = 60
NUM_WORKERS = int(os.environ.get("FLOOD_WORKERS", "32"))  # 並列送信ワーカー数


class Counters:
    def __init__(self):
        self.lock = threading.Lock()
        self.packets_sent = 0
        self.error_count = 0

    def record_ok(self, n=1):
        with self.lock:
            self.packets_sent += n

    def record_error(self):
        with self.lock:
            self.error_count += 1

    def snapshot(self):
        with self.lock:
            return self.packets_sent, self.error_count


def worker_loop(frame, stop_event: threading.Event, counters: Counters):
    # UDPソケット。connect()しない = 宛先未到達時のICMPエラーが例外として
    # 返ってこない(コネクションレスなsendto()の標準動作)。
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dest = (TARGET_IP, TARGET_PORT)
    local_count = 0
    try:
        while not stop_event.is_set():
            try:
                sock.sendto(frame, dest)
                local_count += 1
                if local_count >= 500:
                    counters.record_ok(local_count)
                    local_count = 0
            except OSError:
                counters.record_error()
    finally:
        if local_count:
            counters.record_ok(local_count)
        sock.close()


def run_flood(duration_sec: int = DEFAULT_DURATION_SEC):
    frame = build_dnp3_frame(function_code=5)  # DIRECT_OPERATE、攻撃コマンド相当(TCP版と同一フレーム)

    print("=" * 70)
    print(f"[Phase10-2] DNP3 UDP Burst Flood Test ({duration_sec}s) — 前作条件揃え版")
    print(f"[+] Target: {TARGET_IP}:{TARGET_PORT} (UDP, connectionless)")
    print(f"[+] Frame: {frame.hex()} ({len(frame)} bytes, fc=5 DIRECT_OPERATE)")
    print(f"[+] Workers: {NUM_WORKERS} parallel sendto() loops")
    print("=" * 70)
    print("[+] Starting flood...\n")

    counters = Counters()
    stop_event = threading.Event()
    threads = [
        threading.Thread(target=worker_loop, args=(frame, stop_event, counters), daemon=True)
        for _ in range(NUM_WORKERS)
    ]

    start = time.time()
    for t in threads:
        t.start()

    last_report = start
    try:
        while time.time() - start < duration_sec:
            time.sleep(0.2)
            now = time.time()
            if now - last_report >= 1.0:
                elapsed = now - start
                packets_sent, error_count = counters.snapshot()
                rate = packets_sent / elapsed if elapsed > 0 else 0
                remaining = duration_sec - elapsed
                print(f"[+] {packets_sent} packets sent ({error_count} errors) | "
                      f"{rate:.0f} pps (target: 16,000+) | remaining: {remaining:.0f}s")
                last_report = now
    except KeyboardInterrupt:
        print("\n[!] Flood interrupted by user.")

    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    elapsed = time.time() - start
    packets_sent, error_count = counters.snapshot()
    rate = packets_sent / elapsed if elapsed > 0 else 0
    print("\n" + "=" * 70)
    print(f"[+] Flood completed: {packets_sent} packets in {elapsed:.2f}s ({rate:.0f} pps)")
    print(f"[+] Errors: {error_count}")
    if rate < 16000:
        print(f"[!] 目標(16,000+ pps)に未達。実測値をそのまま10-2の分析材料とする。")
    print("=" * 70)


if __name__ == "__main__":
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DURATION_SEC
    run_flood(duration)
