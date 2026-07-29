#!/usr/bin/env python3
"""
スクショ撮影用・持続攻撃モードスクリプト
(run_sustained_attack_for_screenshot.py)

目的:
1. 遮断器 Trip (OPEN) ＆ UPS バッテリー死亡 (0%) 状態を長期間維持
2. DNP3/UDP パケットDoS連射を長期間 (デフォルト120秒) 継続し、Zeek TAP のパケットドロップとログ蒸発を維持
3. ユーザーがゆっくり Splunk ダッシュボードを開いてスクショを撮影できるようにする
"""

import os
import sys
import time
from attack_stage4_flood import run_stage4_flood

DURATION_SEC = int(sys.argv[1]) if len(sys.argv) > 1 else 120  # デフォルト2分間持続


def run_sustained_attack():
    print("=" * 75)
    print(f"[Screenshot Mode Active] Sustaining attack & breakdown state for {DURATION_SEC} seconds!")
    print("=" * 75)

    # 1. 物理破壊フラグの作成 (Breaker TRIPPED & UPS DEAD)
    with open("trip_trigger.flag", "w") as f:
        f.write("TRIPPED")
    with open("ups_shutdown.flag", "w") as f:
        f.write("DEAD")

    print("[+] Physical State Set: Main Breaker = TRIPPED / OPEN, UPS = 0% (DEAD)")
    print(f"[+] Launching DoS packet storm for {DURATION_SEC} seconds...")
    print(">> Open Splunk Observability Cloud dashboard in your browser NOW to capture screenshot!\n")

    start_time = time.time()
    try:
        # 指定時間までループでパケット連射を持続
        while time.time() - start_time < DURATION_SEC:
            remaining = int(DURATION_SEC - (time.time() - start_time))
            print(f"[+] [Sustaining Attack...] Remaining: {remaining} s | (Press Ctrl+C to stop)")
            run_stage4_flood(duration_sec=10)
    except KeyboardInterrupt:
        print("\n[!] Sustained attack mode stopped by user.")

    print("\n" + "=" * 75)
    print("[Screenshot Mode Finished] Resetting state...")
    print("=" * 75)


if __name__ == "__main__":
    run_sustained_attack()
