#!/usr/bin/env python3
"""
決定事項#24: 6-2の時間圧縮実施用バッチランナー。

Phase4の陰性/陽性テストスクリプト(#1〜5・#7〜11、run_test.py互換の単体スクリプトのみ)を
複数ラウンド反復実行し、Precision/Recall実証に必要な統計的母数を短時間で稼ぐ。
キルチェーン(#6/#12)・複合(#13)は個別のインライン実行手順のため対象外
(このセッション内で既に実行・記録済み)。

各run_test.py呼び出しは内部で35秒のTransform同期待機を含むため、
1ラウンド(10テスト) ≈ 6分程度。
"""

import argparse
import os
import subprocess
import sys
import time

# (test_script, target_src_ip, container_name)
TESTS = [
    ("test_1_negative_zone.py", "10.0.10.10", "cc_scada_master"),
    ("test_2_negative_fc.py", "10.0.10.10", "cc_scada_master"),
    ("test_3_negative_sbo.py", "10.0.10.10", "cc_scada_master"),
    ("test_4_negative_rate.py", "10.0.10.10", "cc_scada_master"),
    ("test_5_negative_crc.py", "10.0.10.10", "cc_scada_master"),
    ("test_7_positive_zone.py", "172.16.0.99", "external_attacker"),
    ("test_8_positive_fc5.py", "10.0.10.10", "cc_scada_master"),
    ("test_9_positive_sbo.py", "10.0.10.10", "cc_scada_master"),
    ("test_10_positive_rate.py", "10.0.10.10", "cc_scada_master"),
    ("test_11_positive_crc.py", "10.0.10.10", "cc_scada_master"),
]

# Git Bash形式のパス(/c/...)をハードコードすると、ネイティブWindows Pythonのsubprocessに
# 渡した際にWinError 267(NotADirectoryError)になる(実機で確認済み)。__file__から動的導出する。
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
# バックグラウンド実行時、bashツール側のstdoutキャプチャがフォアグラウンド→バックグラウンド
# 遷移で途切れる事象を実機で確認したため、進捗はstdoutに頼らずこのファイルへ直接追記する。
PROGRESS_LOG = os.path.join(SCRIPT_DIR, "compressed_6_2_progress.log")


def log(msg):
    line = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}"
    print(line, flush=True)
    with open(PROGRESS_LOG, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        f.flush()


def run_one(script, src_ip, container, round_no, idx, total):
    log(f"[ラウンド{round_no} {idx}/{total}] 開始: {script} ({container} / {src_ip})")
    result = subprocess.run(
        [sys.executable, f"{SCRIPT_DIR}/run_test.py", script, src_ip, container],
        cwd=SCRIPT_DIR,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    log(f"[ラウンド{round_no} {idx}/{total}] 終了: {script} -> returncode={result.returncode}")
    return result.returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rounds", type=int, default=3, help="反復ラウンド数")
    parser.add_argument("--inter-test-sleep", type=int, default=5, help="テスト間の待機秒数")
    parser.add_argument("--inter-round-sleep", type=int, default=30, help="ラウンド間の待機秒数")
    args = parser.parse_args()

    log(f"=== バッチ開始: rounds={args.rounds}, inter_test_sleep={args.inter_test_sleep}, inter_round_sleep={args.inter_round_sleep} ===")
    total_ok, total_fail = 0, 0
    for r in range(1, args.rounds + 1):
        for i, (script, src_ip, container) in enumerate(TESTS, 1):
            ok = run_one(script, src_ip, container, r, i, len(TESTS))
            if ok:
                total_ok += 1
            else:
                total_fail += 1
            time.sleep(args.inter_test_sleep)
        if r < args.rounds:
            log(f"--- ラウンド{r}完了。次ラウンドまで{args.inter_round_sleep}秒待機 ---")
            time.sleep(args.inter_round_sleep)

    log(f"=== 全{args.rounds}ラウンド完了。成功: {total_ok} / 失敗: {total_fail} ===")


if __name__ == "__main__":
    main()
