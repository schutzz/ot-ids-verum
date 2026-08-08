# test_3_negative_sbo.py — 陰性テスト#3: Signal3(初見資産×制御 / SBOバイパス)
# 計画書7.2 / 決定事項#12・#13: cc_scada_master(10.0.10.10)で「事前にfc=1(READ)実行済みの
# 資産がfc=5(DIRECT_OPERATE)+CROBを送信」。
# 期待: last_read_per_src Transform→last_read_lookup_policy経由で直前のREAD実績が
#       見つかり、30分以内なのでsbo_bypass=falseと判定される。
#
# 罠一覧#9: READ送信からEnrich Policyへの反映まで最悪ケースで約100秒のラグがあるため、
# READ送信と制御コマンド送信の間隔は150秒以上空ける(検知ロジックの仕様ではなく、
# テスト実装上の配慮)。
#
# 罠一覧#6: dnp3_control.logに記録されるにはCROBオブジェクトが必須。build_dnp3_frame()
# ではなくbuild_dnp3_frame_with_crob()を使うこと。
#
# 罠#(test_3旧版で発覚): READ送信とOPERATE送信を別接続で10秒未満の間隔にすると、
# SumStats(Signal4)のRate_Anomalyが意図せず混入する。150秒間隔なのでこの罠も自然に回避される。
import socket
import time
from dnp3_frame import build_dnp3_frame, build_dnp3_frame_with_crob

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000
READ_TO_CONTROL_INTERVAL_SEC = 150  # 伝播ラグ(最大約100秒)に対する余裕


def send_frame(payload: bytes):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((TARGET_IP, TARGET_PORT))
    s.sendall(payload)
    s.close()


# 1) 先にREAD実績を作る
read_payload = build_dnp3_frame(function_code=1, dest=1, src=1024)  # READ
send_frame(read_payload)
print(f"[+] Sent DNP3 fc=1 (READ) frame ({len(read_payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")

print(f"[i] Waiting {READ_TO_CONTROL_INTERVAL_SEC}s for last_read_per_src Transform "
      f"+ last_read_lookup_policy to catch up...")
time.sleep(READ_TO_CONTROL_INTERVAL_SEC)

# 2) READ実績のある資産としてDIRECT_OPERATE(+CROB)を送信
operate_payload = build_dnp3_frame_with_crob(function_code=5, control_code=0x41)  # DIRECT_OPERATE
send_frame(operate_payload)
print(f"[+] Sent DNP3 fc=5 (DIRECT_OPERATE) frame with CROB ({len(operate_payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
