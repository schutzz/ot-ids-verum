# test_9_positive_sbo.py — 陽性テスト#9: Signal3(初見資産×制御 / SBOバイパス)
# 計画書7.2 / 決定事項#12・#13: cc_scada_master(10.0.10.10)で「READ実績ゼロ(30分以内に
# READ無し)の状態でいきなりfc=5(DIRECT_OPERATE)+CROBを送信」。
# 期待: last_read_lookup_policyでマッチ無し、またはマッチしても30分より古いため
#       sbo_bypass=trueと判定される。
#
# 実行前提: このスクリプトを実行する前に、対象IP(10.0.10.10)が過去30分以内にfc=1(READ)を
# 送信していないことを確認すること(test_3実施直後に続けて実行すると、test_3で作った
# READ実績が残っていてsbo_bypass=falseになってしまう。既存の10分鮮度チェックとは
# 別軸の、Signal3専用の30分ウィンドウであることに注意)。
import socket
from dnp3_frame import build_dnp3_frame_with_crob

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000

payload = build_dnp3_frame_with_crob(function_code=5, control_code=0x41)  # DIRECT_OPERATE

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect((TARGET_IP, TARGET_PORT))
s.sendall(payload)
s.close()
print(f"[+] Sent DNP3 fc=5 (DIRECT_OPERATE) frame with CROB ({len(payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
