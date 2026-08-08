# test_3_negative_sbo.py — 陰性テスト#3: Signal3(初見資産×制御 / SBOバイパス)
# 計画書7.2: cc_scada_master(10.0.10.10)で「事前にfc=1(READ)実行済みの資産がfc=5(DIRECT_OPERATE)を送信」。
# 期待: ICSNPP dnp3_control.log上、READ実績のある資産からの制御として正規シーケンス相当に扱われ、
#       異常(SBOバイパス)としては記録されない。
# 陽性側(#9)は「READ実績ゼロの状態でいきなりfc=5」なので、本テストはこのREAD実績を
# 同一スクリプト内で事前に作ってからfc=5を送る点が異なる。
import socket
import time
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000


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

time.sleep(1.0)  # READ実績がdnp3_control.logに記録されるのを待つ

# 2) READ実績のある資産としてDIRECT_OPERATEを送信
operate_payload = build_dnp3_frame(function_code=5, dest=1, src=1024)  # DIRECT_OPERATE
send_frame(operate_payload)
print(f"[+] Sent DNP3 fc=5 (DIRECT_OPERATE) frame ({len(operate_payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
