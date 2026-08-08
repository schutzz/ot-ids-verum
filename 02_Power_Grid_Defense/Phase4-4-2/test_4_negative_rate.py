# test_4_negative_rate.py — 陰性テスト#4: Signal4(レート異常)
# 計画書7.2: cc_scada_master(10.0.10.10)からfc=1(READ)を「数百秒間隔相当」の低頻度で送信。
# local.zeekの実際のSumStatsしきい値を確認済み: epoch=10sec, threshold=2.0
# (同一送信元から10秒window内に2接続以上でRate_Anomaly発火)。
# 本テストはそのepoch(10秒)を確実に跨ぐよう15秒間隔で2回送信し、閾値未達を確認する。
import socket
import time
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000
INTERVAL_SEC = 15  # SumStats epoch(10秒)を確実に跨ぐ間隔


def send_frame():
    payload = build_dnp3_frame(function_code=1, dest=1, src=1024)  # READ
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((TARGET_IP, TARGET_PORT))
    s.sendall(payload)
    s.close()
    print(f"[+] Sent DNP3 fc=1 frame ({len(payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")


send_frame()
print(f"[i] Waiting {INTERVAL_SEC}s before next low-frequency send...")
time.sleep(INTERVAL_SEC)
send_frame()
