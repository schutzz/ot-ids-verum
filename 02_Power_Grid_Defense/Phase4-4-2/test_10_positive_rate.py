# test_10_positive_rate.py — 陽性テスト#10: Signal4(レート異常バースト)
# local.zeekの実際のSumStatsしきい値: epoch=10sec, threshold=2.0
# (同一送信元から10秒window内に2接続以上でRate_Anomaly発火)。
# 陰性#4の逆パターン：同一epoch(10秒)内に閾値を超える接続を送る。
# fc=1(READ、無害)を使い、Signal2/3/5の混入を避けてSignal4単体の純度を保つ。
import socket
import time
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000
BURST_COUNT = 5  # 10秒window内に閾値(2.0)を超える接続数


def send_frame():
    payload = build_dnp3_frame(function_code=1, dest=1, src=1024)  # READ
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    s.connect((TARGET_IP, TARGET_PORT))
    s.sendall(payload)
    s.close()


for i in range(BURST_COUNT):
    send_frame()
    print(f"[+] Sent DNP3 fc=1 frame {i+1}/{BURST_COUNT} to {TARGET_IP}:{TARGET_PORT}")
    time.sleep(0.3)  # 短間隔(合計約1.5秒、10秒epoch内に確実に収める)
