# test_1_negative_zone.py — 陰性テスト#1: Signal1(ゾーン逸脱)
# 計画書7.2: cc_scada_master(allowlist内, 10.0.10.10)からfc=1(READ)を正常送信。
# 期待: allowlist内のためzone_violation発火せず、red昇格なし。
import socket
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000

payload = build_dnp3_frame(function_code=1, dest=1, src=1024)  # READ

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect((TARGET_IP, TARGET_PORT))
s.sendall(payload)
s.close()
print(f"[+] Sent DNP3 fc=1 frame ({len(payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
