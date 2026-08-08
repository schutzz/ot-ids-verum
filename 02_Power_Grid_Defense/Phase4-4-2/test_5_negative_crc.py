# test_5_negative_crc.py — 陰性テスト#5: Signal5(プロトコル整合性)
# 計画書7.2: cc_scada_master(10.0.10.10)からvalid_crc=Trueの正規フレームを送信。
# 期待: weird.logにエントリなし(CRC破壊なし)。
import socket
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000

payload = build_dnp3_frame(function_code=1, dest=1, src=1024, valid_crc=True)  # READ, 正規CRC

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect((TARGET_IP, TARGET_PORT))
s.sendall(payload)
s.close()
print(f"[+] Sent DNP3 fc=1 frame (valid_crc=True, {len(payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
