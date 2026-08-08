# test_11_positive_crc.py — 陽性テスト#11: Signal5(プロトコル整合性違反)
# fc=1(READ、無害)でCRCのみ意図的に破壊する。fc=5等の危険FCを避けるのは、
# 万一SuricataのパーサーがCRC検証をスキップしてfcだけ読み取った場合にSignal2が
# 意図せず混入するのを防ぎ、Signal5単体の純度を保つため。
import socket
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000

payload = build_dnp3_frame(function_code=1, dest=1, src=1024, valid_crc=False)  # 意図的にCRC破壊

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect((TARGET_IP, TARGET_PORT))
s.sendall(payload)
s.close()
print(f"[+] Sent DNP3 fc=1 frame with INVALID CRC ({len(payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
