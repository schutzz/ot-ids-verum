# test_crob_direct_operate.py — CROB検証: DIRECT_OPERATE(fc=5)単体でdnp3_crobイベントが発火するか確認
import socket
from dnp3_frame import build_dnp3_frame_with_crob

payload = build_dnp3_frame_with_crob(function_code=5, control_code=0x41)  # DIRECT_OPERATE

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect(("10.0.30.10", 20000))
s.sendall(payload)
s.close()
print(f"[+] Sent DNP3 fc=5 (DIRECT_OPERATE) frame with CROB ({len(payload)} bytes)")
