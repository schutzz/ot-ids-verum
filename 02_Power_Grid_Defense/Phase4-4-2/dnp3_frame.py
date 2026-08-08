# dnp3_frame.py — Phase 4の13本共通で使うDNP3フレーム生成ユーティリティ

def crc_dnp(data: bytes) -> bytes:
    """CRC-DNP (poly=0xA6BC, reversed, init=0x0000, xorout=0xFFFF)"""
    crc = 0x0000
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if (crc & 1) else (crc >> 1)
    crc ^= 0xFFFF
    return bytes([crc & 0xFF, (crc >> 8) & 0xFF])

def _with_crc_blocks(data: bytes) -> bytes:
    """DNP3はユーザデータを16バイトごとのブロックに区切り、各ブロックにCRCを付与する"""
    out = b""
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        out += chunk + crc_dnp(chunk)
    return out

def build_dnp3_frame(function_code: int, dest: int = 1, src: int = 1024,
                      valid_crc: bool = True) -> bytes:
    """
    function_code: DNP3アプリケーション層ファンクションコード(1=READ, 5=DIRECT_OPERATE 等)
    valid_crc: Falseにすると意図的にCRCを破壊する(Signal 5の陽性テスト#11用)
    """
    # --- Transport + Application Layer (user data) ---
    transport = 0xC0   # FIN+FIR, seq=0
    app_ctrl  = 0xC0   # FIR+FIN, seq=0
    user_data = bytes([transport, app_ctrl, function_code])
    user_data_with_crc = _with_crc_blocks(user_data)

    # --- Data Link Header ---
    ctrl = 0xC4  # DIR + PRM + FUNC=UNCONFIRMED_USER_DATA
    length = 5 + len(user_data)  # Control(1) + Dest(2) + Src(2) + UserData
    dl_body = bytes([length, ctrl]) + dest.to_bytes(2, "little") + src.to_bytes(2, "little")
    header = b"\x05\x64" + dl_body
    header_crc = crc_dnp(header)
    
    if not valid_crc:
        header_crc = bytes([header_crc[0] ^ 0xFF, header_crc[1]])  # 意図的にCRC破壊

    return header + header_crc + user_data_with_crc

def build_crob_object(point_index: int = 0, control_code: int = 0x41,
                       count: int = 1, on_time_ms: int = 1000,
                       off_time_ms: int = 1000, status: int = 0) -> bytes:
    """DNP3 Group12 Var1 (CROB) オブジェクトブロックを生成(IEEE 1815準拠、要実機検証)"""
    header = bytes([0x0C, 0x01, 0x17, 0x01])  # Group, Var, Qualifier(1byte index+1byte count), Count=1
    obj = bytes([point_index, control_code, count]) \
        + on_time_ms.to_bytes(4, "little") \
        + off_time_ms.to_bytes(4, "little") \
        + bytes([status])
    return header + obj  # 4 + 13 = 17 bytes


def build_dnp3_frame_with_crob(function_code: int, dest: int = 1, src: int = 1024,
                                point_index: int = 0, control_code: int = 0x41) -> bytes:
    """function_code(SELECT=3/OPERATE=4/DIRECT_OPERATE=5等)にCROBオブジェクトを付与したフレームを生成"""
    transport = 0xC0
    app_ctrl = 0xC0
    crob = build_crob_object(point_index=point_index, control_code=control_code)
    user_data = bytes([transport, app_ctrl, function_code]) + crob
    user_data_with_crc = _with_crc_blocks(user_data)

    ctrl = 0xC4
    length = 5 + len(user_data)
    dl_body = bytes([length, ctrl]) + dest.to_bytes(2, "little") + src.to_bytes(2, "little")
    header = b"\x05\x64" + dl_body
    header_crc = crc_dnp(header)

    return header + header_crc + user_data_with_crc


if __name__ == '__main__':
    # 単体テスト: fc=5のフレームを生成して長さ・構造を確認
    frame = build_dnp3_frame(5)
    print(f"Frame length: {len(frame)} bytes")
    print(f"Hex dump: {frame.hex(' ')}")
    assert len(frame) == 15, "Expected frame length is 15 bytes"
    assert frame[0:2] == b'\x05\x64', "Invalid start bytes"
    # 追加: 既知の検証ベクタでCRC関数自体も自己診断できるようにしておく
    known = crc_dnp(bytes([0x05,0x64,0x05,0xC0,0x01,0x00,0x00,0x00]))
    assert known == bytes([0x91, 0xF8]), "CRC algorithm itself is broken"
    print("DNP3 frame generation test passed.")
