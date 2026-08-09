import socket
import sys
import threading
import time
import uuid
import os
import json
import urllib.parse
import urllib.request
import urllib.error
from flask import Flask, request, jsonify

sys.path.insert(0, "/phase-ex")  # dnp3_frame.py (正しいCRC計算・CROB実装、罠一覧#6/#9参照)
from dnp3_frame import build_dnp3_frame

app = Flask(__name__)

# Config
SRC_IP = os.environ.get("SRC_IP", "10.0.10.10")  # cc_scada_master IP
DST_IP = os.environ.get("DST_IP", "10.0.30.10")  # sub_b_rtu IP
DST_PORT = int(os.environ.get("DST_PORT", "20000"))
FUNCTION_CODE = 5  # Direct Operate

# Phase6-2: 恒常的な正常トラフィック(Integrity Poll相当)の生成。6-2のモニタリング期間中、
# ラボのネットワークが実質無音のままだと、Signal1〜6が「継続的な正常運用トラフィック」に対して
# 誤検知を起こさないかを検証できない、という指摘を受けて追加。allowlist内の正当な送信元
# (cc_scada_master自身)から、実運用のIntegrity Pollを模した低頻度READを送り続ける。
INTEGRITY_POLL_INTERVAL_SEC = int(os.environ.get("INTEGRITY_POLL_INTERVAL_SEC", "300"))

def send_integrity_poll():
    """定期READ(fc=1)を送信するバックグラウンドループ。Signal4(レート異常)の閾値を
    大きく下回る低頻度(デフォルト5分間隔)のため、正常運用として扱われるべきトラフィック。"""
    while True:
        time.sleep(INTEGRITY_POLL_INTERVAL_SEC)
        payload = build_dnp3_frame(function_code=1, dest=1, src=1024)  # READ
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((DST_IP, DST_PORT))
            sock.sendall(payload)
            sock.close()
            print(f"[SCADA Integrity Poll] READ sent to {DST_IP}:{DST_PORT}", flush=True)
        except Exception as e:
            print(f"[SCADA Integrity Poll] error: {e}", flush=True)

def send_dnp3_packet():
    """Transmits a properly CRC'd DNP3 DIRECT_OPERATE packet.
    旧実装(b"\\x05\\x64\\x05\\xc0\\x01\\x00\\x00\\x00\\x00\\x05\\x00\\x00")は
    ヘッダCRC・ユーザデータCRCが丸ごと欠落した構造破綻フレーム(12バイト)で
    あり、Zeek/Suricataいずれにも記録されなかった(計画書セクション9参照)。
    """
    dnp3_payload = build_dnp3_frame(function_code=FUNCTION_CODE, dest=1, src=1024)
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        sock.connect((DST_IP, DST_PORT))
        sock.sendall(dnp3_payload)
        sock.close()
    except Exception as e:
        print(f"[SCADA DNP3 Packet Note] Packet attempt to {DST_IP}:{DST_PORT}: {e}", flush=True)

@app.route('/api/command', methods=['POST'])
def handle_command():
    data = request.json or {}
    command = data.get('command')
    
    if command == 'trip':
        try:
            # Step 2 (Phase 4-4-2): OOB登録の自発的呼出しを削除。
            # 発番・Webdis登録の責務は OS カーネル層 (ebpf_tx_agent) に一元化。
            # trace_id, parent_span_id = generate_w3c_traceparent()
            # register_oob_context_webdis(...) 呼び出しは行わない。
            
            # 3. Transmit UNMODIFIED Binary DNP3 Packet
            send_dnp3_packet()
            print(f"[SCADA] Sent binary DNP3 frame to {DST_IP}:{DST_PORT}", flush=True)
            
            return jsonify({
                "status": "success",
                "message": "DNP3 direct operate command sent."
            }), 200
            
        except Exception as e:
            print(f"[SCADA ERROR] {e}", flush=True)
            return jsonify({"status": "error", "message": str(e)}), 500
            
    return jsonify({"status": "ignored", "message": "Unknown command"}), 200

if __name__ == "__main__":
    print(f"[SCADA-MTU] Starting Server on {SRC_IP}:5000...", flush=True)
    print(f"[SCADA-MTU] Integrity Poll background thread: every {INTEGRITY_POLL_INTERVAL_SEC}s", flush=True)
    threading.Thread(target=send_integrity_poll, daemon=True).start()
    app.run(host="0.0.0.0", port=5000)
