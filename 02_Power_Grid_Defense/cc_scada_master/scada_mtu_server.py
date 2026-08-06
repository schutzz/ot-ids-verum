import socket
import time
import uuid
import os
import json
import urllib.parse
import urllib.request
import urllib.error
from flask import Flask, request, jsonify

app = Flask(__name__)

# Config
SRC_IP = os.environ.get("SRC_IP", "10.0.10.10")  # cc_scada_master IP
DST_IP = os.environ.get("DST_IP", "10.0.30.10")  # sub_b_rtu IP
DST_PORT = int(os.environ.get("DST_PORT", "20000"))
FUNCTION_CODE = 5  # Direct Operate

def send_dnp3_packet():
    """Transmits Binary DNP3 Packet (Header: 0x05 0x64, FC: 0x05)"""
    dnp3_payload = b"\x05\x64\x05\xc0\x01\x00\x00\x00\x00\x05\x00\x00"
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
    app.run(host="0.0.0.0", port=5000)
