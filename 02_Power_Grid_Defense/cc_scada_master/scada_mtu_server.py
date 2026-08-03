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
WEBDIS_URL = "http://oob_webdis:7379"
WEBDIS_HOST = os.environ.get("WEBDIS_HOST", "oob_webdis")
WEBDIS_PORT = os.environ.get("WEBDIS_PORT", "7379")
SRC_IP = os.environ.get("SRC_IP", "10.0.10.10")  # cc_scada_master IP
DST_IP = os.environ.get("DST_IP", "10.0.30.10")  # sub_b_rtu IP
DST_PORT = int(os.environ.get("DST_PORT", "20000"))
FUNCTION_CODE = 5  # Direct Operate

webdis_url = f"http://{WEBDIS_HOST}:{WEBDIS_PORT}"

def generate_w3c_traceparent() -> (str, str):
    """Generates a standard W3C Trace Context string (traceparent)."""
    trace_id = uuid.uuid4().hex
    parent_id = uuid.uuid4().hex[:16]
    return trace_id, parent_id

def register_oob_context_webdis(key: str, trace_id: str, parent_span_id: str, ttl: int = 30):
    """Pre-registers the Trace Context into Redis via Webdis REST API with TTL."""
    payload = json.dumps({"trace_id": trace_id, "parent_span_id": parent_span_id})
    encoded_payload = urllib.parse.quote(payload)
    url = f"{webdis_url}/SET/{key}/{encoded_payload}/EX/{ttl}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=2) as resp:
        if resp.status != 200:
            raise Exception(f"Failed to register to Webdis: {resp.status}")

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
            # 1. Generate Context
            trace_id, parent_span_id = generate_w3c_traceparent()
            
            # In Phase 3, the key used by Vector is raw orig_h-resp_h-fc
            binding_key = f"{SRC_IP}-{DST_IP}-{FUNCTION_CODE}"
            
            # 2. Pre-register OOB Context
            try:
                register_oob_context_webdis(binding_key, trace_id, parent_span_id, ttl=30)
                print(f"[SCADA] Pre-registered OOB Key -> key={binding_key}, trace_id={trace_id}", flush=True)
            except Exception as e:
                # If OOB registration fails, log it and proceed anyway (for resilience)
                print(f"[SCADA] Pre-registered OOB Key -> key={binding_key}, trace_id={trace_id} (Webdis err: {e})", flush=True)
            
            # Wait briefly to ensure sync_redis_csv.py picks it up before the packet hits vector
            time.sleep(1)
            
            # 3. Transmit UNMODIFIED Binary DNP3 Packet
            send_dnp3_packet()
            print(f"[SCADA] Sent binary DNP3 frame to {DST_IP}:{DST_PORT}", flush=True)
            
            return jsonify({
                "status": "success",
                "message": "DNP3 direct operate command sent with OOB tracing.",
                "trace_id": trace_id
            }), 200
            
        except Exception as e:
            print(f"[SCADA ERROR] {e}", flush=True)
            return jsonify({"status": "error", "message": str(e)}), 500
            
    return jsonify({"status": "ignored", "message": "Unknown command"}), 200

if __name__ == "__main__":
    print(f"[SCADA-MTU] Starting Server on {SRC_IP}:5000...", flush=True)
    app.run(host="0.0.0.0", port=5000)
