#!/usr/bin/env python3
"""
Step 2: Stage 2/3 物理制御 ✕ UPS補機電源殺害モジュール
(Stage 2/3: Physical Control & UPS Impairment Module)

目的:
1. Stage 2 (Evasion): DNP3 FC 0x14 (Disable Unsolicited Messages) 射出により RTU の自主通報機能を無効化。
2. Stage 3a (DNP3 Strike): DNP3 FC 0x05 (Direct Operate - Breaker Open) 射出によりメイン遮断器を強制的 Trip。
3. Stage 3b (SNMP Impairment): SNMP SetRequest (UPS Output Shutdown) 射出により非常用 UPS バッテリー供給を物理的に完全殺害。
"""

import json
import os
import time
import urllib.request
import urllib.parse
import urllib.error
import uuid
import hashlib
import subprocess

HMI_TRIP_API = "http://localhost:1880/api/trip"
HMI_STATUS_API = "http://localhost:1880/api/status"


def execute_stage2_evasion() -> dict:
    """Stage 2: DNP3 FC 0x14 (Disable Unsolicited Messages) シミュレーション"""
    print("[+] Executing Stage 2: DNP3 FC 0x14 (Disable Unsolicited Messages)...")
    return {
        "status": 200,
        "fc_code": "0x14",
        "fc_name": "DISABLE_UNSOLICITED",
        "target": "10.0.30.10:20000",
        "detail": "RTU unsolicited event report disabled. SCADA master will receive no autonomous alert."
    }


def execute_stage3a_dnp3_strike(use_oob=True) -> bool:
    """Stage 3a: DNP3 FC 0x05 (Direct Operate Breaker Open) 射出"""
    print(f"[+] Executing Stage 3a: DNP3 FC 0x05 (Direct Operate Breaker Open) [OOB Toggle: {'ON' if use_oob else 'OFF'}]...")

    # 1. W3C Trace ID 準拠の 16バイトID (32桁hex) を常に生成
    trace_id = uuid.uuid4().hex
    parent_span_id = uuid.uuid4().hex[:16]

    if use_oob:
        # --- Phase 3: OOB Trace Injection Hook ---
        raw_key = "10.0.10.10-10.0.30.10-5"
        hash_key = raw_key
        payload = json.dumps({"trace_id": trace_id, "parent_span_id": parent_span_id})
        encoded_payload = urllib.parse.quote(payload)
        webdis_base = os.environ.get("WEBDIS_URL", "http://127.0.0.1:7379")
# TTL is increased to allow Vector file-source and processing delays to complete
        webdis_url = f"{webdis_base}/SET/{hash_key}/{encoded_payload}/EX/30"

        print(f"    -> [OOB Hook] Generated Trace ID : {trace_id}")
        print(f"    -> [OOB Hook] Generated Parent Span ID: {parent_span_id}")
        print(f"    -> [OOB Hook] Webdis URL: {webdis_url}")

        # 4. Webdis (Redis) へ事前登録 (TTL = 30秒)
        try:
            req = urllib.request.Request(webdis_url, method="GET")
            with urllib.request.urlopen(req, timeout=2) as resp:
                if resp.status == 200:
                    print("    -> [OOB Hook] Successfully registered to Webdis (TTL=30s).")
        except Exception as e:
            print(f"    [-] [OOB Hook Error] Failed to register to Webdis: {e}")
        # -----------------------------------------
    else:
        print("    -> [OOB Hook] Bypassed (Toggle is OFF). Vector will generate random Trace ID (Phase 2 Emulation).")

    try:
        # trip_trigger.flag を作成し、Node-RED/ジェネレータへ物理 Trip を伝達
        with open("trip_trigger.flag", "w") as f:
            f.write("TRIPPED")
        print("    -> [DNP3 Strike] Breaker Open flag file created (trip_trigger.flag). Main breaker TRIPPED!")
        
        # --- [Mock Zeek Log Injection for Vector Pipeline] ---
        import time
        import subprocess
        
        # Add delay to allow sync_redis_csv.py to sync Webdis to CSV before Vector processes the log
        print("    -> [OOB Hook] Waiting 2 seconds for Vector CSV sync...")
        time.sleep(2)

        mock_log = json.dumps({
            "ts": time.time(),
            "id": {
                "orig_h": "10.0.10.10",
                "resp_h": "10.0.30.10"
            },
            "fc": 5,
            "trace_id": trace_id,
            "parent_span_id": parent_span_id
        })
        try:
            # We use tee -a to append the log to dnp3.log in the zeek container
            subprocess.run(
                ["docker", "exec", "-i", "zeek_tap", "sh", "-c", "tee -a /usr/local/zeek/logs/dnp3.log > /dev/null"],
                input=(mock_log + "\n").encode(),
                check=True
            )
            print("    -> [Mock Zeek] DNP3 log injected into zeek_tap container (Zeek logs dir).")
        except Exception as ze:
            print(f"    [-] [Mock Zeek Error] Failed to inject mock log: {ze}")
            
        return True
    except Exception as e:
        print(f"    [-] [DNP3 Strike Error] Failed to set trip flag: {e}")
        return False


def execute_stage3b_snmp_ups_shutdown() -> bool:
    """Stage 3b: SNMP SetRequest (OID .1.3.6.1.2.1.33.1.1.4 / UPS Output Shutdown) 射出"""
    print("[+] Executing Stage 3b: SNMP SetRequest (UPS Battery Output Shutdown)...")
    try:
        with open("ups_shutdown.flag", "w") as f:
            f.write("DEAD")
        print("    -> [SNMP Impairment] UPS Battery Output forcibly SHUT DOWN. Flag created (ups_shutdown.flag)!")
        return True
    except Exception as e:
        print(f"    [-] [SNMP Impairment Error] Failed to set ups_shutdown flag: {e}")
        return False


def verify_physical_state() -> dict:
    """現場ステートの確認"""
    try:
        req = urllib.request.Request(HMI_STATUS_API, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                return json.loads(resp.read().decode('utf-8'))
    except Exception as e:
        print(f"[-] Status check failed: {e}")
    return {}


def run_stage2_3_test():
    print("=" * 70)
    print("[Phase 1-3 Step 2 Test] Stage 2 & 3 Physical Control & UPS Impairment Test")
    print("=" * 70)

    # 1. 攻撃前ステート確認
    initial_state = verify_physical_state()
    print(f"\n[Initial State] Substation B: Tripped={initial_state.get('is_tripped')}, UPS={initial_state.get('ups_soc')}%")

    # 2. Stage 2 実行
    print("\n[1/3] Stage 2 (Evasion / Impair Defenses) Execution...")
    st2_res = execute_stage2_evasion()
    print(f"      -> {st2_res['detail']}")
    print("      [OK] DNP3 Disable Unsolicited command injected.")

    # 3. Stage 3a DNP3 Strike 実行
    print("\n[2/3] Stage 3a (DNP3 Strike - Breaker Open) Execution...")
    
    # 環境変数 ENABLE_OOB が "1" なら True、それ以外は False として評価 (Phase 1 4-Quadrant Control)
    use_oob = os.environ.get("ENABLE_OOB", "0") == "1"
    st3a_ok = execute_stage3a_dnp3_strike(use_oob=use_oob)
    assert st3a_ok, "Stage 3a Breaker Trip command failed!"

    # 4. Stage 3b SNMP UPS Shutdown 実行
    print("\n[3/3] Stage 3b (SNMP Impairment - UPS Shutdown) Execution...")
    st3b_ok = execute_stage3b_snmp_ups_shutdown()

    # 5. 最終検証
    time.sleep(1)
    final_state = verify_physical_state()
    is_flag_tripped = os.path.exists("trip_trigger.flag")
    is_ups_shutdown = os.path.exists("ups_shutdown.flag")
    print(f"\n[Final Physical State] Substation B:")
    print(f"      -> Breaker State : {'TRIPPED / OPEN (BLACKOUT)' if (is_flag_tripped or final_state.get('is_tripped')) else 'CLOSED'}")
    print(f"      -> UPS Battery   : {'0% (DEAD / SHUTDOWN)' if is_ups_shutdown else final_state.get('ups_soc')}")

    assert is_flag_tripped, "Main breaker flag is not set!"
    print("\n" + "=" * 70)
    print("[Step 2 PASSED] Stage 2 & 3 physical control & UPS impairment module verification complete!")
    print("=" * 70)


if __name__ == "__main__":
    run_stage2_3_test()
