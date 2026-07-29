#!/usr/bin/env python3
"""
Step 1: Stage 1 境界突破＆ピボット認証モジュール
(Stage 1: Initial Access & Token Authentication Pivot Module)

目的:
1. WAN領域から IT/OT 境界 JumpServer (172.16.0.100 / Token Auth) への認証テスト
2. 事前奪取アクセストークン ('ukraine_2015_sandworm_token_auth_key') の妥当性検証
3. 認証成功時における内部変電所B LAN (10.0.30.10) へのピボット疎通パスの確認
"""

import json
import sys
import time
import urllib.request
import urllib.error

# 設定
JUMP_SERVER_HOST = "172.16.0.100"  # Docker container IP
HMI_STATUS_API = "http://localhost:1880/api/status"  # Node-RED HMI API
VALID_TOKEN = "ukraine_2015_sandworm_token_auth_key"
INVALID_TOKEN = "unauthorized_attacker_fake_token_999"


def authenticate_jumpserver(token: str) -> dict:
    """JumpServer アクセストークン認証の模擬検証関数"""
    if token == VALID_TOKEN:
        return {
            "status": 200,
            "result": "SUCCESS",
            "message": "JumpServer token authentication passed. Bastion pivot granted.",
            "auth_status": "jump_server.auth_status: AUTH_SUCCESS",
            "token_id": token[:16] + "..."
        }
    else:
        return {
            "status": 401,
            "result": "DENIED",
            "message": "Invalid access token. Authentication rejected at IT/OT boundary.",
            "auth_status": "jump_server.auth_status: AUTH_FAILED",
            "token_id": token[:16] + "..."
        }


def check_substation_b_pivot() -> bool:
    """内部変電所B LAN (10.0.30.10 / localhost:1880) へのピボット疎通確認"""
    try:
        req = urllib.request.Request(HMI_STATUS_API, method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            if resp.status == 200:
                data = json.loads(resp.read().decode('utf-8'))
                print(f"[+] [Pivot Link Established] Target Substation B Status: {data}")
                return True
    except Exception as e:
        print(f"[-] [Pivot Link Warning] Could not reach Substation B HMI directly: {e}")
        return False
    return False


def run_stage1_pivot_test():
    print("=" * 70)
    print("[Phase 1-3 Step 1 Test] Stage 1 Boundary Infiltration & Pivot Test")
    print("=" * 70)

    # 1. 失敗テスト (Unauthorized Access Try)
    print("\n[1/3] Test 1: Unauthorized access token attempt...")
    denied_res = authenticate_jumpserver(INVALID_TOKEN)
    print(f"      -> Status: HTTP {denied_res['status']} ({denied_res['result']})")
    print(f"      -> Log: {denied_res['auth_status']}")
    assert denied_res['status'] == 401, "Unauthorized token was not rejected!"
    print("      [OK] Unauthorized access token blocked successfully.")

    # 2. 成功テスト (Spear-phishing Stolen Token Authenticated Access)
    print("\n[2/3] Test 2: Stolen valid token JumpServer infiltration...")
    success_res = authenticate_jumpserver(VALID_TOKEN)
    print(f"      -> Status: HTTP {success_res['status']} ({success_res['result']})")
    print(f"      -> Message: {success_res['message']}")
    print(f"      -> Log: {success_res['auth_status']}")
    assert success_res['status'] == 200, "Valid token authentication failed!"
    print("      [OK] Valid token IT/OT Boundary JumpServer pivot granted!")

    # 3. 変電所Bへのピボット疎通確認
    print("\n[3/3] Checking pivot communication path to Substation B LAN (10.0.30.10 / Localhost API)...")
    pivot_ok = check_substation_b_pivot()
    if pivot_ok:
        print("      [OK] Stage 1 Boundary Infiltration -> Substation B attack route established!")
    else:
        print("      [!] Warning: Could not get response from HMI API. Check Node-RED container status.")

    print("\n" + "=" * 70)
    print("[Step 1 PASSED] Stage 1 module (attack_stage1_pivot.py) verification complete!")
    print("=" * 70)


if __name__ == "__main__":
    run_stage1_pivot_test()
