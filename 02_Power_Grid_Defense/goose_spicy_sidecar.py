#!/usr/bin/env python3
"""
Phase9-5: goose_spicy_sidecar

決定事項#42(Zeek統合版とstandalone版の非対称性、原因未解明)を受け、
決定事項#44の判断に基づき、Zeek packet analyzerへの統合を諦め、
goose_anomaly_sidecar(決定事項#35)と同種の独立sidecarパターンで、
9-3で実装した自作GOOSE Spicyパーサー(standalone実行、9-4で完全動作
実証済み)をSignal7として運用する。

mirror_link経由でミラーされたGOOSEフレーム(EtherType 0x88b8)を直接観測し、
各フレームのASN.1ペイロード部分を`spicy-driver`にsubprocessとして渡して
パースする。パーサー自体はZeekに一切依存しない(9-3/9-4でZeek抜きの
spicy-driver実行のみ完全動作を確認済みという経緯を反映した設計)。

出力形式(goose_sidecar.spicy側): 罠ログ#001(フラットキーvsネストキー)の
教訓を踏まえ、人間可読なprint文ではなく「キー\t値\tキー\t値...」形式の
TSV1行に統一(JSON出力はSpicy標準ライブラリに存在しないことを確認済み)。
"""

import json
import os
import subprocess
import time
import urllib.request
from datetime import datetime, timezone

from scapy.all import sniff, Ether, get_if_list, get_if_addr

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
# goose-anomaly-sidecarの実装時は単一ネットワーク(mirror_linkのみ)接続だった
# ためeth0固定で問題なかったが、本sidecarはElasticsearch到達性確保のため
# cc_lanも追加接続しており、インターフェース番号(eth0/eth1)とネットワークの
# 対応がDocker側の内部順序に依存し固定できないことが実機で判明した(cc_lanが
# eth0、mirror_linkがeth1になるケースを確認済み)。IPアドレスのプレフィックス
# から動的に対象インターフェースを検出する設計に変更し、この種の脆さを排除する。
MIRROR_NETWORK_PREFIX = os.environ.get("MIRROR_NETWORK_PREFIX", "10.0.99.")
GOOSE_ETHERTYPE = 0x88B8
HLTO_PATH = os.environ.get("HLTO_PATH", "/app/goose_sidecar.hlto")


def find_mirror_interface(prefix: str) -> str:
    for iface in get_if_list():
        try:
            addr = get_if_addr(iface)
        except Exception:
            continue
        if addr.startswith(prefix):
            return iface
    raise RuntimeError(
        f"No interface found with IP prefix {prefix!r} (checked: {get_if_list()})"
    )

# Signal7: StNum異常ジャンプ判定用の履歴(送信元MACごとに保持)。
# 9-5のスコープでは単純な閾値判定から開始する(ユーザー合意済み、GOOSEサイクル
# 全体を通じて踏襲してきた「まず簡易版で実装し、非検知が分かれば次に活かす」
# という型)。将来的にはIED再起動によるStNumリセット(正当な動作)を、SqNumの
# 同時リセットと突き合わせて誤検知を避ける拡張が候補として残っている。
stnum_history = {}  # mac -> (last_stnum, last_sqnum)


def parse_tsv_result_line(line: str):
    # RESULT\tgocbRef\t...\tstNum\t101\tsqNum\t1\thas_sqNum\ttrue\t...
    parts = line.rstrip("\n").split("\t")
    kv = parts[1:]
    return dict(zip(kv[0::2], kv[1::2]))


def parse_tsv_weird_line(line: str):
    # WEIRD\t<signal_name>\t<detail>
    parts = line.rstrip("\n").split("\t")
    return {
        "signal": parts[1] if len(parts) > 1 else "unknown",
        "detail": parts[2] if len(parts) > 2 else "",
    }


def es_bulk_write(index_name: str, doc: dict):
    lines = [
        json.dumps({"index": {"_index": index_name}}),
        json.dumps(doc),
    ]
    body = ("\n".join(lines) + "\n").encode("utf-8")
    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=body,
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            if result.get("errors"):
                print(f"[goose_spicy_sidecar] ES書き込みエラー: {result}", flush=True)
    except Exception as e:
        print(f"[goose_spicy_sidecar] ES書き込み失敗: {e}", flush=True)


def handle_packet(pkt):
    if Ether not in pkt or pkt[Ether].type != GOOSE_ETHERTYPE:
        return

    src_mac = pkt[Ether].src.lower()
    dst_mac = pkt[Ether].dst.lower()
    payload = bytes(pkt[Ether].payload)
    now = time.time()
    ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    index_name = f"ot-logs-goose-spicy-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"

    try:
        proc = subprocess.run(
            ["spicy-driver", HLTO_PATH, "-p", "goose::Message"],
            input=payload,
            capture_output=True,
            timeout=5,
        )
    except Exception as e:
        print(f"[goose_spicy_sidecar] spicy-driver実行失敗: {e}", flush=True)
        return

    stdout = proc.stdout.decode("utf-8", errors="replace")
    result = None
    weirds = []
    for line in stdout.splitlines():
        if line.startswith("RESULT\t"):
            result = parse_tsv_result_line(line)
        elif line.startswith("WEIRD\t"):
            weirds.append(parse_tsv_weird_line(line))

    if result is None:
        print(f"[goose_spicy_sidecar] パース失敗(RESULT行なし): src={src_mac}, "
              f"stdout={stdout!r}, stderr={proc.stderr.decode('utf-8', errors='replace')!r}",
              flush=True)
        return

    stnum = int(result.get("stNum", "0") or "0")
    sqnum = int(result.get("sqNum", "0") or "0")
    has_sqnum = result.get("has_sqNum", "false") == "true"

    # パーサー自体が検知した異常(宣言長不一致・Tフィールド長不足・goID非ASCII等)を記録
    for w in weirds:
        es_bulk_write(index_name, {
            "@timestamp": ts_iso,
            "signal": "goose_spicy_" + w["signal"],
            "detail": w["detail"],
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        })

    # Signal7: StNum異常ジャンプ判定(9-5、単純な閾値判定から開始)
    if src_mac in stnum_history:
        prev_stnum, prev_sqnum = stnum_history[src_mac]
        if stnum > prev_stnum + 1:
            print(f"[goose_spicy_sidecar] Signal7 fired: {src_mac} "
                  f"stNum {prev_stnum} -> {stnum}", flush=True)
            es_bulk_write(index_name, {
                "@timestamp": ts_iso,
                "signal": "goose_spicy_stnum_anomaly",
                "detail": f"prev_stnum={prev_stnum},new_stnum={stnum}",
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "stNum": stnum,
                "sqNum": sqnum,
                "has_sqNum": has_sqnum,
                "gocbRef": result.get("gocbRef", ""),
            })

    stnum_history[src_mac] = (stnum, sqnum)


if __name__ == "__main__":
    mirror_if = find_mirror_interface(MIRROR_NETWORK_PREFIX)
    print(f"[goose_spicy_sidecar] Resolved mirror interface: {mirror_if} "
          f"(matched prefix {MIRROR_NETWORK_PREFIX!r})", flush=True)
    print(f"[goose_spicy_sidecar] Starting sniff on {mirror_if} for EtherType 0x88b8...", flush=True)
    print(f"[goose_spicy_sidecar] Using parser: {HLTO_PATH}", flush=True)
    sniff(iface=mirror_if, prn=handle_packet, store=False)
