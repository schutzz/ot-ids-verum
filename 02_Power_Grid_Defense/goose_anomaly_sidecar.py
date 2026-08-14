#!/usr/bin/env python3
"""
Phase8-0.5c: Zeek/Vectorの外で完結する、簡易GOOSE異常検知sidecar。

決定事項#34(icsnpp-iec61850-gooseのworkerセグフォルトによる撤退)を受けて、
Zeekのpacket analyzer登録機構(register_packet_analyzer)には一切触れず、
既存のsidecarパターン(es-enrich-refresher/killchain_eql_poller/
signal-comparison-reporter)を4件目として横展開する設計。

mirror_link経由でミラーされたGOOSEフレーム(EtherType 0x88b8)を直接観測し、
以下2種類の異常を検知する:
  1. 未知のMACアドレスからの送信(Signal1のallowlistと同じ静的定義パターン、
     決定事項#4との一貫性を保つため動的学習は採用しない)
  2. バースト送信(Signal4のSumStatsパターンを模した、簡易な閾値ベースのレート異常)

GOOSE自体の完全なプロトコル解析(gocbRef/stNum/sqNum等のフィールド)は行わない
(それはPhase9のSpicy自作課題として持ち越し)。あくまで「送信元と頻度」という
L2レベルの情報だけで異常を判定する、意図的に簡略化した検知。

書き込み先はot-logs-goose-*(新規index)。ot_signal_correlation Transformへの
統合は見送り——既存Signal1-6がzeek_src_ip(IPアドレス)をキーに集約しているのに
対し、GOOSEの識別子はMACアドレスであり、キー体系が異なるため無理に混ぜない。
"""

import json
import os
import time
import urllib.request
from collections import deque
from datetime import datetime, timezone

from scapy.all import sniff, Ether, get_if_list, get_if_addr

ES_URL = os.environ.get("ES_URL", "http://elasticsearch:9200")
# 決定事項#45/#46: mirror_linkのみの接続ではelasticsearch(cc_lanのみ接続)に
# 到達できず、ES書き込みが常に失敗し続けていたことが決定事項#45の調査で判明。
# cc_lan追加接続に伴い、インターフェース番号(eth0/eth1)とネットワークの対応が
# Docker側の内部順序に依存し固定できないことも判明したため、MIRROR_IF固定
# 指定ではなくIPアドレスのプレフィックスから動的に検出する設計に変更。
MIRROR_NETWORK_PREFIX = os.environ.get("MIRROR_NETWORK_PREFIX", "10.0.99.")
GOOSE_ETHERTYPE = 0x88B8


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

# Signal1のallowlist(決定事項#4)と同じ静的定義パターン。動的学習は攻撃者MACの
# 混入リスクがあるため採用しない。sub_a_ied_01のsend_goose.pyに直接埋め込まれた
# SRC_MAC(b'\x02\x42\x0a\x00\x14\x0a')を実機確認済み。
KNOWN_GOOSE_MACS = {
    "02:42:0a:00:14:0a",  # sub_a_ied_01 (正規IED)
}

# Signal4(レート異常)のSumStatsパターンを模した簡易閾値。
BURST_WINDOW_SEC = 10
BURST_THRESHOLD = 20  # WINDOW_SEC内にこの件数を超えたらburst異常

recent_frames = deque()  # (timestamp, src_mac) のスライディングウィンドウ


def es_bulk_write(doc):
    index_name = f"ot-logs-goose-{datetime.now(timezone.utc).strftime('%Y.%m.%d')}"
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
                print(f"[goose_anomaly] ES書き込みエラー: {result}", flush=True)
    except Exception as e:
        print(f"[goose_anomaly] ES書き込み失敗: {e}", flush=True)


def handle_packet(pkt):
    if Ether not in pkt or pkt[Ether].type != GOOSE_ETHERTYPE:
        return

    src_mac = pkt[Ether].src.lower()
    dst_mac = pkt[Ether].dst.lower()
    now = time.time()
    ts_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # --- Signal: 未知MAC ---
    if src_mac not in KNOWN_GOOSE_MACS:
        print(f"[goose_anomaly] unknown_mac detected: {src_mac}", flush=True)
        es_bulk_write({
            "@timestamp": ts_iso,
            "signal": "goose_unknown_mac",
            "src_mac": src_mac,
            "dst_mac": dst_mac,
        })

    # --- Signal: バースト送信 ---
    recent_frames.append((now, src_mac))
    while recent_frames and recent_frames[0][0] < now - BURST_WINDOW_SEC:
        recent_frames.popleft()

    count_in_window = sum(1 for _, m in recent_frames if m == src_mac)
    if count_in_window == BURST_THRESHOLD:  # 閾値を跨いだ瞬間だけ1回発火(連続発火を防ぐ)
        print(f"[goose_anomaly] burst detected: {src_mac} ({count_in_window} in {BURST_WINDOW_SEC}s)", flush=True)
        es_bulk_write({
            "@timestamp": ts_iso,
            "signal": "goose_burst_rate",
            "src_mac": src_mac,
            "count_in_window": count_in_window,
            "window_sec": BURST_WINDOW_SEC,
        })


if __name__ == "__main__":
    mirror_if = find_mirror_interface(MIRROR_NETWORK_PREFIX)
    print(f"[goose_anomaly] Resolved mirror interface: {mirror_if} "
          f"(matched prefix {MIRROR_NETWORK_PREFIX!r})", flush=True)
    print(f"[goose_anomaly] Starting sniff on {mirror_if} for EtherType 0x88b8...", flush=True)
    print(f"[goose_anomaly] Known MACs: {KNOWN_GOOSE_MACS}", flush=True)
    sniff(iface=mirror_if, prn=handle_packet, store=False)
