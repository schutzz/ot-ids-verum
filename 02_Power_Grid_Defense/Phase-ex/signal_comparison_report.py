#!/usr/bin/env python3
"""
Phase6-2: Redis方式(enrichment_status)と新ロジック(zone_violation/correlation_fresh_hit)の
差分モニタリング用横断比較レポート。

決定事項#20により、この差分は「新ロジックの誤り」ではなく「Signal1〜6のPrecision/Recall」
として解釈する。決定事項#22で発見した「閾値境界での揺れ」を、シグナルロジック自体の限界
(=Redis方式のみhit)と混同しないよう、別カテゴリ(境界ギリギリでの不一致)として分離する。

分類:
  both_hit            : 新ロジック・Redis方式とも一致
  new_logic_only       : Redis方式の限界を新ロジックが補完できたケース(望ましい)
  redis_only          : 新ロジックの見逃し(要調査)
  boundary_mismatch    : redis_onlyのうち、閾値(BOUNDARY_WINDOW_SEC)をやや広げれば
                         new_logic側もhitになったはずのケース(境界の揺れ、要調査対象から除外)

集計は src_ip 単位、指定した時間ウィンドウ(デフォルト直近24時間)で行う。
結果は ot-signal-comparison-daily-%Y.%m.%d へ書き込む(6-2モニタリング期間中、日次実行想定)。
"""

import argparse
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone, timedelta

# コンテナ内実行時は docker-compose.yml から ES_URL=http://elasticsearch:9200 を渡す想定。
# ホストから直接実行する場合はデフォルトのlocalhost:9200のままでよい(9200はホストに公開済み)。
ES_URL = os.environ.get("ES_URL", "http://localhost:9200")

# 決定事項#22の閾値と同じ値。今後topology_node_enrichのしきい値を変更したら、ここも追随させること。
FRESH_WINDOW_SEC = 240
# 境界ギリギリでの不一致を判定する猶予幅。240秒〜(240+BOUNDARY_MARGIN_SEC)秒の間にlast_seenが
# あるredis_onlyケースを「境界ギリギリ」として分離する。
BOUNDARY_MARGIN_SEC = 120


def es_search(index, body):
    req = urllib.request.Request(
        f"{ES_URL}/{index}/_search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def es_bulk(lines):
    body = "\n".join(lines) + "\n"
    req = urllib.request.Request(
        f"{ES_URL}/_bulk",
        data=body.encode(),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.load(resp)


def collect_dnp3_signals(since_iso):
    """ot-logs-dnp3-*から、src_ipごとにRedis方式(enrichment_status)とSignal1(zone_violation)の
    hit有無を集計する。

    決定事項#49(技術的負債#2解消): route transform導入によりot-logs-dnp3-*は
    DNP3専用indexとなった(Modbus/connは分離済み)。このスクリプト自体は決定事項#25で
    「DNP3中心・送信元2-3種類」という制約付きで完了宣言済みの6-2検証用であり、
    意図的にDNP3専用のまま据え置く(Modbus/conn分の拡張は現時点では対象外)。
    """
    body = {
        "size": 0,
        "query": {"range": {"@timestamp": {"gte": since_iso}}},
        "aggs": {
            "by_src": {
                "terms": {"field": "tags.network_src_ip.keyword", "size": 1000},
                "aggs": {
                    "redis_hit": {
                        "filter": {"term": {"tags.enrichment_status": "hit"}}
                    },
                    "zone_violation_hit": {
                        "filter": {"term": {"tags.zone_violation": True}}
                    },
                },
            }
        },
    }
    result = es_search("ot-logs-dnp3-*", body)
    out = {}
    for bucket in result.get("aggregations", {}).get("by_src", {}).get("buckets", []):
        src = bucket["key"]
        if not src or src == "unknown":
            continue
        out[src] = {
            "redis_hit": bucket["redis_hit"]["doc_count"] > 0,
            "zone_violation_hit": bucket["zone_violation_hit"]["doc_count"] > 0,
        }
    return out


def collect_detection_results(now):
    """ot-detection-resultsから、src_ipごとのlast_seen/hit_countを取得し、
    新ロジック(Signal2-6)のfresh hit有無・境界ギリギリ判定用の経過秒数を計算する。"""
    body = {"size": 1000, "query": {"match_all": {}}}
    result = es_search("ot-detection-results", body)
    out = {}
    for hit in result.get("hits", {}).get("hits", []):
        s = hit["_source"]
        src = s.get("src_ip")
        if not src or src == "unknown":
            continue
        last_seen_str = s.get("last_seen")
        if not last_seen_str:
            continue
        last_seen = datetime.fromisoformat(last_seen_str.replace("Z", "+00:00"))
        age_sec = (now - last_seen).total_seconds()
        out[src] = {
            "hit_count": s.get("hit_count", 0),
            "age_sec": age_sec,
            "fresh_hit": 0 <= age_sec < FRESH_WINDOW_SEC and s.get("hit_count", 0) > 0,
            "boundary_hit": FRESH_WINDOW_SEC <= age_sec < (FRESH_WINDOW_SEC + BOUNDARY_MARGIN_SEC)
            and s.get("hit_count", 0) > 0,
        }
    return out


def classify(src_ips, dnp3_signals, detection_signals):
    categories = {
        "both_hit": [],
        "new_logic_only": [],
        "redis_only": [],
        "boundary_mismatch": [],
        "both_miss": [],
    }
    for src in src_ips:
        dnp3 = dnp3_signals.get(src, {"redis_hit": False, "zone_violation_hit": False})
        det = detection_signals.get(src, {"fresh_hit": False, "boundary_hit": False})

        redis_hit = dnp3["redis_hit"]
        # 新ロジック = Signal1(即時、zone_violation) OR Signal2-6(correlation_fresh_hit相当)
        new_logic_hit = dnp3["zone_violation_hit"] or det["fresh_hit"]

        if redis_hit and new_logic_hit:
            categories["both_hit"].append(src)
        elif (not redis_hit) and new_logic_hit:
            categories["new_logic_only"].append(src)
        elif redis_hit and (not new_logic_hit):
            if det["boundary_hit"]:
                categories["boundary_mismatch"].append(src)
            else:
                categories["redis_only"].append(src)
        else:
            categories["both_miss"].append(src)
    return categories


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hours", type=float, default=24.0, help="集計対象の遡り時間(時間単位)")
    parser.add_argument("--dry-run", action="store_true", help="ESへの書き込みを行わず結果表示のみ")
    args = parser.parse_args()

    now = datetime.now(timezone.utc)
    since = now - timedelta(hours=args.hours)
    since_iso = since.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    dnp3_signals = collect_dnp3_signals(since_iso)
    detection_signals = collect_detection_results(now)

    all_src_ips = set(dnp3_signals.keys()) | set(detection_signals.keys())
    categories = classify(all_src_ips, dnp3_signals, detection_signals)

    summary = {
        "@timestamp": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "window_hours": args.hours,
        "fresh_window_sec": FRESH_WINDOW_SEC,
        "boundary_margin_sec": BOUNDARY_MARGIN_SEC,
        "counts": {k: len(v) for k, v in categories.items()},
        "detail": categories,
    }

    print(json.dumps(summary, indent=2, ensure_ascii=False))

    if not args.dry_run:
        index_name = f"ot-signal-comparison-daily-{now.strftime('%Y.%m.%d')}"
        bulk_lines = [
            json.dumps({"index": {"_index": index_name}}),
            json.dumps(summary),
        ]
        result = es_bulk(bulk_lines)
        if result.get("errors"):
            print("ES書き込みエラー:", json.dumps(result), file=sys.stderr)
            sys.exit(1)
        print(f"\n書き込み完了: {index_name}", file=sys.stderr)


if __name__ == "__main__":
    main()
