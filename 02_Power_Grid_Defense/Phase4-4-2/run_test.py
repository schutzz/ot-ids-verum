import sys
import os
import time
import json
import urllib.request
import urllib.error

if len(sys.argv) < 4:
    print("Usage: python3 run_test.py <test_script.py> <target_src_ip> <container_name>")
    sys.exit(1)

test_script = sys.argv[1]
target_src_ip = sys.argv[2]
container_name = sys.argv[3]

ES_URL = "http://localhost:9200"

def es_search(index, term_field, term_value, size=1):
    """Query DSLのterm queryを使い、text分析やURLエンコード問題を回避する"""
    sort_field = "last_seen" if index == "ot-detection-results" else "@timestamp"
    body = json.dumps({
        "size": size,
        "sort": [{sort_field: {"order": "desc"}}],
        "query": {"term": {term_field: term_value}}
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{ES_URL}/{index}/_search",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"}
    )
    try:
        res = urllib.request.urlopen(req)
        return json.loads(res.read())["hits"]["hits"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        print(f"  [warn] {index} クエリエラー {e.code}: {e.read().decode()[:200]}")
        return []
    except Exception as e:
        print(f"  [warn] {index} クエリエラー: {e}")
        return []

def es_get_doc(index_pattern_date, doc_id):
    req = urllib.request.Request(f"{ES_URL}/{index_pattern_date}/_doc/{doc_id}")
    try:
        res = urllib.request.urlopen(req)
        return json.loads(res.read())["_source"]
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise

print(f"[1/5] クリーン状態確認 ({target_src_ip})...")
hits = es_search("ot-detection-results", "src_ip", target_src_ip)
print(f"  -> 前回のヒット: {hits[0]['_source'].get('last_seen')}" if hits else "  -> クリーン")

print(f"\n[2/5] テスト実行 ({test_script} on {container_name})...")
exit_code = os.system(f"docker exec {container_name} python3 /phase4-4-2/{os.path.basename(test_script)}")
if exit_code != 0:
    print("  -> テストスクリプトの実行に失敗しました")
    sys.exit(1)

print("\n[3/5] Enrich Policy再実行...")
req = urllib.request.Request(f"{ES_URL}/_enrich/policy/detection_lookup_policy/_execute", method="POST")
try:
    urllib.request.urlopen(req)
    print("  -> ポリシー更新成功")
except Exception as e:
    print(f"  -> ポリシー更新エラー: {e}")

print("\n[4/5] Transform同期待機(35秒)...")
for i in range(35, 0, -5):
    print(f"  ...残り {i} 秒")
    time.sleep(5)

print("\n[5/5] 結果サマリ出力...")
indices = ["ot-logs-weird-*", "ot-logs-dnp3control-*", "ot-logs-notice-*", "ot-logs-suricata-*"]
found_signals = []

for idx in indices:
    hits = es_search(idx, "zeek_src_ip", target_src_ip)
    if hits:
        doc = hits[0]["_source"]
        ts_str = doc.get("@timestamp") or doc.get("timestamp") or ""
        print(f"  - {idx}: 最新ログ = {ts_str}")
        if "suricata" in idx and doc.get("event_type") == "alert":
            found_signals.append(f"Suricata: {doc.get('alert_signature')}")
        elif "weird" in idx:
            found_signals.append(f"Weird: {doc.get('weird_name')}")
        elif "dnp3control" in idx:
            found_signals.append(f"DNP3Control: {doc.get('name', 'ICSNPP')}")
        elif "notice" in idx:
            found_signals.append(f"Notice: {doc.get('note')}")
    else:
        print(f"  - {idx}: ヒットなし")

print("\n=== ot-detection-results の状態 ===")
hits = es_search("ot-detection-results", "src_ip", target_src_ip)
print(json.dumps(hits[0]["_source"], indent=2, ensure_ascii=False) if hits else "該当なし")

print("\n=== ot-topology-nodes (Zone Violation) の状態 ===")
from datetime import datetime
index_date = datetime.utcnow().strftime("%Y.%m.%d")
doc = es_get_doc(f"ot-topology-nodes-{index_date}", target_src_ip)
if doc:
    zv = doc.get("zone_violation")
    print(f"zone_violation: {zv}")
    if zv:
        found_signals.append("Vector: zone_violation=true")
else:
    print("該当なし")

print("\n=== 検出シグナルまとめ ===")
for s in found_signals:
    print(f" - {s}")
