#!/usr/bin/env python3
"""
killchain_eql_poller.py — Signal6(IT→OTキルチェーン相関)のEQL定期ポーリングsidecar。

Vectorのhttp_client sourceがElasticsearchの_eql/searchエンドポイントと非互換
(URL/body/ヘッダーのどの組み合わせでも400、同一内容のcurlは成功)と判明したため、
Vectorを介さずPythonで直接ポーリング→_bulk書き込みを行う(決定事項#18)。

出力ドキュメントのスキーマは、当初vector.tomlのexpand_killchain_detections(Lua)で
設計したものと同一に保っている(ot_signal_correlationのkillchain_count filter集約
に影響を与えないため)。

A案(定数フィルタ): cc_scada_master(10.0.10.10)へのHTTP POST /api/command → 同資産発の
DNP3 Direct Operateアラート、というsequenceをmaxspan=30sで検知する。
"""
import json
import time

import requests

ES_URL = "http://elasticsearch:9200"
POLL_INTERVAL_SEC = 15

EQL_QUERY = {
    # detection_results_poll(vector.toml)と同じ"now-2m"ウィンドウ。フィルタなしだと
    # 同じ過去のシーケンスを毎ポーリング周期(15秒)ごとに再検出し、重複書き込みが
    # 無制限に積み上がってしまうため必須(実機で確認: 2周期で9件→27件に増加した)。
    "filter": {"range": {"@timestamp": {"gte": "now-2m"}}},
    "query": (
        'sequence with maxspan=30s '
        '[any where http_method == "POST" and http_uri == "/api/command" and zeek_dest_ip == "10.0.10.10"] '
        '[any where zeek_src_ip == "10.0.10.10" and alert_signature == "OT-IDS: DNP3 Direct Operate (fc=5)"]'
    ),
    "size": 50,
}


def poll_and_write():
    resp = requests.post(
        f"{ES_URL}/ot-logs-http-*,ot-logs-suricata-*/_eql/search",
        json=EQL_QUERY,
        timeout=10,
    )
    resp.raise_for_status()
    sequences = resp.json().get("hits", {}).get("sequences", [])

    bulk_lines = []
    for seq in sequences:
        pivot_ip, attacker_ip, http_ts, alert_ts = "unknown", "unknown", None, None
        for ev in seq.get("events", []):
            src = ev.get("_source", {})
            if "http_uri" in src:
                attacker_ip = src.get("zeek_src_ip", "unknown")
                pivot_ip = src.get("zeek_dest_ip", "unknown")
                http_ts = src.get("@timestamp")
            elif "alert_signature" in src:
                alert_ts = src.get("@timestamp")

        if pivot_ip != "unknown":
            doc = {
                "@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                # zeek_src_ipはpivot_ip(cc_scada_master)にする: Signal2〜5と同じ資産で
                # ot_signal_correlationのgroup_byに合流させるため。attacker_ipは参考情報として別途保持
                "zeek_src_ip": pivot_ip,
                "pivot_ip": pivot_ip,
                "attacker_ip": attacker_ip,
                "http_event_ts": http_ts,
                "alert_event_ts": alert_ts,
                "killchain_detected": True,
            }
            index_name = time.strftime("ot-logs-killchain-%Y.%m.%d", time.gmtime())
            bulk_lines.append(json.dumps({"index": {"_index": index_name}}))
            bulk_lines.append(json.dumps(doc))

    if bulk_lines:
        bulk_body = "\n".join(bulk_lines) + "\n"
        r = requests.post(
            f"{ES_URL}/_bulk",
            data=bulk_body,
            headers={"Content-Type": "application/x-ndjson"},
        )
        r.raise_for_status()
        print(f"[+] Wrote {len(bulk_lines) // 2} killchain detections", flush=True)


if __name__ == "__main__":
    print("[killchain_eql_poller] starting, polling every "
          f"{POLL_INTERVAL_SEC}s", flush=True)
    while True:
        try:
            poll_and_write()
        except Exception as e:
            print(f"[!] Error: {e}", flush=True)
        time.sleep(POLL_INTERVAL_SEC)
