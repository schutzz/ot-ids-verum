#!/bin/bash
# setup_elasticsearch.sh
#
# Signal1〜6の判定ロジックが依存するElasticsearchの設定一式(Index Template・
# Transform・Enrich Policy・Ingest Pipeline)を作成する。
#
# 背景: これらは開発の過程でその都度curlコマンドで作成されたが、一括で再現する
# スクリプトが存在しなかった(2026-08-14、DEPLOYMENT.md作成時に判明)。本スクリプト
# は稼働中クラスタから実際の定義をそのまま抽出して構成したもので、内容は現行の
# 稼働中クラスタと一致することを確認済み。
#
# 前提: elasticsearchコンテナが起動し、http://localhost:9200 で応答すること。
# 実行: docker compose --profile legacy up -d elasticsearch の後、このスクリプトを実行する。
#
# 依存関係の順序:
#   1. Index Template (ot-logs-* が作られる前に登録しておく必要がある。決定事項#7参照:
#      Index Templateは「新規作成されるindex」にのみ適用され、既存indexには遡って適用されない)
#   2. Transform (集計元・集計先のindexは未作成でも定義自体は可能)
#   3. Enrich Policy (作成後に _execute で一度実体化させる。以降はes-enrich-refresherが60秒毎に自動更新)
#   4. Ingest Pipeline (対応するEnrich Policyが存在している必要がある)

set -e
ES_URL="${ES_URL:-http://localhost:9200}"

echo "[1/4] Index Template (ot_logs_template) を作成..."
curl -s -X PUT "$ES_URL/_index_template/ot_logs_template" -H 'Content-Type: application/json' -d '{
  "index_patterns": ["ot-logs-*"],
  "template": {
    "mappings": {
      "properties": {
        "zeek_src_ip":     { "type": "keyword" },
        "zeek_dest_ip":    { "type": "keyword" },
        "alert_signature": { "type": "keyword" },
        "weird_name":      { "type": "keyword" },
        "notice_type":     { "type": "keyword" }
      }
    }
  }
}'
echo

echo "[2/4] Transform を作成・開始..."
curl -s -X PUT "$ES_URL/_transform/last_read_per_src" -H 'Content-Type: application/json' -d '{
  "source": {
    "index": ["ot-logs-dnp3-2026.08.08*", "ot-logs-dnp3-2026.08.09*", "ot-logs-dnp3-2026.08.1*", "ot-logs-dnp3-2026.08.2*", "ot-logs-dnp3-2026.08.3*"],
    "query": { "term": { "fc_request.keyword": "READ" } }
  },
  "dest": { "index": "ot-last-read-tracking" },
  "frequency": "30s",
  "sync": { "time": { "field": "@timestamp", "delay": "10s" } },
  "pivot": {
    "group_by": { "src_ip": { "terms": { "field": "zeek_src_ip" } } },
    "aggregations": { "last_read_time": { "max": { "field": "@timestamp" } } }
  }
}'
echo
curl -s -X POST "$ES_URL/_transform/last_read_per_src/_start"
echo

curl -s -X PUT "$ES_URL/_transform/ot_signal_correlation" -H 'Content-Type: application/json' -d '{
  "source": {
    "index": ["ot-logs-suricata-*", "ot-logs-dnp3control-*", "ot-logs-weird-*", "ot-logs-notice-*", "ot-logs-killchain-*"],
    "query": { "match_all": {} }
  },
  "dest": { "index": "ot-detection-results" },
  "frequency": "30s",
  "sync": { "time": { "field": "@timestamp", "delay": "10s" } },
  "pivot": {
    "group_by": { "src_ip": { "terms": { "field": "zeek_src_ip" } } },
    "aggregations": {
      "last_seen":       { "max": { "field": "@timestamp" } },
      "hit_count":       { "value_count": { "field": "zeek_src_ip" } },
      "top_signature": {
        "top_metrics": {
          "metrics": [
            { "field": "alert_signature" },
            { "field": "notice_type" },
            { "field": "weird_name" }
          ],
          "sort": { "@timestamp": "desc" }
        }
      },
      "sbo_bypass_count":  { "filter": { "term": { "sbo_bypass": true } } },
      "killchain_count":   { "filter": { "term": { "killchain_detected": true } } }
    }
  }
}'
echo
curl -s -X POST "$ES_URL/_transform/ot_signal_correlation/_start"
echo

echo "[3/4] Enrich Policy を作成・実体化..."
curl -s -X PUT "$ES_URL/_enrich/policy/detection_lookup_policy" -H 'Content-Type: application/json' -d '{
  "match": {
    "indices": ["ot-detection-results"],
    "match_field": "src_ip",
    "enrich_fields": ["top_signature", "hit_count", "last_seen"]
  }
}'
echo
curl -s -X PUT "$ES_URL/_enrich/policy/last_read_lookup_policy" -H 'Content-Type: application/json' -d '{
  "match": {
    "indices": ["ot-last-read-tracking"],
    "match_field": "src_ip",
    "enrich_fields": ["last_read_time"]
  }
}'
echo
curl -s -X POST "$ES_URL/_enrich/policy/detection_lookup_policy/_execute"
echo
curl -s -X POST "$ES_URL/_enrich/policy/last_read_lookup_policy/_execute"
echo

echo "[4/4] Ingest Pipeline を作成..."
curl -s -X PUT "$ES_URL/_ingest/pipeline/dnp3_control_sbo_check" -H 'Content-Type: application/json' -d '{
  "processors": [
    { "set": { "field": "_ingest_ts", "value": "{{{_ingest.timestamp}}}" } },
    { "enrich": {
        "policy_name": "last_read_lookup_policy",
        "field": "zeek_src_ip",
        "target_field": "read_match",
        "max_matches": 1,
        "ignore_missing": true
    }},
    { "script": {
        "source": "if (ctx.read_match == null) {\n  ctx.sbo_bypass = true;\n} else {\n  long now = ZonedDateTime.parse(ctx._ingest_ts).toInstant().toEpochMilli();\n  long lastRead = ZonedDateTime.parse(ctx.read_match.last_read_time).toInstant().toEpochMilli();\n  ctx.sbo_bypass = (now - lastRead) > 1800000L;\n}"
    }},
    { "remove": { "field": "_ingest_ts", "ignore_missing": true } }
  ]
}'
echo
curl -s -X PUT "$ES_URL/_ingest/pipeline/topology_node_enrich" -H 'Content-Type: application/json' -d '{
  "processors": [
    { "set": { "field": "_ingest_ts", "value": "{{{_ingest.timestamp}}}" } },
    { "enrich": {
        "policy_name": "detection_lookup_policy",
        "field": "id",
        "target_field": "detection_match",
        "max_matches": 1,
        "ignore_missing": true
    }},
    { "script": {
        "source": "if (ctx.detection_match != null) {\n  long now = ZonedDateTime.parse(ctx._ingest_ts).toInstant().toEpochMilli();\n  long lastSeen = ZonedDateTime.parse(ctx.detection_match.last_seen).toInstant().toEpochMilli();\n  ctx.correlation_fresh_hit = (now - lastSeen) < 240000L;\n} else {\n  ctx.correlation_fresh_hit = false;\n}\nctx.correlation_would_be_red = ctx.correlation_fresh_hit;"
    }},
    { "set": { "if": "ctx.correlation_fresh_hit == true && ctx.shadow_mode != true", "field": "color", "value": "red" } },
    { "set": { "if": "ctx.correlation_fresh_hit == true && ctx.shadow_mode != true", "field": "arc__status", "value": 1.0 } },
    { "set": { "if": "ctx.correlation_fresh_hit == true && ctx.shadow_mode != true", "field": "arc__status_color", "value": "red" } },
    { "remove": { "field": "_ingest_ts", "ignore_missing": true } }
  ]
}'
echo

echo "完了。ot-detection-results / ot-last-read-tracking にデータが流れ始めると、"
echo "es_enrich_refresherコンテナ(60秒間隔)がEnrich Policyを自動更新し続けます。"
