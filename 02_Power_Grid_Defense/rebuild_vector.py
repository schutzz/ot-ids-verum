import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# parse_dnp3 を置き換え
content = re.sub(
    r'\[transforms\.parse_dnp3\].*?\[transforms\.parse_conn\]',
    '''[transforms.parse_dnp3]
type = "remap"
inputs = ["zeek_dnp3_source"]
source = \'\'\'
  msg_str = to_string!(.message)
  
  if !starts_with(strip_whitespace(msg_str), "{") {
    abort
  }

  . = parse_json!(msg_str)

  orig_h = to_string(."id.orig_h") ?? to_string(.id.orig_h) ?? "unknown"
  if orig_h == "" { orig_h = "unknown" }
  
  resp_h = to_string(."id.resp_h") ?? to_string(.id.resp_h) ?? "unknown"
  if resp_h == "" { resp_h = "unknown" }
  
  if exists(.ts) {
    .processing_delay_ms = (to_float(now()) - to_float!(.ts)) * 1000.0
  }

  if orig_h == "" { orig_h = "unknown" }
  if resp_h == "" { resp_h = "unknown" }

  fc_num = "0"
  if exists(.fc) && .fc != null {
    fc_num = to_string(to_int!(.fc))
  }
  fc_str = to_string(.fc_request) ?? ""
  if fc_num == "0" && fc_str == "DIRECT_OPERATE" { fc_num = "5" }
  if fc_num == "0" && fc_str == "DIRECT_OPERATE_NO_ACK" { fc_num = "6" }
  if fc_num == "0" && fc_str == "IMMED_FREEZE" { fc_num = "7" }
  if fc_num == "0" && fc_str == "FREEZE_CLEAR" { fc_num = "8" }
  if fc_num == "0" && fc_str == "FREEZE_AT_TIME" { fc_num = "9" }
  if fc_num == "0" && fc_str == "COLD_RESTART" { fc_num = "13" }
  if fc_num == "0" && fc_str == "WARM_RESTART" { fc_num = "14" }
  if fc_num == "0" && fc_str == "DISABLE_UNSOLICITED" { fc_num = "20" }
  if fc_num == "0" && fc_str == "ENABLE_UNSOLICITED" { fc_num = "21" }
  if fc_num == "0" && fc_str == "READ" { fc_num = "1" }
  if fc_num == "0" && fc_str == "WRITE" { fc_num = "2" }
  if fc_num == "0" && fc_str == "SELECT" { fc_num = "3" }

  .edge__mainStat = "DNP3 FC: " + fc_num

  orig_p = to_string(."id.orig_p") ?? to_string(.id.orig_p) ?? ""

  if orig_p != "" {
    .hash_key = orig_h + ":" + orig_p
  } else {
    .hash_key = orig_h
  }
  
  .zeek_src_ip = orig_h
  .zeek_dest_ip = resp_h
\'\'\'

[transforms.parse_conn]''',
    content,
    flags=re.DOTALL
)

# parse_conn を置き換え
content = re.sub(
    r'\[transforms\.parse_conn\].*?\[transforms\.pre_lua_ts\]',
    '''[transforms.parse_conn]
type = "remap"
inputs = ["zeek_conn_source"]
source = \'\'\'
  msg_str = to_string!(.message)
  
  if !starts_with(strip_whitespace(msg_str), "{") {
    abort
  }

  . = parse_json!(msg_str)

  orig_h = to_string(."id.orig_h") ?? to_string(.id.orig_h) ?? "unknown"
  if orig_h == "" { orig_h = "unknown" }
  
  resp_h = to_string(."id.resp_h") ?? to_string(.id.resp_h) ?? "unknown"
  if resp_h == "" { resp_h = "unknown" }
  
  orig_p = to_string(."id.orig_p") ?? to_string(.id.orig_p) ?? ""
  
  if orig_p != "" {
    .hash_key = orig_h + ":" + orig_p
  } else {
    .hash_key = orig_h
  }
  
  .edge__mainStat = "SSH/Token Auth"
  .zeek_src_ip = orig_h
  .zeek_dest_ip = resp_h
\'\'\'

[transforms.pre_lua_ts]''',
    content,
    flags=re.DOTALL
)

# enrich_trace を置き換え
content = re.sub(
    r'\[transforms\.enrich_trace\].*?\[transforms\.race_log_only\]',
    '''[transforms.enrich_trace]
type = "remap"
inputs = ["enrich_trace_lua"]
source = \'\'\'
result = to_string(.webdis_result) ?? ""
my_span_id = slice!(replace(uuid_v4(), "-", ""), 0, 16)

if exists(.ts) {
    ."@timestamp" = from_unix_timestamp!(to_int(to_float!(.ts)), "seconds")
} else {
    ."@timestamp" = now()
}

.enrichment_status = "miss"
.attacker_ip = ""
my_trace_id = replace(uuid_v4(), "-", "")
if exists(.trace_id) && .trace_id != null {
    my_trace_id = to_string!(.trace_id)
}
my_parent_span_id = ""

if result != "" && length(result) > 5 {
    parsed = parse_json(result) ?? {}
    raw = to_string(parsed.GET) ?? ""
    nested = parse_json(raw) ?? {}

    if nested.trace_id != null {
        .enrichment_status = "hit"
        my_trace_id = to_string!(nested.trace_id)
        if nested.parent_span_id != null {
            my_parent_span_id = to_string!(nested.parent_span_id)
        }
        if nested.attacker_ip != null {
            .attacker_ip = to_string!(nested.attacker_ip)
        }
    }
}

log_event = {
    "trace_id": my_trace_id,
    "t_rx_eval": .t_rx_eval,
    "enrichment_status": .enrichment_status,
    "webdis_result": result
}
local_race_log = encode_json(log_event)

raw_zeek_json = encode_json(.)

fc_str = to_string(.fc) ?? to_string(.fc_request) ?? "0x05"

orig_h_str = to_string(.zeek_src_ip) ?? "unknown"
if orig_h_str == "" { orig_h_str = "unknown" }
resp_h_str = to_string(.zeek_dest_ip) ?? "unknown"
if resp_h_str == "" { resp_h_str = "unknown" }

tags = {
    "network_src_ip": orig_h_str,
    "network_dest_ip": resp_h_str,
    "network_attacker_ip": .attacker_ip,
    "ot_dnp3_function_code": to_string(.fc) ?? "",
    "enrichment_status": to_string(.enrichment_status),
    "workflow_name": "IT_to_OT_Killchain_DNP3",
    "deployment_environment": "ot-lab",
    "raw_zeek_log": raw_zeek_json,
    "webdis_result": result
}

ts_seconds = to_float(.ts) ?? to_float(to_unix_timestamp(now(), unit: "seconds"))
span_time_micro = to_int(to_unix_timestamp(now(), unit: "microseconds"))
.timestamp = span_time_micro

color = "blue"
if .enrichment_status == "hit" {
    color = "red"
}

.tags = tags
.race_log = local_race_log
.traceId = my_trace_id

# Elasticsearch でのパース競合を避けるため、Zeek由来のオブジェクトを退避して削除
.zeek_id = .id
del(.id)
del(."id.orig_h")
del(."id.resp_h")
del(."id.orig_p")
del(."id.resp_p")

.id = my_span_id
.color = color

if my_parent_span_id != "" {
    .parentId = my_parent_span_id
}
\'\'\'

[transforms.race_log_only]''',
    content,
    flags=re.DOTALL
)

with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("Robust IP parsing fixed!")
