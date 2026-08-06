import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# 壊れた部分を見つける
target_pattern = r'    "raw_zeek_log": raw_zeek_json,\n(source = \'\'\'\n  \. = parse_json!\(\.race_log\))'

replacement = """    "raw_zeek_log": raw_zeek_json,
    "webdis_result": result
}

ts_seconds = to_float(.ts) ?? to_float(to_unix_timestamp(now(), unit: "seconds"))
span_time_micro = to_int(to_unix_timestamp(now(), unit: "microseconds"))

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
'''

[transforms.race_log_only]
type = "remap"
inputs = ["enrich_trace"]
\\1"""

new_content = re.sub(target_pattern, replacement, content)

with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(new_content)

print("Fixed!")
