import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# .timestamp にタイムスタンプ型を入れている部分を消して "@timestamp" だけにする
content = content.replace(
"""if exists(.ts) {
    .timestamp = from_unix_timestamp!(to_int(to_float!(.ts)), "seconds")
    ."@timestamp" = .timestamp
} else {
    .timestamp = now()
    ."@timestamp" = .timestamp
}""",
"""if exists(.ts) {
    ."@timestamp" = from_unix_timestamp!(to_int(to_float!(.ts)), "seconds")
} else {
    ."@timestamp" = now()
}""")

# 末尾付近に .timestamp = span_time_micro を追加
content = content.replace(
"""span_time_micro = to_int(to_unix_timestamp(now(), unit: "microseconds"))

color = "blue\"""",
"""span_time_micro = to_int(to_unix_timestamp(now(), unit: "microseconds"))
.timestamp = span_time_micro

color = "blue\"""")

with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed timestamp parsing issue!")
