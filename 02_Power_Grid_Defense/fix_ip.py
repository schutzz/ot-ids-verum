import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# 1. parse_dnp3 に zeek_src_ip, zeek_dest_ip を追加
content = content.replace(
"""  if orig_p != "" {
    .hash_key = orig_h + ":" + orig_p
  } else {
    .hash_key = orig_h
  }
'''""",
"""  if orig_p != "" {
    .hash_key = orig_h + ":" + orig_p
  } else {
    .hash_key = orig_h
  }
  .zeek_src_ip = orig_h
  .zeek_dest_ip = resp_h
'''""")

# 2. parse_conn に zeek_src_ip, zeek_dest_ip を追加
content = content.replace(
"""  } else {
    .hash_key = orig_h
  }
  .edge__mainStat = "SSH/Token Auth"
'''""",
"""  } else {
    .hash_key = orig_h
  }
  .edge__mainStat = "SSH/Token Auth"
  .zeek_src_ip = orig_h
  .zeek_dest_ip = to_string(.id.resp_h) ?? to_string(."id.resp_h") ?? "unknown"
'''""")

# 3. enrich_trace で zeek_src_ip, zeek_dest_ip を使用するように変更
content = content.replace(
"""orig_h_str = to_string(.id.orig_h) ?? to_string(."id.orig_h") ?? "unknown"
resp_h_str = to_string(.id.resp_h) ?? to_string(."id.resp_h") ?? "unknown\"""",
"""orig_h_str = to_string(.zeek_src_ip) ?? "unknown"
resp_h_str = to_string(.zeek_dest_ip) ?? "unknown\"""")


with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("Fixed Zeek IP extraction!")
