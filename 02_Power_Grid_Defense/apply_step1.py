import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# 1. parse_dnp3 から .edge__mainStat 行を削除
content = re.sub(r'\s*\.edge__mainStat = "DNP3 FC: " \+ fc_num', '', content)

# 2. parse_conn から .edge__mainStat 行を削除
content = re.sub(r'\s*\.edge__mainStat = "SSH/Token Auth"', '', content)

# 3. tags 配下のドット含むキー名をアンダースコア統一
content = content.replace('"network.src_ip"', '"network_src_ip"')
content = content.replace('"network.dest_ip"', '"network_dest_ip"')
content = content.replace('"network.attacker_ip"', '"network_attacker_ip"')
content = content.replace('"ot.dnp3.function_code"', '"ot_dnp3_function_code"')
content = content.replace('"workflow.name"', '"workflow_name"')
content = content.replace('"deployment.environment"', '"deployment_environment"')

# build_topology_nodes / edges での参照もアンダースコア統一に合わせて置換
content = content.replace('.tags."network.src_ip"', '.tags.network_src_ip')
content = content.replace('.tags."network.dest_ip"', '.tags.network_dest_ip')

# 4. build_topology_nodes の abort 削除と arc__color マージ処理の適用
old_nodes_block = '''[transforms.build_topology_nodes]
type = "remap"
inputs = ["enrich_trace"]
source = \'\'\'
  src_ip = to_string(.tags."network.src_ip") ?? "unknown"
  if src_ip == "" || src_ip == "unknown" { abort }
  
  if .color == "blue" { abort } # Only emit red nodes to avoid downgrading existing red nodes to blue in ES via upsert. Misses won't overwrite hits. Wait, if we abort, the node is never created if it's always miss.
  
  . = {
    "@timestamp": ."@timestamp",
    "id": src_ip,
    "title": src_ip,
    "subTitle": "Source Node",
    "mainStat": "Active",
    "color": .color
  }
\'\'\''''

new_nodes_block = '''[transforms.build_topology_nodes]
type = "remap"
inputs = ["enrich_trace"]
source = \'\'\'
  src_ip = to_string(.tags.network_src_ip) ?? "unknown"
  if src_ip == "" || src_ip == "unknown" { abort }
  
  . = {
    "@timestamp": ."@timestamp",
    "id": src_ip,
    "title": src_ip,
    "subTitle": "Source Node",
    "mainStat": "Active"
  }
  
  # 攻撃(red)のイベントの時のみ arc__color を付与して送信
  # ES の doc_as_upsert 特性により、正常(blue)イベント受信時に既存の "red" が消去されるのを防止する
  if .color == "red" {
    .arc__color = "red"
  }
\'\'\''''

if old_nodes_block in content:
    content = content.replace(old_nodes_block, new_nodes_block)
else:
    # 柔軟な正規表現置換
    content = re.sub(
        r'\[transforms\.build_topology_nodes\].*?\[transforms\.build_topology_edges\]',
        new_nodes_block + '\n\n[transforms.build_topology_edges]',
        content,
        flags=re.DOTALL
    )

# 5. 末尾のコメントアウトされた [[tests]] ブロックの削除
content = re.sub(r'# \[\[tests\]\].*', '', content, flags=re.DOTALL)

with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("Step 1 fixes applied successfully to vector.toml")
