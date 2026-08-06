import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# E651 エラーを修正
# "id_obj = .id ?? {}" を削除し、直接参照する
content = content.replace('id_obj = .id ?? {}', '')
content = content.replace('orig_h = to_string(id_obj.orig_h) ?? to_string(."id.orig_h") ?? "unknown"', 'orig_h = to_string(.id.orig_h) ?? to_string(."id.orig_h") ?? "unknown"')
content = content.replace('resp_h = to_string(id_obj.resp_h) ?? to_string(."id.resp_h") ?? "unknown"', 'resp_h = to_string(.id.resp_h) ?? to_string(."id.resp_h") ?? "unknown"')
content = content.replace('orig_p = to_string(id_obj.orig_p) ?? to_string(."id.orig_p") ?? ""', 'orig_p = to_string(.id.orig_p) ?? to_string(."id.orig_p") ?? ""')


with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("VRL Error E651 fixed!")
