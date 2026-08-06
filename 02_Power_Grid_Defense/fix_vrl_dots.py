import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# Fix VRL syntax for keys with dots
content = content.replace('to_string(."id.orig_h")', 'to_string(.["id.orig_h"])')
content = content.replace('to_string(."id.resp_h")', 'to_string(.["id.resp_h"])')
content = content.replace('to_string(."id.orig_p")', 'to_string(.["id.orig_p"])')
content = content.replace('to_string(."id.resp_p")', 'to_string(.["id.resp_p"])')

with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("VRL keys with dots fixed!")
