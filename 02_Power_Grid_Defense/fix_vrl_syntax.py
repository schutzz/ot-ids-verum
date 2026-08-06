import re

with open("vector/vector.toml", "r", encoding="utf-8") as f:
    content = f.read()

# Fix bracket notation .["id.xxx"] back to correct VRL double-quote notation ."id.xxx"
content = content.replace('.["id.orig_h"]', '."id.orig_h"')
content = content.replace('.["id.resp_h"]', '."id.resp_h"')
content = content.replace('.["id.orig_p"]', '."id.orig_p"')
content = content.replace('.["id.resp_p"]', '."id.resp_p"')

with open("vector/vector.toml", "w", encoding="utf-8") as f:
    f.write(content)

print("VRL syntax fixed in vector.toml")
