import json
import os

flows_path = r"C:\Users\user\.gemini\antigravity-ide\scratch\github_repo\ot-security-lab\Phase12_Splunk_Observability\hmi_data\flows.json"

with open(flows_path, "r", encoding="utf-8") as f:
    flows = json.load(f)

# 1. ブレーカー用グループの追加 (ui_group)
group_id = "group_circuit_breakers"
tab_id = "tab_ot_dashboard"

# すでにグループが存在しなければ追加
existing_group = next((n for n in flows if n.get("id") == group_id), None)
if not existing_group:
    flows.append({
        "id": group_id,
        "type": "ui_group",
        "name": "広域変電所 系統遮断器ステータス (3-System Circuit Breakers)",
        "tab": tab_id,
        "order": 3,
        "disp": True,
        "width": "6",
        "collapse": False
    })

# 2. 3系統遮断器のUIテキスト/LEDノードの追加
breakers_nodes = [
    {
        "id": "ui_breaker_cb101",
        "type": "ui_text",
        "z": "f6f2187d.f17ca8",
        "group": group_id,
        "order": 1,
        "width": "6",
        "height": "1",
        "name": "CB-101",
        "label": "CB-101 (変電所A 主系統):",
        "format": "<span style='color: {{msg.color}}; font-weight: bold;'>{{msg.payload}}</span>",
        "layout": "row-spread"
    },
    {
        "id": "ui_breaker_cb202",
        "type": "ui_text",
        "z": "f6f2187d.f17ca8",
        "group": group_id,
        "order": 2,
        "width": "6",
        "height": "1",
        "name": "CB-202",
        "label": "CB-202 (変電所B 予備系統):",
        "format": "<span style='color: {{msg.color}}; font-weight: bold;'>{{msg.payload}}</span>",
        "layout": "row-spread"
    },
    {
        "id": "ui_breaker_cb303",
        "type": "ui_text",
        "z": "f6f2187d.f17ca8",
        "group": group_id,
        "order": 3,
        "width": "6",
        "height": "1",
        "name": "CB-303",
        "label": "CB-303 (変圧器 Bus-Tie 連絡線):",
        "format": "<span style='color: {{msg.color}}; font-weight: bold;'>{{msg.payload}}</span>",
        "layout": "row-spread"
    }
]

for b_node in breakers_nodes:
    if not any(n.get("id") == b_node["id"] for n in flows):
        flows.append(b_node)

with open(flows_path, "w", encoding="utf-8") as f:
    json.dump(flows, f, ensure_ascii=False, indent=4)

print("Successfully added 3-system circuit breakers to flows.json!")
