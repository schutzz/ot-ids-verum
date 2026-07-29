import json
import urllib.request

with open("c:/Users/user/.gemini/antigravity-ide/scratch/blog_project/labs/homemade_dragos_lab/sub_b_hmi/cockpit_flow.json", "r", encoding="utf-8") as f:
    flows = json.load(f)

req = urllib.request.Request(
    "http://localhost:1880/flows",
    data=json.dumps(flows).encode("utf-8"),
    headers={"Content-Type": "application/json", "Node-RED-Deployment-Type": "full"},
    method="POST"
)
try:
    with urllib.request.urlopen(req) as resp:
        print("[+] Node-RED cockpit flows deployed successfully! Status:", resp.status)
except Exception as e:
    print("[!] Failed to deploy flows to Node-RED:", e)
