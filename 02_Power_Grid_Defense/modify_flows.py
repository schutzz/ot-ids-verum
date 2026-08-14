import json

FLOWS_FILE = "sub_b_hmi/flows.json"

def main():
    with open(FLOWS_FILE, 'r', encoding='utf-8') as f:
        flows = json.load(f)

    # Check if already added
    if any(node.get('id') == 'http_req_mtu' for node in flows):
        print("Already modified. Exiting.")
        return

    # Create new nodes
    func_prep_mtu_command = {
        "id": "func_prep_mtu_command",
        "type": "function",
        "z": "tab_cockpit",
        "name": "Prepare MTU Trip Command",
        "func": "if (msg.payload.state === false) {\n    msg.payload = { command: 'trip' };\n    return msg;\n}\nreturn null;",
        "outputs": 1,
        "noerr": 0,
        "initialize": "",
        "finalize": "",
        "libs": [],
        "x": 360,
        "y": 120,
        "wires": [["http_req_mtu"]]
    }

    http_req_mtu = {
        "id": "http_req_mtu",
        "type": "http request",
        "z": "tab_cockpit",
        "name": "Trigger SCADA MTU",
        "method": "POST",
        "ret": "obj",
        "url": "http://10.0.10.10:5000/api/command",
        "tls": "",
        "persist": False,
        "proxy": "",
        "x": 580,
        "y": 120,
        "wires": [[]]
    }

    flows.append(func_prep_mtu_command)
    flows.append(http_req_mtu)

    # Find the HTTP IN node
    for node in flows:
        if node.get("id") == "http_in_api_breaker":
            # Add wire to our new function node
            node["wires"][0].append("func_prep_mtu_command")

    with open(FLOWS_FILE, 'w', encoding='utf-8') as f:
        json.dump(flows, f, indent=4)

    print("Successfully modified flows.json to forward trip commands to cc_scada_master.")

if __name__ == "__main__":
    main()
