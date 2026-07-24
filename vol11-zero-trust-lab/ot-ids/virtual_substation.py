import json
import time
import random
import os

LOG_FILE = "/var/log/ot_data/ids.json"

def log_event(event_type, action, status, threat_level="info"):
    event = {
        "attributes": {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())
        },
        "substation": "Kyiv-North-330kV",
        "protocol": "IEC-60870-5-104",
        "event": event_type,
        "action": action,
        "threat_level": threat_level,
        "status": status
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"Logged: {event['action']}")

if __name__ == "__main__":
    print("Starting Virtual Substation IEC-104 Simulator...")
    
    if os.path.exists(LOG_FILE):
        os.remove(LOG_FILE)
        
    while True:
        log_event("ASDU_M_ME_NA_1", "Voltage_Check", "Normal")
        time.sleep(2)
        
        if random.randint(1, 5) == 1:
            print("[!] INCOMING ATTACK DETECTED")
            for ioa in range(401, 404):
                log_event("ASDU_C_SC_NA_1", f"BREAKER_OPEN_IOA_{ioa}", "Executed", "critical")
                time.sleep(0.5)
