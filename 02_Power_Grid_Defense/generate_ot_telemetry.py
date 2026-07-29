import json
import time
import urllib.request
import urllib.error
import random
import os

SPLUNK_REALM = "jp0"
ACCESS_TOKEN = "05bdlF4LgTAEMRa2bNB1BQ"
METRICS_ENDPOINT = f"https://ingest.{SPLUNK_REALM}.signalfx.com/v2/datapoint"
HMI_STATUS_API = "http://localhost:1880/api/status"
FLAG_FILE = "trip_trigger.flag"
SHUTDOWN_FLAG = "ups_shutdown.flag"

class GridPhysicsEngine:
    def __init__(self):
        self.ups_soc = 100.0
        self.dnp3_rate = 1
        self.goose_st = 143

    def step(self, is_tripped, is_shutdown):
        if is_shutdown:
            # Stage 3b/4: UPS forcibly shut down (0%) and cause packet drop
            self.ups_soc = 0.0
            self.dnp3_rate = 0  # Cause packet dropped at Zeek TAP buffer
            self.goose_st = 144
        elif is_tripped:
            # Smooth physics drain curve
            if self.ups_soc > 60.0:
                drain = round(random.uniform(0.4, 0.9), 1)
                self.ups_soc = max(60.0, round(self.ups_soc - drain, 1))
            else:
                delta = round(random.uniform(-1.5, 2.8), 1)
                self.ups_soc = min(72.0, max(58.0, round(self.ups_soc + delta, 1)))
            self.dnp3_rate = random.randint(18, 28)
            self.goose_st = 144
        else:
            # Smooth recharge curve back to float charge 100%
            if self.ups_soc < 99.0:
                self.ups_soc = min(100.0, round(self.ups_soc + random.uniform(2.0, 4.5), 1))
            else:
                self.ups_soc = round(100.0 - random.uniform(0.0, 0.4), 1)
            self.dnp3_rate = 1
            self.goose_st = 143

engine = GridPhysicsEngine()

def get_hmi_tripped():
    return os.path.exists(FLAG_FILE)

def get_ups_shutdown():
    return os.path.exists(SHUTDOWN_FLAG)

def send_telemetry():
    is_tripped = get_hmi_tripped()
    is_shutdown = get_ups_shutdown()
    engine.step(is_tripped, is_shutdown)
    
    if is_shutdown:
        status_str = "[ATTACK & BREAKDOWN] UPS 0% DEAD & Zeek Loss 35.88% (Cause Dropped)"
    elif is_tripped:
        status_str = "[TRIPPED] Continuous Physics Drain"
    else:
        status_str = "[NORMAL] Smooth Float Charge"

    timestamp_ms = int(time.time() * 1000)
    rtt_1 = round(50.0 + random.uniform(-4.5, 5.2), 2)
    rtt_2 = round(52.0 + random.uniform(-6.0, 7.5), 2)
    rtt_3 = round(48.0 + random.uniform(-3.0, 8.1), 2)
    jitter_val = round(abs(rtt_1 - rtt_2) / 2.0, 2)
    
    # Packets loss spike on attack
    if is_shutdown:
        loss_val = round(35.88 + random.uniform(-2.1, 3.4), 2)
    else:
        loss_val = round(0.12 + random.uniform(-0.05, 0.08), 3)

    base_dims = {
        "service": "ot_network_security_monitor",
        "deployment.environment": "homemade_dragos_wide_grid",
        "host.name": "wan_router",
        "host": "wan_router"
    }

    datapoints = {
        "gauge": [
            {"metric": "dnp3.fc_name", "value": engine.dnp3_rate, "timestamp": timestamp_ms, "dimensions": {"fc_name": "DIRECT_OPERATE", "id.resp_h": "10.0.30.10", "service": "dnp3", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "wan.rtt.ms", "value": rtt_1, "timestamp": timestamp_ms, "dimensions": {**base_dims, "router_node": "core"}},
            {"metric": "wan.rtt.ms", "value": rtt_2, "timestamp": timestamp_ms, "dimensions": {**base_dims, "router_node": "sub_a"}},
            {"metric": "wan.rtt.ms", "value": rtt_3, "timestamp": timestamp_ms, "dimensions": {**base_dims, "router_node": "sub_b"}},
            {"metric": "rtt.wan.ms", "value": rtt_1, "timestamp": timestamp_ms, "dimensions": {**base_dims, "router_node": "core"}},
            {"metric": "wan.jitter.ms", "value": jitter_val, "timestamp": timestamp_ms, "dimensions": base_dims},
            {"metric": "ups.estimated_charge_remaining", "value": engine.ups_soc, "timestamp": timestamp_ms, "dimensions": {"id.orig_h": "10.0.30.10", "service": "ot_network_security_monitor", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "iec61850.st_num", "value": engine.goose_st, "timestamp": timestamp_ms, "dimensions": {"gocb_ref": "Kyiv_Grid/IED_Sub_A$GO$gcb01", "src_mac": "02:42:0a:00:14:0a", "service": "ot_network_security_monitor", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "jump_server.auth_status", "value": 1 if not (is_tripped or is_shutdown) else 0, "timestamp": timestamp_ms, "dimensions": {"auth_result": "SUCCESS" if not (is_tripped or is_shutdown) else "FAILED_TRIP_ALARM", "client_ip": "172.16.0.10", "service": "jumpserver", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "network.bytes", "value": int(random.uniform(4500, 5200)), "timestamp": timestamp_ms, "dimensions": {"proto": "IEC61850_GOOSE", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "network.bytes", "value": int(random.uniform(3200, 3800)) if not (is_tripped or is_shutdown) else int(random.uniform(28000, 45000)), "timestamp": timestamp_ms, "dimensions": {"proto": "DNP3", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "network.bytes", "value": int(random.uniform(1500, 1900)), "timestamp": timestamp_ms, "dimensions": {"proto": "SNMP_Trap", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "network.bytes", "value": int(random.uniform(800, 1100)), "timestamp": timestamp_ms, "dimensions": {"proto": "Modbus_TCP", "deployment.environment": "homemade_dragos_wide_grid"}},
            {"metric": "zeek.capture_loss.percent", "value": loss_val, "timestamp": timestamp_ms, "dimensions": {"service": "ot_network_security_monitor", "deployment.environment": "homemade_dragos_wide_grid"}}
        ]
    }

    req = urllib.request.Request(
        METRICS_ENDPOINT,
        data=json.dumps(datapoints).encode("utf-8"),
        headers={"Content-Type": "application/json", "X-SF-Token": ACCESS_TOKEN},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as resp:
            print(f"[{time.strftime('%H:%M:%S')}] {status_str} -> UPS SOC: {engine.ups_soc}% | DNP3 Rate: {engine.dnp3_rate}/s")
    except Exception as e:
        print(f"[!] Error sending metrics: {e}")

if __name__ == "__main__":
    print("[*] Continuous Physics Telemetry Generator Starting...")
    try:
        while True:
            send_telemetry()
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopped generator.")
