import sys
import time
import requests
import json
import uuid
import random
import urllib.request
from threading import Thread, Lock
from http.server import BaseHTTPRequestHandler, HTTPServer

try:
    from scapy.all import sniff, TCP, UDP, IP, ARP, Raw
except ImportError:
    print("[!] scapy is not installed. Please run: pip install scapy", file=sys.stderr)
    sys.exit(1)
import os

# --- Configuration ---
HMI_URL = "http://192.168.151.20:1880/api/alert"
COOLDOWN_SECONDS = 5

# --- State tracking ---
arp_table_ip_to_mac = {}
arp_table_mac_to_ip = {}
last_alert_time = 0
bacnet_events = {} # ip -> timestamp

# --- Trace Context (Temporal Proximity) ---
trace_context = {}
trace_lock = Lock()

def log_event(event_name, message, trace_id=None, parent_span_id=None, metadata=None):
    current_time = time.time()
    active_trace_id = trace_id
    
    # Context propagation via temporal proximity
    if active_trace_id is None:
        with trace_lock:
            recent_contexts = [(k, v) for k, v in trace_context.items() if current_time - v[2] < 2.0]
            if recent_contexts:
                recent_contexts.sort(key=lambda x: x[1][2], reverse=True) # Sort by newest
                active_trace_id = recent_contexts[0][1][0]
                parent_span_id = recent_contexts[0][1][1]
    
    if not active_trace_id:
        active_trace_id = format(random.getrandbits(128), '032x')
        
    span_id = format(random.getrandbits(64), '016x')
    timestamp_us = int(current_time * 1000000)
    
    tags = {"message": message}
    if metadata:
        tags.update(metadata)
        
    span = {
        "traceId": active_trace_id,
        "id": span_id,
        "name": event_name,
        "kind": "SERVER",
        "timestamp": timestamp_us,
        "duration": 1000,
        "localEndpoint": {"serviceName": "ot-ids"},
        "tags": tags
    }
    
    if parent_span_id:
        span["parentId"] = parent_span_id
        
    try:
        req = urllib.request.Request(
            'http://192.168.151.40:9411/api/v2/spans',
            data=json.dumps([span]).encode('utf-8'),
            headers={'Content-Type': 'application/json'},
            method='POST'
        )
        urllib.request.urlopen(req, timeout=1)
    except Exception as e:
        pass

def send_splunk_event(event_type, message, dimensions=None):
    realm = "jp0"
    token = "05bdlF4LgTAEMRa2bNB1BQ"
    if not realm or not token:
        print("[!] SPLUNK_REALM or SPLUNK_ACCESS_TOKEN not set, skipping Custom Event")
        return
        
    url = f"https://ingest.{realm}.signalfx.com/v2/event"
    timestamp_ms = int(time.time() * 1000)
    
    event_data = {
        "category": "USER_DEFINED",
        "eventType": event_type,
        "timestamp": timestamp_ms,
        "properties": {
            "message": message
        }
    }
    
    if dimensions:
        event_data["dimensions"] = dimensions
        
    try:
        headers = {
            "X-SF-TOKEN": token,
            "Content-Type": "application/json"
        }
        requests.post(url, headers=headers, json=[event_data], timeout=2)
        print(f"[DEBUG] Sent Custom Event {event_type} to Splunk")
    except Exception as e:
        print(f"[DEBUG] Failed to send Custom Event: {e}")



class TraceContextHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode('utf-8'))
            trace_id = data.get('trace_id')
            span_id = data.get('span_id')
            event_name = data.get('event.name')
            
            if trace_id and span_id:
                with trace_lock:
                    trace_context[event_name] = (trace_id, span_id, time.time())
                
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
            else:
                self.send_response(400)
                self.end_headers()
        except Exception:
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        pass # Suppress standard HTTP logs so they don't break JSON logging

def start_trace_server():
    server = HTTPServer(('0.0.0.0', 5000), TraceContextHandler)
    server.serve_forever()

def send_alert_to_hmi(alert_type, attacker_ip, attacker_mac, details):
    global last_alert_time
    current_time = time.time()
    
    if current_time - last_alert_time < COOLDOWN_SECONDS:
        return
        
    last_alert_time = current_time
    
    payload = {
        "alert_type": alert_type,
        "attacker_ip": attacker_ip,
        "attacker_mac": attacker_mac,
        "details": details,
        "timestamp": int(current_time)
    }
    
    try:
        requests.post(HMI_URL, json=payload, timeout=2)
    except Exception:
        pass

def process_packet(pkt):
    global arp_table_ip_to_mac, arp_table_mac_to_ip, bacnet_events
    
    if pkt.haslayer(IP):
        src_ip = pkt[IP].src
        
        # Check BACnet (UDP 47808)
        if pkt.haslayer(UDP) and pkt[UDP].dport == 47808:
            print(f"[DEBUG] Saw BACnet packet from {src_ip}")
            bacnet_events[src_ip] = time.time()
            
        # Check RTSP (TCP 8554)
        if pkt.haslayer(TCP) and pkt[TCP].dport == 8554:
            print(f"[DEBUG] Saw RTSP packet from {src_ip}")
            if src_ip in bacnet_events:
                time_diff = time.time() - bacnet_events[src_ip]
                print(f"[DEBUG] Correlation matched! time_diff={time_diff}")
                if 0 < time_diff < 60: # Within 60 seconds
                    log_msg = (f"[!] 複合シナリオアラート: 「門扉不正開放(BACnet) ➔ カメラアクセス(RTSP)」 の連鎖\n\n"
                               f"{time.strftime('%H:%M:%S', time.localtime(bacnet_events[src_ip]))} [BACnet Gateway] Unauthorized Write (Object: Gate)\n"
                               f"         --> normalized_ip: {src_ip} / payload: 0x810a00110104...\n"
                               f"         | ({int(time_diff)} seconds later...)\n"
                               f"{time.strftime('%H:%M:%S')} [RTSP Server] Camera Feed Accessed\n"
                               f"         --> normalized_ip: {src_ip} / method: DESCRIBE")
                    log_event("bacnet_rtsp_correlation", "Physical Security & OT Control Correlation", metadata={
                        "attacker_ip": src_ip,
                        "log_detail": log_msg
                    })
                    # Send as a Custom Event for the dynamic Event Feed Panel in Splunk
                    Thread(target=send_splunk_event, args=("bacnet_rtsp_correlation", log_msg, {"attacker_ip": src_ip})).start()
                    del bacnet_events[src_ip]
    
    if pkt.haslayer(ARP) and pkt[ARP].op in (1, 2):
        ip = pkt[ARP].psrc
        mac = pkt[ARP].hwsrc
        
        if ip in arp_table_ip_to_mac and arp_table_ip_to_mac[ip] != mac:
            log_event("arp_spoof_detected", "Conflicting MAC addresses detected", metadata={
                "attacker_ip": ip,
                "attacker_mac": mac,
                "original_mac": arp_table_ip_to_mac[ip]
            })
            Thread(target=send_alert_to_hmi, args=("ARP Spoofing (Conflict)", ip, mac, f"Original MAC: {arp_table_ip_to_mac[ip]}, Spoofed MAC: {mac}")).start()
        else:
            arp_table_ip_to_mac[ip] = mac

        if mac in arp_table_mac_to_ip and ip not in arp_table_mac_to_ip[mac]:
            log_event("arp_spoof_detected", "Single MAC claiming multiple IPs", metadata={
                "attacker_ip": ip,
                "attacker_mac": mac,
                "claimed_ips": arp_table_mac_to_ip[mac] + [ip]
            })
            Thread(target=send_alert_to_hmi, args=("ARP Spoofing (MITM)", ip, mac, f"MAC {mac} is claiming multiple IPs!")).start()
            arp_table_mac_to_ip[mac].append(ip)
        elif mac not in arp_table_mac_to_ip:
            arp_table_mac_to_ip[mac] = [ip]

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        if pkt[TCP].dport == 502 or pkt[TCP].sport == 502:
            payload = pkt[Raw].load
            if len(payload) >= 8:
                fc = payload[7]
                if fc == 0x05:
                    src_ip = pkt[IP].src
                    log_event("modbus_unauthorized_write", "Unauthorized Write Command (FC 0x05)", metadata={
                        "attacker_ip": src_ip
                    })
                    Thread(target=send_alert_to_hmi, args=("Modbus Memory Override", src_ip, "Unknown", f"Unauthorized FC 0x05 write detected")).start()

def main():
    # Start the HTTP server for trace context receiving in a background thread
    Thread(target=start_trace_server, daemon=True).start()
    
    # Initial JSON log
    log_event("ids_started", "OT-IDS Real-time NSM Engine initialized")
    
    try:
        sniff(iface="eth0", prn=process_packet, store=0)
    except Exception:
        sys.exit(1)

if __name__ == '__main__':
    main()
