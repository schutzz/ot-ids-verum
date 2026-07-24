import time
import sys
import os

# Ensure we can import realtime_ids
sys.path.append("/ids")
import realtime_ids

from scapy.all import IP, UDP, TCP, Ether

print("Creating fake BACnet packet...")
bacnet_pkt = Ether()/IP(src="10.0.5.22", dst="192.168.151.30")/UDP(dport=47808)

print("Creating fake RTSP packet...")
rtsp_pkt = Ether()/IP(src="10.0.5.22", dst="192.168.151.30")/TCP(dport=8554, flags="S")

print("Feeding BACnet packet to IDS engine...")
realtime_ids.process_packet(bacnet_pkt)

print("Waiting 2 seconds...")
time.sleep(2)

print("Feeding RTSP packet to IDS engine...")
realtime_ids.process_packet(rtsp_pkt)

print("Correlation trigger completed! Wait a few seconds for OTel to forward to Splunk.")
time.sleep(3)
