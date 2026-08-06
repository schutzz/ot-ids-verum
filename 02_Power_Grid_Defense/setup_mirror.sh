#!/bin/bash
apt-get update
apt-get install -y iproute2 iptables tcpdump iputils-ping

MIRROR_IF=$(ip -o addr show | grep '10.0.99.254' | awk '{print $2}')
WAN_IF=$(ip -o addr show | grep '172.16.0.254' | awk '{print $2}')
SUB_B_IF=$(ip -o addr show | grep '10.0.30.254' | awk '{print $2}')

tc qdisc add dev $WAN_IF handle ffff: ingress 2>/dev/null
tc filter add dev $WAN_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

tc qdisc add dev $SUB_B_IF handle ffff: ingress 2>/dev/null
tc filter add dev $SUB_B_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

CC_LAN_IF=$(ip -o addr show | grep '10.0.10.254' | awk '{print $2}')
tc qdisc add dev $CC_LAN_IF handle ffff: ingress 2>/dev/null
tc filter add dev $CC_LAN_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

echo "Traffic mirroring setup complete."
