#!/bin/bash
apt-get update
apt-get install -y iproute2 iptables tcpdump iputils-ping

MIRROR_IF=$(ip -o addr show | grep '10.0.99.254' | awk '{print $2}' | awk -F'@' '{print $1}')
WAN_IF=$(ip -o addr show | grep '172.16.0.254' | awk '{print $2}' | awk -F'@' '{print $1}')
SUB_B_IF=$(ip -o addr show | grep '10.0.30.254' | awk '{print $2}' | awk -F'@' '{print $1}')

# 決定事項#39: tc filterは冪等でないため、setup_mirror.shの複数回実行のたびに
# 同一内容のfilterが重複登録され続けていた(WAN_IF/SUB_B_IF/CC_LAN_IFで実際に
# 2重登録を確認、SUB_B_IF側の重複がModbus応答パケットのミラー配送を阻害する
# 実害を引き起こしていた)。tc qdisc addと同様、filter追加の前に既存filterを
# 全削除してから再作成することで、何度実行しても最終的に1件だけになるようにする。

tc qdisc add dev $WAN_IF handle ffff: ingress 2>/dev/null
tc filter del dev $WAN_IF parent ffff: 2>/dev/null
tc filter add dev $WAN_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

tc qdisc add dev $SUB_B_IF handle ffff: ingress 2>/dev/null
tc filter del dev $SUB_B_IF parent ffff: 2>/dev/null
tc filter add dev $SUB_B_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

CC_LAN_IF=$(ip -o addr show | grep '10.0.10.254' | awk '{print $2}' | awk -F'@' '{print $1}')
tc qdisc add dev $CC_LAN_IF handle ffff: ingress 2>/dev/null
tc filter del dev $CC_LAN_IF parent ffff: 2>/dev/null
tc filter add dev $CC_LAN_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

# Phase8-0(技術的負債#3対応): sub_a(10.0.20.0/24, GOOSEセグメント)のミラーリング追加
SUB_A_IF=$(ip -o addr show | grep '10.0.20.254' | awk '{print $2}' | awk -F'@' '{print $1}')
tc qdisc add dev $SUB_A_IF handle ffff: ingress 2>/dev/null
tc filter del dev $SUB_A_IF parent ffff: 2>/dev/null
tc filter add dev $SUB_A_IF parent ffff: protocol all u32 match u32 0 0 action mirred egress mirror dev $MIRROR_IF

echo "Traffic mirroring setup complete."
