import struct
import time

# PCAP Global Header
# magic_number (4B), version_major (2B), version_minor (2B), thiszone (4B), sigfigs (4B), snaplen (4B), network (4B: 1=Ethernet)
pcap_global_hdr = struct.pack('<IHHIIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)

# Ethernet Header (14B)
eth_hdr = bytes.fromhex("000c29123456000c296543210800")

# IPv4 Header (20B): Src=192.168.10.100 (c0a80a64), Dst=192.168.151.20 (c0a89714), Proto=6 (TCP)
ip_hdr = bytes.fromhex("4500003b0001000040067c2ac0a80a64c0a89714")

# TCP Header (20B): SrcPort=50333 (c49d), DstPort=20000 (4e20), Flags=0x18 (PSH, ACK)
tcp_hdr = bytes.fromhex("c49d4e2000000001000000015018020000000000")

# DNP3 Application Payload (Direct Operate: Function Code 0x05)
# C4 (App Control: Seq 4), 05 (Function Code: Direct Operate), 0C 01 (Obj Group 12: Control Block), 28 01 (Variation 1)
dnp3_payload = bytes.fromhex("056405c00100000000c4050c012801000000")

packet_data = eth_hdr + ip_hdr + tcp_hdr + dnp3_payload
pkt_len = len(packet_data)

now = time.time()
sec = int(now)
usec = int((now - sec) * 1000000)

# Packet Header: ts_sec (4B), ts_usec (4B), incl_len (4B), orig_len (4B)
pcap_pkt_hdr = struct.pack('<IIII', sec, usec, pkt_len, pkt_len)

pcap_file = r'C:\Users\user\.gemini\antigravity-ide\scratch\github_repo\ot-security-lab\Phase12_Splunk_Observability\attacks\attack.pcap'

with open(pcap_file, 'wb') as f:
    f.write(pcap_global_hdr)
    f.write(pcap_pkt_hdr)
    f.write(packet_data)

print(f"[+] PCAP generated successfully: {pcap_file}")

# Hex Dump Format Output Simulation
print("\n[+] Hex Dump of DNP3 Direct Operate (Function Code 5) Packet:")
print("-" * 60)
hex_str = packet_data.hex()
for i in range(0, len(packet_data), 16):
    chunk = packet_data[i:i+16]
    hex_repr = ' '.join(f'{b:02x}' for b in chunk)
    ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
    print(f"0000{i:02x}  {hex_repr:<48}  |{ascii_repr}|")
print("-" * 60)
