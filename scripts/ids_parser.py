import sys
try:
    from scapy.all import rdpcap, TCP, IP, Raw
except ImportError:
    print("[!] scapy is not installed. Please run: pip install scapy")
    sys.exit(1)

# --- ANSI Escape Codes ---
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
BG_RED = "\033[41m"
WHITE = "\033[97m"

def print_banner():
    banner = f"""{CYAN}{BOLD}
    ================================================
      [ OT-IDS ] Modbus/TCP Anomaly Detector v1.0
    ================================================
    Analyzing pcap for memory contamination attacks...
    {RESET}"""
    print(banner)

def alert_attack(pkt, tx_id, fc, src_ip, dst_ip):
    alert_art = f"""
{BG_RED}{WHITE}{BOLD} 
 !!! CRITICAL SECURITY ALERT !!! 
 !!! MEMORY OVERRIDE DETECTED !!! 
{RESET}
{RED}{BOLD}
      /\\
     /  \\     [!] UNAUTHORIZED WRITE COMMAND (FC 0x05)
    / !! \\    [!] SOURCE IP : {src_ip} (Spoofed/Attacker)
   /______\\   [!] TARGET IP : {dst_ip}
              [!] TRANS ID  : {tx_id} (Anomaly Detected)
{RESET}
    """
    print(alert_art)

def main():
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    print_banner()
    print(f"{YELLOW}[*] Loading {pcap_file}...{RESET}\n")

    try:
        packets = rdpcap(pcap_file)
    except Exception as e:
        print(f"{RED}[!] Error reading pcap: {e}{RESET}")
        return

    hmi_ip = "192.168.100.10"
    normal_fcs = [0x01, 0x04]
    
    count = 0
    attack_detected = False

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            # Check if it's Modbus (Port 502)
            if pkt[TCP].dport == 502 or pkt[TCP].sport == 502:
                payload = pkt[Raw].load
                
                # MBAP Header is 7 bytes
                if len(payload) >= 8:
                    # Parse Transaction ID (2 bytes) and Function Code (offset 7)
                    tx_id = (payload[0] << 8) | payload[1]
                    fc = payload[7]
                    
                    src_ip = pkt[IP].src
                    dst_ip = pkt[IP].dst
                    
                    # Ignore response packets from sensor
                    if src_ip == "192.168.100.11":
                        continue
                        
                    count += 1
                    
                    # 正常系通信の表示（短く）
                    if fc in normal_fcs and src_ip == hmi_ip:
                        print(f"{GREEN}[OK]{RESET} {src_ip} -> {dst_ip} | Trans: {tx_id:04d} | FC: 0x{fc:02X}")
                    
                    # アノマリー（異常）検知: FC0x05 または 未知のIP
                    if fc == 0x05:
                        attack_detected = True
                        alert_attack(pkt, tx_id, fc, src_ip, dst_ip)
                        print(f"{CYAN}[HEX DUMP]{RESET} {payload.hex(' ')}\n")

    print(f"--- Analysis Complete: {count} Modbus requests analyzed ---")
    if not attack_detected:
        print(f"{GREEN}No memory override attacks detected in this pcap.{RESET}")

if __name__ == '__main__':
    main()
