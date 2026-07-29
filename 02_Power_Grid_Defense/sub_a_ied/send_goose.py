import socket
import time
import sys

GOOSE_ETHERTYPE = b'\x88\xb8'
DEST_MAC = b'\x01\x0c\xcd\x01\x00\x01'
SRC_MAC = b'\x02\x42\x0a\x00\x14\x0a'

GOOSE_PAYLOAD = (
    b'\x61\x2c'
    b'\x80\x09\x4b\x79\x69\x76\x5f\x47\x72\x69\x64'
    b'\x81\x02\x03\xe8'
    b'\x82\x09\x49\x45\x44\x5f\x53\x75\x62\x5f\x41'
    b'\x83\x02\x01\x8e'
    b'\x84\x01\x01'
    b'\x85\x01\x00'
)

def run_sender():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind(("eth0", 0))
        print("[+] IEC 61850 GOOSE L2 Multicast Publisher started on eth0...")
        count = 0
        while True:
            frame = DEST_MAC + SRC_MAC + GOOSE_ETHERTYPE + GOOSE_PAYLOAD
            s.send(frame)
            count += 1
            if count % 5 == 0:
                print(f"[GOOSE] Broadcasted L2 Multicast Frame #{count} (EtherType 0x88B8)")
            time.sleep(2)
    except Exception as e:
        print(f"[!] Error in GOOSE sender: {e}")
        time.sleep(5)

if __name__ == "__main__":
    run_sender()
