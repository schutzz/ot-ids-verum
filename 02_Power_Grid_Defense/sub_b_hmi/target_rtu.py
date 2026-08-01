import socket
import os

def main():
    listen_ip = os.environ.get("LISTEN_IP", "0.0.0.0")
    listen_port = int(os.environ.get("LISTEN_PORT", "20000"))

    # DNP3標準のTCPサーバーとしてバインド
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind((listen_ip, listen_port))
    server_sock.listen(5)

    print(f"[RTU-Outstation] Mock DNP3 RTU Server listening on TCP {listen_ip}:{listen_port}...", flush=True)

    while True:
        client_sock, addr = server_sock.accept()
        try:
            # TCPストリームからの受信
            data = client_sock.recv(1024)
            # マジックバイトの確認と、オフセット12のFCを安全に読み取るためのレングスチェック
            if data and len(data) >= 13 and data[0] == 0x05 and data[1] == 0x64:
                # 規格準拠に合わせて、オフセット12からFunction Codeを抽出
                function_code = data[12]
                print(f"[RTU-Outstation] Received IEEE 1815 DNP3 Packet from {addr[0]}:{addr[1]} | FC=0x{function_code:02x} | Length={len(data)} bytes", flush=True)
                if function_code == 0x05:
                    print(f"[RTU-Outstation] ⚡ Direct Operate Executed: Breaker Opened!", flush=True)
        except Exception as e:
            print(f"[RTU-Outstation] Error processing packet: {e}", flush=True)
        finally:
            client_sock.close()

if __name__ == "__main__":
    main()