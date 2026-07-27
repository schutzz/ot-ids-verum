---
title: "第8章：OT環境の高度化（BACnet自動門扉とRTSP監視カメラの統合）"
---

# 第8章：OT環境の高度化（BACnet自動門扉とRTSP監視カメラの統合）

---

## 1. はじめに

これまでの章では、Modbus/TCPを用いた単一の侵入検知センサーとHMI（Node-RED）の連携、そしてPurdueモデルに基づいたDMZネットワーク分離について学んできました。

しかし、実際の施設警備や工場インフラにおいては、単一のセンサーだけでなく「門扉の自動開閉制御」や「監視カメラ映像のライブストリーミング」といった多様な機器が統合運用されています。

本章では、本ラボのOT網（Level 0〜2）に以下の2つの主要インフラ要素を新規構築・追加し、**「本物さながらの総合施設警備システム」へ高度化・拡充**していきます。

1. **BACnetによる自動門扉システム**: ビル管理の国際標準プロトコルであるBACnetを用いて、物理ゲートの開閉システムを構築。
2. **RTSPによる監視カメラシステム**: 施設の映像監視網をFFmpegで生成し、RTSPストリームとしてメディアサーバー（MediaMTX）から配信。

![現状のNode-RED](https://static.zenn.studio/user-upload/f8cd05b8d553-20260722.png)

---

## 2. 導入する3大OTプロトコルの詳細解説

新たなインフラ要素の追加に伴い、本ラボで稼働する3つの主要産業プロトコル（Modbus/TCP, BACnet/IP, RTSP）の技術的仕様や特徴について深掘り解説します。

---

### ① Modbus/TCP (TCP 502)
* **概要**: 1979年にModicon社（現Schneider Electric）が開発した歴史のある産業用プロトコルです。これをEthernet/TCP上で利用できるようにしたのが Modbus/TCP です。
* **技術的特徴**: 
  * 7バイトの **MBAP (Modbus Application Protocol) ヘッダー** と、命令を示す **PDU (Protocol Data Unit)** で構成されます。
  * `0x01 (Read Coils)`, `0x04 (Read Input Registers)`, `0x05 (Write Single Coil)` といったシンプルなファンクションコード（FC）でメモリ空間を操作します。
  * **セキュリティ上の構造的課題**: 認証機構、暗号化、改ざん検知が一切存在しないため、パケットの捏造やコマンド注入が容易な構造となっています。

---

### ② BACnet / BACnet/IP (UDP 47808 / 0xBAC0)
* **概要**: ASHRAE（米国暖房冷凍エアコン学会）が制定し、ISO 16484-5 として標準化された**ビル自動化・ファシリティ管理専用の国際標準プロトコル**です。空調（HVAC）、照明、自動ドア、防犯ゲート等の管理に使用されます。
* **技術的特徴**:
  * モノや状態を「オブジェクト（`Binary Value`, `Analog Input` 等）」や「プロパティ」として扱うオブジェクト指向設計です。
  * ネットワーク上で自律的に機器を検索する `Who-Is` / `I-Am` などのブロードキャスト機構や、ASN.1ベースの構造を持ちます。
  * **セキュリティ上の構造的課題**: 従来のBACnet/IPには標準で認証概念がなく、UDP 47808 ポートに対して開閉コマンドを投げるだけで物理ゲートが動作する仕様となっています。

---

### ③ RTSP (Real Time Streaming Protocol / TCP・UDP 8554) & ONVIF
* **概要**: 監視カメラ（IPカメラ）やメディアサーバーとの間で、リアルタイムな映像ストリーミングの確立・制御を行うアプリケーション層プロトコルです。
* **技術的特徴**:
  * RTSP自体はセッション制御を行い、実際の映像フレームデータ（H.264/H.265等）は RTP (Real-time Transport Protocol) によって送信されます。
  * 今回のラボでは `MediaMTX` メディアサーバーがこのRTSPストリームを受け取り、Webブラウザで直接視聴可能な WebRTC/HLS 形式（ポート8889）へ変換しています。
  * **セキュリティ上の構造的課題**: 平文通信やデフォルト資格情報での運用が多く、ネットワーク通信の傍受やストリーム中継の差し替えに脆弱な側面を併せ持ちます。

---

## 3. BACnetゲートエミュレータの作成

Pythonの `bacpypes` ライブラリを使用して、門扉の「開/閉（Active/Inactive）」状態を保持するBACnet/IPデバイス（仮想ゲート）を作成します。

> **💡 なぜ今回はRustではなくPythonを採用したのか？**
> * **Modbus（Rust自作）**: 非常に原始的な構造（単なるメモリ空間の読み書き）であるため、バイナリ構造を意識する目的でRust標準ライブラリ（生ソケット）でゼロから構築しました。
> * **BACnet（Python/bacpypes）**: オブジェクト指向、デバイス発見（Who-Is/I-Am）、複雑なASN.1エンコードを持つ大容量プロトコルです。ゼロからの自作は非現実的であるため、OT業界のデファクト標準ライブラリである `bacpypes` を採用しました。

```python
# gate_server.py (一部抜粋)
from bacpypes.app import BIPSimpleApplication
from bacpypes.object import BinaryValueObject
from bacpypes.local.device import LocalDeviceObject

# デバイスオブジェクトの定義
this_device = LocalDeviceObject(objectName="AutomatedGate", objectIdentifier=599)
this_application = BIPSimpleApplication(this_device, "192.168.151.22/24")

# 門扉状態のオブジェクト (binaryValue:1)
gate_obj = BinaryValueObject(
    objectIdentifier=('binaryValue', 1),
    objectName='GateControl',
    presentValue='inactive' # 初期状態: 閉 (inactive)
)
this_application.add_object(gate_obj)
```

---

## 4. 監視カメラ（FFmpeg + MediaMTX）の構築

オープンソースの高性能メディアサーバー `bluenviron/mediamtx` をコンテナとして立て、そこへ向かって `ffmpeg` コンテナが「現在の時刻とSECURE AREAという文字」を焼き付けたダミーのテスト映像をリアルタイム配信し続けます。

```bash
# FFmpegによるダミー映像生成スクリプト
ffmpeg -re -f lavfi -i testsrc=size=1280x720:rate=15 \
       -vf "drawtext=text='%{localtime}':fontcolor=white:fontsize=36:x=100:y=100" \
       -f rtsp rtsp://mediamtx:8554/cam1
```

MediaMTXはこのRTSPストリームを受け取り、自動的にWebRTC/HLSに変換してブラウザ再生可能（ポート8889）にします。

---

## 5. ホストOSのポートプロキシ設定

ホストOS（Windows 11）の管理者PowerShellで追加設定を行います。

```powershell
netsh interface portproxy add v4tov4 listenport=8889 listenaddress=192.168.150.1 connectport=8889 connectaddress=127.0.0.1
```

SSHトンネルコマンドにも `-L 8889:...` を追加します。

```powershell
ssh -L 8880:192.168.150.1:1880 -L 8889:192.168.150.1:8889 Administrator@192.168.150.10
```

---

## 6. HMI（Node-RED）のダッシュボード改修

Node-REDに `node-red-contrib-bacnet` をインストールし、BACnetの「GateControl」オブジェクトを操作するスイッチを追加します。

レイアウト崩れを回避するため、「1つの巨大なグループの中にすべての要素を配置する」手法をとっています。カスタムの `ui_template`（HTML/Angular）を利用し、視認性の高い巨大なアイコンで門扉の開閉を可視化・操作可能にします。

![ダッシュボード全体](https://static.zenn.studio/user-upload/f486c0171fee-20260722.png)

---

## 7. センサーエミュレータの動的化とOT通信一覧

Modbusセンサーエミュレータの内部にバックグラウンドスレッドを追加し、以下のシミュレーションを組み込みました。

* **温度変動**: 3秒ごとに20.0℃〜30.0℃の間で疑似乱数変動
* **侵入検知**: 約5%の確率で一時的に「異常検知」点滅

![ダッシュボード状態変化](https://static.zenn.studio/user-upload/95e08cc4a370-20260722.png)

### 本ラボ環境で稼働中のプロトコル・機器一覧

| 送信元 (Source) | 宛先 (Destination) | プロトコル / ポート | 用途・通信内容 |
| :--- | :--- | :--- | :--- |
| **HMI (Node-RED)** (`192.168.151.20`) | **Modbus Sensor** (`192.168.151.21`) | Modbus/TCP (TCP 502) | 1秒間隔で侵入検知(Coil 0)と温度(Reg 1)をポーリング |
| **HMI (Node-RED)** (`192.168.151.20`) | **BACnet Gate** (`192.168.151.22`) | BACnet/IP (UDP 47808) | 門扉ステータスの定期監視(Read)および開閉操作(Write) |
| **Camera (FFmpeg)** (`192.168.151.24`) | **MediaMTX** (`192.168.151.23`) | RTSP (TCP 8554) | 監視カメラ映像のリアルタイムストリーミング配信 |

---

## 8. おわりに

本章では、単一センサーのみであった環境に対し、BACnetによる自動門扉制御システムおよび RTSP/MediaMTX による監視カメラ映像配信網を組み込み、**「高度な総合施設警備OTシステム」** を完成させました。

これで、Modbus / BACnet / RTSP という主要なOTプロトコルが混在するリアルなインフラ環境が整いました。

次回（第9章）は、完成したこの高度OTインフラに対し、MITRE ATT&CK for ICS マッピングに基づいた「門扉の不法開閉」「HMI表示の隠蔽」「監視映像の中間者インジェクション攻撃」といった本格的な Red Teaming 演習を実践していきます。
