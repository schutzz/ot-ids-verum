---
title: "第5章：HMI監視基盤構築とメモリ汚染攻撃・自作IDS"
---

# 第5章：HMI監視基盤構築とメモリ汚染攻撃・自作IDS

---

## 1. はじめに

前回は、Rustを用いて「状態（メモリ）を保持し、書き換え攻撃を受け付ける」ステートフルな Modbus/TCP センサーエミュレータを自作しました。これにより、OT特有のサイバー攻撃（メモリ汚染）をシミュレーションする準備が整いました。

今回は、IT/OT境界に位置する HMI（Node-RED）からセンサーの値を定期的に取得（ポーリング）する監視フローを構築し、**「正常な状態での通信（ベースライン）」** のネットワークキャプチャ（pcap）を取得します。

ここで取得する正常系のpcapは、後続の「メモリ汚染攻撃」発生時に、異常をバイナリレベルで見つけ出すための重要な基準（ベースライン）となります。

---

## 2. Node-REDへのModbus/UIモジュール導入

HMIコンテナ（Node-RED）からエミュレータへアクセスするため、Modbus通信用のノードを追加します。今回は、直感的にポーリング処理を構築できるデファクトスタンダード `node-red-contrib-modbus` を使用します。

また、取得したセンサーの値をHMIとして可視化するため、最新のダッシュボードUI構築モジュールである `@flowfuse/node-red-dashboard` (Dashboard 2.0) も併せて導入します。

1. Node-REDの画面（`http://localhost:1880`）を開く。
2. 画面右上のメニュー (≡) から「パレットの管理」を開く。
3. 「ノードを追加」タブで以下の2つを検索し、インストールする。
   * `node-red-contrib-modbus`
   * `@flowfuse/node-red-dashboard`

---

## 3. センサー監視（ポーリング）フローの構築

インストールしたノードを使い、エミュレータ（`192.168.100.11:502`）に対して1秒に1回、センサー状態を問い合わせるフローを作成します。

### 監視対象1：侵入検知センサー（接点・Coil）
* **Node**: `Modbus-Read`
* **FC**: `FC 1: Read Coil Status`
* **Address**: `0` (Quantity: 1)
* **UI表示**: Dashboard 2.0の `ui text` ノードに接続し、ON/OFF状態を表示。

### 監視対象2：温度センサー（アナログ・Register）
* **Node**: `Modbus-Read`
* **FC**: `FC 4: Read Input Registers`
* **Address**: `1` (Quantity: 1)
* **UI表示**: Dashboard 2.0の `ui gauge` ノードに接続し、数値をゲージメーターで表示。

> **💡 TIPS: ModbusノードとDashboardノード間のデータ型変換**
> Modbus-Readノードから出力されるデータは、要求したQuantityが1であっても、仕様により常に配列（Array）形式や、生バッファ（ArrayBuffer）を含んだ複雑なオブジェクトとして出力されます。
> 一方で、DashboardのUIノード（textやgauge等）は単一の数値や文字列を期待します。そのため、Modbusノードの出力を直接UIノードに繋ぐとデータ型のミスマッチが起き、ダッシュボード上の表示が崩れる原因となります。

![](https://static.zenn.studio/user-upload/608c59244e69-20260720.png)

![](https://static.zenn.studio/user-upload/bd5c9b337c6c-20260720.png)

![](https://static.zenn.studio/user-upload/1c04e0be3069-20260720.png)

![](https://static.zenn.studio/user-upload/0f014596bf51-20260720.png)

#### 確実な解決策（Functionノードの活用）
両ノードの間にオレンジ色の `function` ノードを配置し、JavaScriptで確実なデータ抽出と型変換を行います。

侵入検知用のコード:
```javascript
let val = msg.payload.data ? msg.payload.data[0] : msg.payload[0];
msg.payload = val ? "異常あり (ON)" : "正常 (OFF)";
return msg;
```

温度計用のコード:
```javascript
let val = msg.payload.data ? msg.payload.data[0] : msg.payload[0];
msg.payload = Number(val);
return msg;
```

![](https://static.zenn.studio/user-upload/d8b66e08a30a-20260721.png)

![](https://static.zenn.studio/user-upload/59b774803f8b-20260721.png)

設定された温度と異常ありの表示が出るようになりました。

---

### フローの一括インポート（構築を時短したい方向け）

上記の設定を手作業で行うのが面倒な場合は、以下のJSONをコピーし、Node-RED右上のメニューから「インポート」に貼り付けるだけで完了します。

```json
[
    {
        "id": "f6f2187d.f17ca8",
        "type": "tab",
        "label": "Flow 1",
        "disabled": false,
        "info": ""
    },
    {
        "id": "859346e05fe34fbc",
        "type": "modbus-read",
        "z": "f6f2187d.f17ca8",
        "name": "侵入検知 (Coil 0)",
        "topic": "",
        "showStatusType": "output",
        "logIOActivities": false,
        "startAddress": "0",
        "unitid": "1",
        "dataType": "Coil",
        "adrsub": "",
        "quantity": "1",
        "rate": "1",
        "rateUnit": "s",
        "delayOnStart": false,
        "startDelayTime": "",
        "server": "b85ee7f3ddae90fa",
        "useIOFile": false,
        "ioFile": "",
        "useIOForPayload": false,
        "emptyMsgOnFail": false,
        "keepMsgProperties": false,
        "x": 170,
        "y": 40,
        "wires": [
            [
                "6fa68c078ae4bb49"
            ],
            []
        ]
    },
    {
        "id": "6fa68c078ae4bb49",
        "type": "function",
        "z": "f6f2187d.f17ca8",
        "name": "ON/OFF文字変換",
        "func": "let val = msg.payload.data ? msg.payload.data[0] : msg.payload[0];\nmsg.payload = val ? \"異常あり (ON)\" : \"正常 (OFF)\";\nreturn msg;",
        "outputs": 1,
        "timeout": 0,
        "noerr": 0,
        "initialize": "",
        "finalize": "",
        "libs": [],
        "x": 370,
        "y": 40,
        "wires": [
            [
                "de0b830b6bf5324c"
            ]
        ]
    },
    {
        "id": "76ed1c238b0e7747",
        "type": "modbus-read",
        "z": "f6f2187d.f17ca8",
        "name": "温度センサー (Register 1)",
        "topic": "",
        "showStatusType": "output",
        "logIOActivities": false,
        "startAddress": "1",
        "unitid": "1",
        "dataType": "InputRegister",
        "adrsub": "",
        "quantity": "1",
        "rate": "1",
        "rateUnit": "s",
        "delayOnStart": false,
        "startDelayTime": "",
        "server": "b85ee7f3ddae90fa",
        "useIOFile": false,
        "ioFile": "",
        "useIOForPayload": false,
        "emptyMsgOnFail": false,
        "keepMsgProperties": false,
        "x": 160,
        "y": 100,
        "wires": [
            [
                "f9b7c84521bdc31a"
            ],
            []
        ]
    },
    {
        "id": "f9b7c84521bdc31a",
        "type": "function",
        "z": "f6f2187d.f17ca8",
        "name": "数値抽出",
        "func": "let val = msg.payload.data ? msg.payload.data[0] : msg.payload[0];\nmsg.payload = Number(val);\nreturn msg;",
        "outputs": 1,
        "timeout": 0,
        "noerr": 0,
        "initialize": "",
        "finalize": "",
        "libs": [],
        "x": 370,
        "y": 100,
        "wires": [
            [
                "3d7a12c6db32018c"
            ]
        ]
    },
    {
        "id": "b85ee7f3ddae90fa",
        "type": "modbus-client",
        "name": "Sensor Emulator",
        "clienttype": "tcp",
        "tcpHost": "192.168.100.11",
        "tcpPort": 502,
        "unit_id": 1
    }
]
```

デプロイ後、`http://localhost:1880/dashboard` にアクセスし、表示されていれば監視基盤の完成です。

---

## 4. 正常系パケット（ベースライン）のキャプチャ

HMIとセンサー間で「平常時の通信」が定常的に流れるようになりました。
後続のフォレンジック（パケット解析）のため、この正常なトラフィックを `tcpdump` を使ってキャプチャし、pcapファイルとして切り出します。

### キャプチャ時の注意点（権限エラーと解決策）

```bash
fol@DESKTOP-OJBFPIG:~$ docker exec hmi-nodered tcpdump -i any host 192.168.100.11 and tcp port 502 -w /tmp/normal_traffic.pcap
tcpdump: any: You don't have permission to perform this capture on that device
(Attempt to create packet socket failed - CAP_NET_RAW may be required)
```

Root権限（`-u root`）を指定して正しく実行します。

```bash
fol@DESKTOP-OJBFPIG:~$ docker exec -u root hmi-nodered tcpdump -i any host 192.168.100.11 and tcp port 502 -w /tmp/normal_traffic.pcap
tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2), snapshot length 262144 bytes
```

10秒ほど待機し、パケットを蓄積させたら `Ctrl+C` で停止させ、生成されたpcapファイルをホスト側にコピーします。

```bash
# 生成されたpcapファイルをカレントディレクトリに取り出す
fol@DESKTOP-OJBFPIG:~$ docker cp hmi-nodered:/tmp/normal_traffic.pcap ./
```

---

## 5. 正常系通信（ベースライン）の構造確認とWiresharkの活用

取得した `normal_traffic.pcap` を Wireshark で開いて観察します。

![](https://static.zenn.studio/user-upload/9616fc51d77d-20260721.png)

---

### 💡 補足：OTセキュリティ解析における Wireshark と Lua スクリプト拡張の決定的な重要性

OT（産業制御システム）領域におけるネットワークアナライザ **Wireshark** の役割と、実務における高度なカスタマイズ手法について触れておきます。

#### ① OT解析における Wireshark の役割
Wireshark は、L2（イーサネット）からL7（アプリケーション層）までの全パケットをバイナリレベルで可視化する業界標準のツールです。Modbus/TCP、BACnet/IP、OPC UA、IEC 60870-5-104 といった主要なOTプロトコルの解剖アナライザ（Dissector）が標準で組み込まれています。

#### ② OT現場特有の課題：「ベンダー独自・未定義プロトコル」の壁
実際の工場、発電所、ビル管理施設では、大手制御機器メーカー（Siemens, 三菱電機, オムロン, 横河電機等）の独自プロトコルや、仕様が非公開のカスタムバイナリ通信が数多く流通しています。
標準の Wireshark でこれらを開いても、`TCP payload` や `Unknown Data` と表示され、パケットの中身（制御命令やパラメータ）をデコードできません。

#### ③ Lua スクリプトによるカスタム Dissector（アナライザ）自作の強力なメリット
Wireshark は、軽量スクリプト言語 **Lua（ルア）** によるアナライザ拡張を標準サポートしています。
C言語で解剖プラグインを再コンパイルすることなく、わずか数10行の Lua スクリプトを記述するだけで、独自プロトコルのバイナリ構造（ヘッダー、コマンドコード、チェックサム等）をパースし、Wiresharkのツリー画面上に美しく可視化・フィルタリングできるようになります。

```lua
-- Wireshark用 カスタムOTプロトコル Dissector の記述例 (Lua)
local my_proto = Proto("CustomOT", "Custom OT Protocol")

local f_cmd  = ProtoField.uint8("customot.cmd", "Command Code", base.HEX)
local f_data = ProtoField.uint16("customot.data", "Sensor Value", base.DEC)
my_proto.fields = { f_cmd, f_data }

function my_proto.dissector(buffer, pinfo, tree)
    pinfo.cols.protocol = "CustomOT"
    local subtree = tree:add(my_proto, buffer(), "Custom OT Protocol Data")
    subtree:add(f_cmd, buffer(0, 1))
    subtree:add(f_data, buffer(1, 2))
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(9999, my_proto) -- TCPポート9999にバインド
```

> **🛡️ セキュリティアナリストへの意識付け**
> 未知の制御プロトコルや独自機器が入り混じるOT環境において、**「リバースエンジニアリングでパケット構造を解読し、Wireshark用Lua Dissectorを自作できるスキル」** は、未知のマルウェア解析やOTセキュリティ監視（SOC/IR）において最強の武器となります。

---

### パケットから読み取れる3つの「正常なベースライン」

#### ① トランザクションIDの連続性（最重要）
Wiresharkの `Info` 列に注目すると、HMIからの Transaction Identifier が `253` → `254` → `255` → `0` → `1`... と綺麗にインクリメント推移しています。
正常なHMIがポーリングを行っている限り、このIDは必ず連続します。外部から攻撃者が不正パケットを割り込ませた場合、この連番の規則性が崩れるため、強力なアノマリー（異常）検知の指標となります。

#### ② Function Codeのパターン
平常時であるため、Modbus/TCP のパケットは以下の2つの読み取り命令（Read）とその応答のみで構成されます。
* `FC 0x01` (Read Coils)： 侵入検知センサーの読み取り
* `FC 0x04` (Read Input Registers)： 温度センサーの読み取り
データを書き換えるコマンド（`FC 0x05` や `FC 0x06` 等）は一切存在しません。

#### ③ パケットのバイナリ構造（MBAPヘッダ）とIPの整合性
パケット詳細ペインで生のバイト列を確認します。

![](https://static.zenn.studio/user-upload/3d3b0041b8e0-20260721.png)

```
[00 01] [00 00] [00 06] [01] [01] [00 00] [00 01]
   |       |       |      |    |     |       |
   |       |       |      |    |     |       +-- Quantity (1個)
   |       |       |      |    |     +-- Address (0x0000)
   |       |       |      |    +-- Function Code (0x01)
   |       |       +-- Unit ID (0x01)
   |       +-- Length (以降6バイト)
   +-- Protocol ID (Modbus=0x0000)
   +-- Transaction ID (0x0001)
```

送信元は必ず HMI（`192.168.100.10`）であり、宛先はセンサー（`192.168.100.11`）のみで構成されています。
この**「決まった通信パターンが、決まった送信元からのみ発生する」**状態が、OTネットワークにおける正常なベースラインです。

---

## 6. おわりに

今回は、Node-REDを用いたModbusセンサーの定常監視フローを構築し、Wiresharkを用いた正常パケット（ベースライン）の取得と構造解析を行いました。

次回は、「センサー隠蔽（メモリ汚染）攻撃の実行とバイナリ解析」に突入します。IT網を乗っ取った攻撃者の視点で不正な `FC 0x05` パケットを注入し、今回取得した正常ベースラインとのバイナリレベルでの決定的な違いをあぶり出していきます。
