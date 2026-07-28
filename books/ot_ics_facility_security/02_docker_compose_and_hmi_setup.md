---
title: "第2章：Docker Compose環境構築とHMI(Node-RED)起動"
---

# 第2章：Docker Compose環境構築とHMI(Node-RED)起動

---


前回は、OT/ICSの基本概念とPurdueモデルに基づいたネットワーク設計（全体像）について整理しました。

今回は、実際に `docker-compose.yml` を書いて「L2ネットワーク分離基盤の構築」と、統合監視盤（HMI）となる 「Node-REDコンテナの起動」（Phase 1）を進めていきます。

 1. フォルダ構成と設計図の作成

まずは今回のラボ用に、以下のようなディレクトリ階層を作成します。

```
/home/fol/ot-lab/
├── docs/
│   └── system_diagram.puml
└── docker-compose.yml
```

`system_diagram.puml` は前回作成したネットワーク構成図ですね。

この同じディレクトリに、今回の要となる `docker-compose.yml` を作成していきます。

`docker-compose.yml` は、複数のコンテナと、それらが繋がるネットワーク環境を定義するいわば「設計図」です。

まずはこの設計図の骨組み（ネットワーク）と、最初の住人（Node-RED）を定義するところから始めます。

 2. docker-compose.yml の記述

作成した `docker-compose.yml` に、以下の内容を記述します。

```
# ==========================================
# 1. 論理ネットワークの定義 (L2分離基盤)
# ==========================================
networks:
  ot_net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.100.0/24  # OT_Network: 物理機器シミュレータ用

  it_net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.200.0/24  # IT_Network: 攻撃者端末・ログ収集基盤用

# ==========================================
# 2. サービス(コンテナ)の定義
# ==========================================
services:
  # 統合監視盤 (HMI) - Node-RED
  hmi-nodered:
    image: nodered/node-red:latest
    container_name: hmi-nodered
    ports:
      - "1880:1880" # ホストの1880番ポートをコンテナの1880番に直結
    networks:
      ot_net:
        ipv4_address: 192.168.100.10 # OT網内でIPアドレスを固定
    restart: unless-stopped
```

## 3. docker-compose.yml の文法ルールと詳細技術解説

今回作成した `docker-compose.yml` は、OT分離環境の根幹をなす「ネットワーク設計図」です。初心者がつまずきやすいYAMLの文法ルールと、各パラメータの技術的背景を行ごとに詳しく解説します。

---

### ① YAMLフォーマットの必須基本ルール

1. **インデントは半角スペース2個**: タブ文字（Tab）の使用は禁止されています。スペースの数がずれるとパースエラーとなります。
2. **キーと値の間のスペース**: `key: value` のように、コロン（`:`）の後には必ず**半角スペース**が必要です。
3. **文字列とポート指定のクォーテーション**: `"1880:1880"` のようにポート番号は文字列（ダブルクォート囲み）として記述します。YAMLでは `1880:1880` を60進数（時刻）として自動解釈してしまう仕様（YAML 1.1仕様）があるため、明示的に文字列化するのが安全な記述法です。

---

### ② `networks` ブロック（L2ネットワーク分離の記述）

```yaml
networks:
  ot_net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.100.0/24  # OT_Network
  it_net:
    driver: bridge
    ipam:
      config:
        - subnet: 192.168.200.0/24  # IT_Network
```

* **`networks:`**: このCompose環境内で利用する仮想ネットワーク領域を定義します。
* **`ot_net` / `it_net`**: Docker内で識別されるネットワークの論理名称です。
* **`driver: bridge`**: 
  * DockerがLinuxカーネル内に仮想的なL2スイッチ（ネットワークブリッジ `br-xxxx`）を生成します。
  * `ot_net` と `it_net` は互いに独立した別個のL2スイッチとして動作するため、同一物理ホスト上であってもブロードキャストドメインが完全に隔離されます。
* **`ipam` (IP Address Management)**:
  * IPアドレスの割り当てルール（管理プロトコル）を定義します。
* **`config` / `subnet: 192.168.100.0/24`**:
  * CIDR表記（`/24` = サブネットマスク `255.255.255.0`）でIPアドレス空間を指定します。
  * `192.168.100.1` ～ `192.168.100.254`（全254個）のアドレスが割り当て可能空間となります（Dockerエンジンにより `192.168.100.1` はデフォルトゲートウェイとして自動保持されます）。

---

### ③ `services` ブロック（コンテナの配置と固定IP指定）

```yaml
services:
  hmi-nodered:
    image: nodered/node-red:latest
    container_name: hmi-nodered
    ports:
      - "1880:1880"
    networks:
      ot_net:
        ipv4_address: 192.168.100.10
    restart: unless-stopped
```

* **`services:`**: 起動させるコンテナ群の共通定義ブロックです。
* **`hmi-nodered:`**: Compose内でこのコンテナを識別するサービス名です（内部DNSで名前解決に使われます）。
* **`image: nodered/node-red:latest`**:
  * 公式Docker Hubから取得するビルド済みイメージです。`latest` タグにより最新のNode-RED環境を取得します。
* **`container_name: hmi-nodered`**:
  * コンテナの名前を明示的に固定します。これを省略すると `プロジェクト名-サービス名-1`（例: `ot-lab-hmi-nodered-1`）という自動生成名になってしまうため、スクリプト等からの操作性を考慮して名前を固定化します。
* **`ports: - "1880:1880"`**:
  * `[ホストOSのポート]:[コンテナ内部のポート]` の順でポート転送（NAT/Port Forwarding）を設定します。
  * ホストPCのブラウザから `http://localhost:1880` へアクセスすると、Dockerのiptablesルーティングを経由してコンテナ内のNode-RED（1880番）に転送されます。
* **`networks` / `ipv4_address: 192.168.100.10`**:
  * コンテナを所属させるネットワーク（`ot_net`）を指定します。
  * `ipv4_address` によって、OT網内でのコンテナIPアドレスを `192.168.100.10` に**静的固定（Static IP）**します。実際の産業制御環境（OT）では、PLCやHMIのIPアドレスが動的DHCPで変わってしまうと通信不能になるため、全機器でIPアドレスの明示的固定が必須となります。
* **`restart: unless-stopped`**:
  * コンテナの自動再起動ポリシーです。手動で停止させない限り、Dockerサービス起動時やエラー終了時にコンテナを自動復旧・再起動させます。

---

## 4. コンテナの起動と接続確認

設定ファイルが書けたら、ターミナルで以下のコマンドを実行してコンテナを起動します。

```
docker compose up -d
```

無事にコンテナが立ち上がったら、ホスト側のブラウザから `http://localhost:1880` にアクセスしてみます。

![](https://static.zenn.studio/user-upload/4a2c05321fb4-20260720.png)

![](https://static.zenn.studio/user-upload/c3129ff7950c-20260720.png)

Node-REDのUI画面が問題なく表示されました。

---

## 5. Node-REDの基礎知識とOT環境における活用の広がり

今回統合監視盤（HMI）の基盤として採用した **Node-RED（ノード・レッド）** について、その出自や元々の使い方、そして近年のOT/ICS（制御システム・工場・ビル管理）環境における採用の広がりについて詳しく解説します。

### ① Node-REDの歴史と出自（IoTプロトタイピングツールとしての誕生）

* **誕生の経緯**: 2013年、IBMのEmerging Technology研究所に所属していた Nick O'Leary と Dave Conway-Jones によって開発され、後にオープンソース化（現在は OpenJS Foundation プロジェクト）されました。
* **技術的特徴**: Node.js（JavaScriptランタイム）上で動作し、画面上でノード（機能ブロック）をドラッグ＆ドロップしてワイヤー（線）で繋ぐ**フローベース・プログラミング（Flow-based Programming）**を採用しています。
* **本来の目的**: API、ハードウェアデバイス（Raspberry Pi、Arduinoなど）、各種Webサービスを専門的なコードを書かずに素早く繋ぎ合わせる「IoTプロトタイピング・データ連携ツール」として広く普及しました。

### ② 近年のOT（制御システム・スマートファクトリー）領域における活用の広がり

元々はWebサービスやDIY・IoT向けのツールであったNode-REDですが、近年では「IT/OT融合の鍵を握るエッジミドルウェア」として、現場の産業制御環境（OT）において極めて重要な役割を果たしています。

1. **IT/OTプロトコルの変換ゲートウェイ（プロトコルブリッジ）**:
   - 現場のPLCやセンサーが話す産業プロトコル（Modbus/TCP, OPC UA, BACnet, Siemens S7等）と、IT層で使われる現代的なプロトコル（MQTT, HTTP REST API, JSON, WebSocket）を相互に繋ぐ「翻訳機」として標準的に活用されています。
2. **産業用エッジコンピュータ（IPC）への標準採用**:
   - シーメンス（Siemens SIMATIC IOT2000シリーズ）、研華（Advantech WISE gateway）、フェニックス・コンタクト（PLCnext）など、世界的な産業機器メーカーが提供するエッジゲートウェイやスマートPLCにNode-REDが標準インストール（または公式Dockerイメージ化）されて出荷されるケースが急増しています。
3. **簡易HMI（Human Machine Interface）およびダッシュボードの高速構築**:
   - `node-red-dashboard` 等の拡張ノードを利用することで、高価な商用SCADA/HMIソフトウェア（数百万〜数千万円規模）を購入・ライセンス契約しなくても、ブラウザベースで直感的な操作パネルやメーター、リアルタイムグラフ画面を数時間で作成可能です。
4. **セキュリティ検証・OTプロトタイプ評価環境としてのメリット**:
   - 本ラボのように、OT通信（Modbus等）を発生・受信・可視化するエミュレーション基盤として極めて優秀であり、パケット改ざん時のHMI画面の挙動変化（表示偽装やアラート発報）を即座に視覚化・検証できます。

OT/ICSセキュリティを学ぶには必要と判断し選定しました。
非常に応用力の高い面白いおもちゃとも言えます。

---

## 6. おわりに（次回予告）

今回は、Docker Composeを用いてOT領域のネットワーク分離基盤を構築し、HMIとなるNode-REDを固定IPで無事に起動させました。

次回（第3回）は、Rustを用いてModbus/TCPプロトコルを話す仮想センサー機器（エミュレータ）を開発していきます。

Node-REDからModbus通信を発生させ、実際にデータのやり取りやパケットの挙動を確認していく予定です。
