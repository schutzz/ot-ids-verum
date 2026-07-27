---
title: "第11章：Splunk Observabilityを活用したOT/ITインフラの統合監視実践"
---

# 第11章：Splunk Observabilityを活用したOT/ITインフラの統合監視実践

---

> **💡 全ソースコード公開**
> 本ラボ環境を構成する `docker-compose.yml`、自作のOT-IDSスクリプト、Node-REDのフロー設定ファイル（JSON）など、すべてのコードはGitHubにて公開しています。
> [GitHubリポジトリはこちら](https://github.com/schutzz/ot-security-lab)

---

## 1. 概要

本章では、帯域制限と可用性が極端に厳しいOT/ICS（制御システム）閉域網に対し、**OpenTelemetry Collector（エッジ計装） × Splunk Observability Cloud（SaaS）** を用いた次世代インシデント監視基盤を構築し、以下の成果を実証します。

### 境界での帯域削減とSaaS監視の両立
DMZ（Purdue Level 3.5）に関所として配置したOTel Collectorでパケット解析と不要ログの破棄・Log-to-Metric変換を実施。OT網の極小帯域を保護しつつ、Splunk Observability Cloudによるリアルタイムな可観測性を実現しました。

### 重厚なオンプレSIEMからの脱却とHMI操作追跡
従来のホスト型防御やリソースを消費するオンプレSIEMを脱却し、非HTTPプロトコル（Modbus等）の相関分析エッジ処理に特化。Node-REDのHMI操作履歴（Audit Log）と現場の物理事象をTrace IDで強力に紐付けることで、L2攻撃や不正操作の死角を決定論的に検知可能にしました。

### 超低負荷アーキテクチャの実証
このエンタープライズ級の監視アーキテクチャは、ローエンド環境（第11世代 Core i7, メモリ32GBの一般的なPC）1台のラボ環境で、システムリソースを枯渇させることなく軽快に動作します。エッジで負荷を削ぎ落とし、重い処理をSaaSに逃がす構成によりエッジ側のリソース消費を極小化しました。

![](https://static.zenn.studio/user-upload/a32fb217cee7-20260723.png)

---

## 2. 【課題編】これまでの検証で直面した「従来アプローチ」の限界

これまでの第1章〜第10章を通じて、自作のOT/ICSラボ環境に「境界防御（FW）」や「従来型のネットワーク監視（ホスト型IDS/PCAP解析）」を組み込んで検証を重ねてきました。しかし、Red Teaming演習や内部ネットワークでの攻撃検証を経た結果、以下の3つの致命的な課題に直面しました。

| フェーズ | 実施した検証 | 突きつけられた現実（課題と限界） |
| :--- | :--- | :--- |
| **Phase 5/9** | 境界防御・自作IDSによる監視 | Modbus等非HTTPのコンテキスト欠如およびHMI操作ログとの分断により、正規コマンドを悪用した攻撃を追跡不能 |
| **Phase 7** | Modbus / BACnet / RTSPの混在 | HMI（Node-RED）操作とマルチプロトコル間の横断的な相関分析ができず、事象の点と点が繋がらない |
| **Phase 4/9** | PCAP全量取得とNSMの構築 | 常時運用した場合、ローエンドなエッジPCではストレージ・リソース枯渇のリスクが極めて高い |

これら第1章〜第10章の実験・検証から得られた結論として、**エッジ側の極限まで限られたリソースで継続的に運用するには、パケットをただ記録するのではなく、「HMI操作ログから物理プロトコルまでを統一フォーマットで集約し、DMZの関所で軽量なメトリクスやトレース（文脈）に変換して、重い相関分析をSaaSに委ねる」というアプローチへの転換** が不可欠となります。

---

## 3. 【アーキテクチャ選定編】バックエンド選定の根拠

### ① Splunk Observability Cloud 採用の技術的根拠

| 項目 | Splunk Enterprise (従来型オンプレ) | Splunk Observability Cloud (本案SaaS) |
| :--- | :--- | :--- |
| **アーキテクチャ** | オンプレミス / IaaS (管理・運用負荷大) | SaaS (フルマネージド) |
| **スケーリング** | インフラ増強が必要 (物理コスト大) | 自動スケーリング (即応性高) |
| **分析手法** | SPLによる検索クエリベース | SignalFlowによるリアルタイム計算 |
| **APM / 相関分析** | 設定・構築が複雑 | OTelネイティブ対応 (標準装備) |
| **OT適性** | ログ保管中心 (高レイテンシ) | リアルタイム可観測性 (低レイテンシ) |

---

### ② OTel Collector 採用の技術的根拠

1. **ホスト数制約の突破とエンドポイント集約 (Resource Masking)**
   Purdue Level 3.5にGatewayモードで配置することで、配下の全OTノード（PLC, IDS, Node-RED等）を秘匿し、SaaS側から「1つのデータソース」として認識させることで効率的な管理を実現します。
2. **エッジ側でのLog-to-Metric変換による帯域保護 (Edge Computing)**
   DMZの時点で生ログをメトリクスへ変換し、数バイトの時系列データのみをSaaSへ送信することで、帯域の狭いOT網のアップリンクを保護します。
3. **DMZにおけるプロトコルブレイクとアウトバウンド制御 (Boundary Defense)**
   OTノードとSaaSの直接通信を排除。OTel Collectorのみを外部接続ポイントとすることで、FWのエグレス（送信）ルールを極小化し、堅牢な境界防御を確立します。
4. **決定論的な相関分析のための統合ハブ機能 (Trace Context Engine)**
   Node-RED上のHMI操作履歴（Root Span）や現場パケットから生成された `trace_id` を受け取り、W3C Trace Contextに準拠したフォーマットへ整形。物理事象（Modbus等）と論理事象（HMI操作）を単一のトレースツリーに統合します。

---

### ③ 検証環境の詳細ネットワーク構成と設定

認証情報はセキュリティの観点から設定ファイル（YAML）に直接書き込まず、`.env` ファイルに分離してコンテナ起動時に環境変数として渡します。

```bash
# .env ファイルの例
SPLUNK_REALM=jp0
SPLUNK_ACCESS_TOKEN=05bdlF4LgTAEMRa2bNB1BQ...
```

`docker-compose.yml` にて `otel/opentelemetry-collector-contrib` イメージを展開します。

```yaml
otel-collector:
    image: otel/opentelemetry-collector-contrib:latest
    container_name: otel-collector
    user: "0:0"
    command: ["--config=/etc/otel-collector-config.yaml"]
    env_file:
      - .env
    volumes:
      - ./otel-collector-config.yaml:/etc/otel-collector-config.yaml:ro
      - /var/lib/docker/containers:/var/lib/docker/containers:ro
      - /var/run/docker.sock:/var/run/docker.sock:ro
    ports:
      - "24224:24224"      # Fluentdログ受信用 (TCP)
      - "24224:24224/udp"  # Fluentdログ受信用 (UDP)
      - "9411:9411"        # Zipkinトレース受信用
    networks:
      ot_net:
        ipv4_address: 192.168.151.40
    restart: unless-stopped
```

---

## 4. エッジ側の実装：OTプロトコルの壁と帯域外相関推論

Pythonによる時間的近接性評価とコンテキスト継承の実装です。マルチスレッド環境での競合を防ぐため `Lock()` を用いて排他制御を行っています。

```python
# --- Trace Context (Temporal Proximity) ---
trace_context = {}
trace_lock = Lock()

def log_event(event_name, message, trace_id=None, parent_span_id=None, metadata=None):
    current_time = time.time()
    active_trace_id = trace_id

    # Context propagation via temporal proximity
    if active_trace_id is None:
        with trace_lock:
            # 2秒以内のコンテキストを検索し、最新のものを取得
            recent_contexts = [(k, v) for k, v in trace_context.items() if current_time - v[2] <= 2.0]
            if recent_contexts:
                recent_contexts.sort(key=lambda x: x[1][2], reverse=True)
                active_trace_id = recent_contexts[0][0]
```

![Node-RED相関推論](https://static.zenn.studio/user-upload/f361f777ad81-20260724.png)
*(図: Node-RED上に構築されたHMIと、相関推論の起点となるイベント発行フロー)*

---

## 5. ダッシュボード構築とアラート実装における「6つの罠」

本基盤の構築過程で遭遇した技術的な「罠」と突破口を記録します。

1. **Docker Desktopのネットワーク隔離**: Windowsホストからのパケットが隔離されていたため、`red-team` 攻撃コンテナを同一OTネットワーク内に配置して内部インジェクション化して解決。
2. **コンテナ起動時の `pip install` ラグ**: コンテナ起動時のパッケージ追加で初期パケットが漏れる問題を、起動検知ラッパースクリプトにより解決。
3. **APM Service Mapのノード非接続問題**: 呼び出し元（Node-RED）を `kind: "CLIENT"`、呼び出し先（OT-IDS）を `kind: "SERVER"` と明示することでトポロジー接続線を描画。
4. **APM Spansの文字数制限**: 詳細テキストログの表表示崩れに対し、Splunk Ingest APIへCustom Eventを送信しEvent Feedパネルで描画するハイブリッド方式へ転換。
5. **UIオートコンプリートの属性遅延**: TSDB保存時のフィールド名自動変換を、SignalFlowコードの直接投入により回避。
6. **アラート構築ウィザードの仕様制限**: ウィザード経由の制限をコードベースのSignalFlow記述で突破。

---

## 6. ついに完成した次世代OTセキュリティダッシュボード

![サービスマップ](https://static.zenn.studio/user-upload/6cbb9adfeee8-20260724.png)
*(図: サービスマップ上で、hmi-noderedからot-idsへと点線のトポロジー接続線が引かれている様子)*

![OT Security SOCダッシュボード](https://static.zenn.studio/user-upload/2db479f0cc66-20260724.png)
*(図: 実演時のOT Security SOCダッシュボード。CRITICAL ALERTSが「3」に増加し、アラートがポップアップしている状態)*

---

## 7. 【実演編】インシデント検知と攻撃パケットの検証

### ① Panel 1: Modbus不正書き込みスパイク（SignalFlow記述）

```python
# 初期化ログ(ids_started) 以外の全ot-idsイベントスパンをカウント
filter_ = filter('sf_service', 'ot-ids') and not filter('sf_operation', 'ids_started')
A = histogram('spans', filter=filter_).count().publish(label='CRITICAL ALERTS')
```

攻撃パケット（Python/Scapy）:
```python
# Modbus/TCP Unauthorized Write (Coil Force Write FC 0x05)
send(IP(dst='192.168.151.30')/TCP(dport=502)/Raw(b'\x00\x01\x00\x00\x00\x06\x01\x05\x00\x01\xff\x00'), verbose=False)
```

### ② Panel 3: 物理セキュリティとOT制御の相関検知（Event Feed）

複合攻撃コード（Python/Scapy）:
```python
# Step 1: BACnet Unauthenticated Write (UDP 47808)
bacnet_pkt = Ether()/IP(src="10.0.5.22", dst="192.168.151.30")/UDP(dport=47808)/Raw(b'\x81\x0a')
realtime_ids.process_packet(bacnet_pkt)

time.sleep(1) # 1秒のタイムラグ

# Step 2: RTSP Stream Unauthorized Access (TCP 8554)
rtsp_pkt = Ether()/IP(src="10.0.5.22", dst="192.168.151.30")/TCP(dport=8554, flags="S")
realtime_ids.process_packet(rtsp_pkt)
```

---

## 8. 【評価編】パフォーマンス評価とリソース消費実測値

本アーキテクチャの最大の利点は、エッジ側（ローエンドPC）における監視・転送リソース消費の極小化です。

### 監視コンポーネントのリソース消費実測値 (`docker stats`)

* **`otel-collector` (ログ変換・転送ハブ)**: CPU 0.27% / MEM 40.11 MiB
* **`ot-ids` (相関推論・事前通知API)**: CPU 0.04% / MEM 132.8 MiB
* **`hmi-nodered` (HMI・操作ログ起点)**: CPU 0.54% / MEM 77.29 MiB

![docker stats実測値](https://static.zenn.studio/user-upload/80853548f3f1-20260723.png)

重厚な相関分析や時系列データベース（TSDB）の構築をすべてSaaS（Splunk Observability Cloud）側に委ねることで、エッジ側の監視用コンテナ群は極めて低いCPU使用率と数十MB程度のメモリ消費に収まっています。

---

## 9. おわりに：迫る法規制と統合監視の未来

経済安全保障推進法に基づくインフラ・サプライチェーン防護の強化をはじめ、OT/ICS環境のセキュリティ監視はすべての重要インフラ事業者および製造業にとって待ったなしの課題となっています。

本章で実証した **「OpenTelemetry Collectorによるエッジでのデータ最適化」** と **「Splunk Observability CloudによるSaaS型監視」** のアーキテクチャは、高価なオンプレミスアプライアンスを導入することなく、限られたインフラリソースでスモールスタートし、シームレスにスケール可能な現実的選択肢を提供します。

OTelの軽量さとSaaSの俊敏性を掛け合わせることで、OT環境における統合可観測性（Observability）の確立が実現します。
