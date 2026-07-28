# 【OT/ICS×Splunk Observability】OTel Collectorのエッジ計装で突破する次世代インシデント監視構築

## 概要
本記事では、帯域制限と可用性が極端に厳しいOT/ICS（制御システム）閉域網に対し、**OpenTelemetry Collector（エッジ計装） × Splunk Observability Cloud（SaaS）** を用いた次世代インシデント監視ラボを構築し、以下の成果を実証しました。

1. **境界での帯域削減とSaaS監視の両立**
   DMZ（Purdue Level 3.5）に関所として配置したOTel Collectorでパケット解析と不要ログの破棄・Log-to-Metric変換を実施。OT網の極小帯域を保護しつつ、Splunk Observability Cloudによるリアルタイムな可観測性を実現しました。
2. **重厚なオンプレSIEMからの脱却とHMI操作追跡**
   従来のホスト型防御やリソースを食い潰すオンプレSIEMを捨て、非HTTPプロトコル（Modbus等）の相関分析エッジ処理に特化。Node-REDのHMI操作履歴（Audit Log）と現場の物理事象をTrace IDで強力に紐付けることで、L2攻撃や不正操作の死角を決定論的に検知可能にしました。
3. **総額3万円のローエンド環境でサクサク動く「超低負荷アーキテクチャ」**
   このエンタープライズ級の監視アーキテクチャは、3万円で調達した中古PC（第11世代 Core i7 メモリ32GB）1台のラボ環境で稼働します。エッジで負荷を削ぎ落とし、重い処理をSaaSに逃がす「OTel × Splunk」アーキテクチャにより、システムリソースを枯渇させることなく低負荷で軽快に動作する事実を確認しました。

---

## 【課題編】ラボ検証（Phase 1〜9）で直面した「従来アプローチ」の限界

これまでの連載を通じて、自作のOT/ICSラボ環境に「境界防御（FW）」や「従来型のネットワーク監視（ホスト型IDS/PCAP解析）」を組み込んで検証を重ねてきました。しかし、Red Teaming演習や内部ネットワークでの攻撃検証を経た結果、以下の3つの致命的な課題に直面しました。

### 1. 単発パケット解析（従来型IDS）では防げない「正規の皮を被った攻撃」
Modbus/TCPやBACnetといったプロトコルにおいては、攻撃者が発行した「不正なバルブ開放命令」であっても、パケットの構造上は「完全に正常なフォーマット」として扱われます。HMI（Node-RED）上の操作パネルから意図的に不正な制御コマンドが打ち込まれた場合でも、PLC側の受信ログや単発のパケット監視だけでは「それが正規オペレーターの意図した操作なのか、攻撃者による不正割り込みなのか」というコンテキスト（前後関係）を把握することが不可能でした。

### 2. マルチプロトコル環境における相関分析の「手作業による破綻」
ラボ内の通信が複雑化した結果、インシデント発生時に異なるプロトコル（Modbus, BACnet, RTSP）のPCAPデータや生ログ、さらにNode-RED上のHMI操作履歴を個別に取得・分析する羽目になりました。「HMIでボタンが押された数ミリ秒後に、カメラの映像が途切れ、Modbusのコイルが不正に書き換えられた」といった因果関係をアナリストが手動で突き合わせる作業は、極めて困難かつ非現実的でした。

### 3. PCAP全量取得によるエッジリソース「即時枯渇」の懸念
すべてのトラフィックをミラーリングし、生パケット（PCAP）や未加工のログをエッジ側（ローエンドPC環境）で解析・保存し続ければ、遠からずCPUやストレージI/Oが限界に達します。限られたリソースしか持たない現場において、重厚な解析データをオンプレミスで抱え込むアーキテクチャは長期的運用に耐えません。

### 課題の総括：導出された次なる一手
エッジ側の極限まで限られたリソースで継続的に生き残るには、パケットをただ記録するのではなく、**「HMI操作ログから物理プロトコルまでを統一フォーマットで集約し、DMZの関所で軽量なメトリクスやトレース（文脈）に変換して、重い相関分析をSaaSに丸投げする」**というアプローチへの転換が必要でした。

---

## 【アーキテクチャ選定編】バックエンド選定の根拠：Splunk Enterprise vs. Splunk Observability Cloud

### 1. Splunk Observability Cloud採用の技術的・物理的根拠
本アーキテクチャでSaaS版を採用した理由は、オンプレミス型Splunk Enterpriseが持つ運用負荷を排除し、OT/ICS環境におけるリアルタイム性を確保するためです。

| 項目 | Splunk Enterprise (従来) | Splunk Observability Cloud (本案) |
| :--- | :--- | :--- |
| **アーキテクチャ** | オンプレミス/IaaS (管理負荷大) | SaaS (フルマネージド) |
| **スケーリング** | インフラ増強が必要 (物理コスト大) | 自動スケーリング (即応性高) |
| **分析手法** | SPLによる検索クエリベース | SignalFlowによるリアルタイム計算 |
| **APM/相関分析** | 設定・構築が複雑 | OTelネイティブ対応 (標準装備) |
| **OT適性** | ログ保管中心 (高レイテンシ) | リアルタイム可観測性 (低レイテンシ) |

### 2. OTel Collector 採用の技術的・物理的根拠
OT環境とSaaSの中間に OpenTelemetry (OTel) Collector を「関所」として挟むことで、安全かつ確実な可観測性を実現します。
*   **エンドポイント集約 (Resource Masking)**: Purdue Level 3.5に配置し、配下の全OTノードを秘匿。SaaS側から「1つのデータソース」として認識させます。
*   **Log-to-Metric変換による帯域保護**: 生ログをメトリクスへ変換し、数バイトの時系列データのみをSaaSへ送信することで、細いOT網の帯域を保護します。
*   **決定論的な相関分析ハブ機能**: 現場パケットと論理事象（HMI操作）を、W3C Trace Contextに準拠した単一のトレースツリーに統合します。

> **[📸 スクショプレースホルダー：Purdueモデルをベースにしたネットワークアーキテクチャ図の画像を挿入]**

---

## 【実装編】次世代インシデント監視の実装プロセス

> 💡 **全コードの公開について**
> 本検証で使用したすべての設定ファイル（Docker Compose、OTel Collector設定、自作IDS、Node-REDフロー）は、読者が手元で即座に再現できるよう以下のGitHubリポジトリで公開しています。
> [🔗 GitHub: OT-ICS-Splunk-Observability-Lab (※ご自身のURLに変更してください)]

### 1. Splunk Observability Cloudの準備とOTel Collectorの展開

Splunk Observability Cloudのトライアル環境は5分足らずで取得できました。`Realm` と `Access Token` を取得し、セキュリティの観点から `.env` ファイルに分離します。

```env
# .env ファイルの例
SPLUNK_REALM=jp0
SPLUNK_ACCESS_TOKEN=05bdlF4LgTAEMRa2bNB1BQ...
```

次に、エッジに配置するOTel Collectorのフルコンフィグ（`otel-collector-config.yaml`）を作成します。無駄なログを削ぎ落とし、リソース制限（`memory_limiter`）をかけつつ、Splunkへ安全に転送するパイプラインです。

```yaml
# otel-collector-config.yaml
receivers:
  zipkin:
    endpoint: 0.0.0.0:9411
processors:
  batch:
    send_batch_size: 100
    timeout: 1s
  resourcedetection:
    detectors: [env, system]
  memory_limiter:
    check_interval: 1s
    limit_mib: 100
  resource:
    attributes:
      - key: deployment.environment
        value: "ot-lab"
        action: insert
exporters:
  otlp:
    endpoint: "ingest.${SPLUNK_REALM}.signalfx.com:443"
    headers:
      "X-SF-Token": "${SPLUNK_ACCESS_TOKEN}"
service:
  pipelines:
    traces:
      receivers: [zipkin]
      processors: [memory_limiter, resourcedetection, resource, batch]
      exporters: [otlp]
```

### 2. エッジ側の実装：OTプロトコルの壁と「帯域外（Out-of-Band）相関推論」

クラウドネイティブな環境であればHTTPヘッダーに `trace_id` を付与して因果関係を伝播できますが、ModbusやBACnetにはそのような拡張ヘッダーが存在しません。
この制約を突破するため、本番環境さながらの**「アウトオブバンド（帯域外）相関推論」**を実装しました。

**【Node-RED側の実装（Root Spanの生成と事前通知）】**
HMIの操作パネル（Node-RED）でボタンが押された瞬間、以下の通りランダムな `trace_id` を生成してIDSのAPIへ事前通知するフローを組みました。

> **[📸 スクショプレースホルダー：ここにNode-REDのフロー画面（関数ノードとHTTP Requestノードが繋がっている部分）のスクショを挿入]**
> *キャプション：Node-RED上のHMI操作を起点としてTrace IDを生成し、OTelとIDSに同時送信するフロー*

```javascript
// Node-RED: Trace ID生成とコンテキスト付与ノード
const trace_id = msg.trace_id || (Math.random().toString(16).substring(2, 18) + Math.random().toString(16).substring(2, 18));
const span_id = Math.random().toString(16).substring(2, 18);

msg.payload = {
    "trace_id": trace_id,
    "span_id": span_id,
    "event.name": "gate_toggle"
};
return msg;
// ※この後、HTTP Requestノードで OTel Collector と IDS(5000番) へ同時にPOST送信
```

> 💡 **Tips: Splunk APM サービスマップ描画における `kind` 属性の罠**
> Splunk APMのサービスマップ（Service Map）上で、2つのサービス間にトポロジー接続線（`A ➔ B`）を描画させるためには、単に `trace_id` を同一にするだけでなく、**OpenTelemetry / Zipkinの `kind` 属性を厳密に設定する必要があります**。
> - **呼び出し元（例: Node-RED）:** `kind: "CLIENT"` （クライアントとして外部へ要求を発行）
> - **呼び出し先（例: OT-IDS）:** `kind: "SERVER"` （サーバーとして要求を受信）
> 
> 両方が `SERVER` になっていると、Splunk APMはそれぞれを独立したエントリーポイント（単体のサーバー）と誤認し、マップ上で線が繋がらない「独立したポツンノード」になってしまいます。サービスマップに線が出ない場合は、まず `kind` 属性のロール定義を疑ってみてください。

**【IDS側の実装（時間的近接性によるコンテキスト結合）】**
IDS側では、受信したTrace Contextをメモリに保持。物理ネットワーク上で異常を検知した際、直近2秒以内のコンテキストが存在すれば、同一トランザクションとして `trace_id` を継承します。

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
            # 2秒以内のコンテキストを検索し、最新のものをソートして取得
            recent_contexts = [(k, v) for k, v in trace_context.items() if current_time - v[2] < 2.0]
            if recent_contexts:
                recent_contexts.sort(key=lambda x: x[1][2], reverse=True) 
                active_trace_id = recent_contexts[0][1][0]
                parent_span_id = recent_contexts[0][1][1]
    
    if not active_trace_id:
        active_trace_id = format(random.getrandbits(128), '032x')
```

### 3. ダッシュボード構築とアラートの実装における「6つの罠（つまづきポイント）」

今回の高度な監視基盤を構築するにあたり、ドキュメント通りにはいかない「強烈な罠」に何度も遭遇しました。同じ構成を目指すエンジニアのために、直面した課題と突破口をすべて記録しておきます。

*   **罠①：Docker Desktopのネットワーク隔離によるパケット空振り**
    *   **事象:** Windowsホスト（WSL）からテスト用の攻撃パケットを送信しても、IDSコンテナが全く検知しない。
    *   **突破口:** DockerのBridgeネットワークがホストから隔離されていたため。同じネットワーク内に `red-team` 用の攻撃コンテナを配置し、そこから内部向けに直接インジェクションする構成に変更。
*   **罠②：コンテナ起動時の `pip install` ラグ問題**
    *   **事象:** テストスクリプトを回してもIDSがパケットをスルーする。
    *   **突破口:** `docker-compose up` 時に毎回走る `apt-get` や `pip` に数十秒かかっており、IDSが起動する前に攻撃が着弾していた。起動完了をプロセス監視で確実に待機するテストラッパースクリプトを自作して自動化。
*   **罠③：APM Service Mapでサービス同士の線が繋がらない問題**
    *   **事象:** スパンを送信しているにもかかわらず、APM上のサービスマップで `hmi-nodered` と `ot-ids` が独立したノードになり、接続線が描画されない。
    *   **突破口:** トレースIDの共有に加え、HMI側の送信スパンを `kind: "CLIENT"`、IDS側を `kind: "SERVER"` と定義することで、APMが正確なトポロジー接続（親子関係）を自動認識して線を描画する仕様を解明。
*   **罠④：APM Spansの文字数制限と「Data Table」の崩壊**
    *   **事象:** 検知時の詳細なテキストログをダッシュボードの表（Data Table）に出そうとしたが、何も表示されない。
    *   **突破口:** Splunk APMのメトリクス（spans）は、改行を含む長文をディメンションとして集計できない仕様。そのため、文字列表示用のアラートパネルにはAPMを使わず、**「相関検知発火と同時にSplunk Ingest APIへCustom Eventを送信し、Event Feedパネルで受信する」**ハイブリッドアーキテクチャへピボット。
*   **罠⑤：UIオートコンプリートの遅延と内部変換**
    *   **事象:** 新サービス登録直後はUIのフィルター候補に属性が表示されない。またTSDB保存時に `service.name` は `sf_service` に強制変換される。
    *   **突破口:** UI（Chart Builder）を無視し、SignalFlowタブからコードを直接流し込むハックで突破。
*   **罠⑥：アラート構築ウィザードの幽閉**
    *   **事象:** APM画面の「ベルのマーク」からDetectorを作成するとSaaS特有のウィザードに固定され、カスタムSignalFlowが書けない。
    *   **突破口:** 汎用アラート画面から作成し直すことで解決。これが一番時間を溶かしました。

---

## 【実演編】エンドツーエンドでのインシデント検知と攻撃ペイロードの検証

本アーキテクチャが実際にどのように攻撃を捉え、ダッシュボード上にリアルタイム描画するのか、実際に仕掛けた**3種類の攻撃コードと対応する発振メカニズム**を詳細に解説します。

> **[📸 スクショ1プレースホルダー：Splunk APM サービスマップの画像を挿入]**
> *キャプション：サービスマップ上で、hmi-noderedからot-idsへと点線のトポロジー接続線が引かれている様子*

> **[📸 スクショ2プレースホルダー：完成したOT Security SOCダッシュボード全体の画像を挿入]**
> *キャプション：実演時のOT Security SOCダッシュボード。CRITICAL ALERTSが「3」に跳ね上がり、Panel 1に攻撃スパイク、Panel 3に長文アラートテキストがポップアップしている状態。*

---

### 💥 各パネルの発振メカニズムと送信攻撃パケットの詳細

#### 1. CRITICAL ALERTS（左上カウンター：表示「3」）の集計ロジック
トップに配置された **`CRITICAL ALERTS`** は、単一の攻撃手法だけでなく、エッジのIDSが捉えた**すべての危険度の高いセキュリティアラート（初期化ログ以外）の総数**をリアルタイム集計しています。

**【SignalFlowコード】**
```signalflow
filter_ = filter('sf_service', 'ot-ids') and not filter('sf_operation', 'ids_started')
A = histogram('spans', filter=filter_).count().publish(label='CRITICAL ALERTS')
```
（※`ids_started` 以外の全イベントスパンをカウント対象とすることで、後述する攻撃が着弾するたびに数値が「1 ➔ 2 ➔ 3」と動的にカウントアップし、赤い大アイコンで危険を即座に知らせます）

---

#### 2. Panel 1: Modbus不正書き込みスパイク（左下Timechartの青色スパイク）
攻撃者がModbus/TCP通信において、許可されていないコイル書き込み命令（Function Code 0x05）を送信した際の検知です。

*   **送信した攻撃コード（Python/Scapy）:**
    ```python
    # Modbus/TCP Unauthorized Write (Coil Force Write FC 0x05)
    # ターゲット: ot-ids (192.168.151.30:5002 / 502)
    send(IP(dst='192.168.151.30')/TCP(dport=502)/Raw(b'\x00\x01\x00\x00\x00\x06\x01\x05\x00\x01\xff\x00'), verbose=False)
    ```
*   **発振メカニズム:**
    `ot-ids` がTCP 502ポートを通過する生パケットをScapyでディープインスペクション。Payloadの第8バイト目（`FC=0x05`）を検出した瞬間、`modbus_unauthorized_write` スパンを発行します。
    ダッシュボード上では、13:44および13:46のタイムスタンプ位置に**青色（紫色）の鋭いスパイク**としてリアルタイム描画されます。

---

#### 3. Panel 3: 物理セキュリティとOT制御の相関検知（右下Event Feedの長文ポップアップ）
単体では正常に見える「BACnet門扉の不正書き込み」と「RTSP監視カメラへのアクセス」が、短時間（2秒以内）に連続して発生した複合シナリオ攻撃の検知です。

*   **送信した攻撃コード（Python/Scapy）:**
    ```python
    # Step 1: BACnet Unauthenticated Write (UDP 47808)
    bacnet_pkt = Ether()/IP(src="10.0.5.22", dst="192.168.151.30")/UDP(dport=47808)/Raw(b'\x81\x0a')
    realtime_ids.process_packet(bacnet_pkt)

    time.sleep(1) # 1秒のタイムラグ

    # Step 2: RTSP Stream Unauthorized Access (TCP 8554)
    rtsp_pkt = Ether()/IP(src="10.0.5.22", dst="192.168.151.30")/TCP(dport=8554, flags="S")
    realtime_ids.process_packet(rtsp_pkt)
    ```
*   **発振メカニズム:**
    `ot-ids` がメモリ上のテーブルで「BACnetアクセスから1秒後にRTSPアクセスが来た」という時間的近接性（Correlation）を判定。即座に `bacnet_rtsp_correlation` イベントを生成し、Splunk Ingest APIへCustom Eventとして直接POST送信します。
    Panel 3の **Event Feed（カスタムイベントパネル）** に、以下の詳細なアラートテキストが動的にポップアップします：
    ```text
    bacnet_rtsp_correlation
    attacker_ip: 10.0.5.22
    message: [!] 複合シナリオアラート: 「門扉不正開放(BACnet) ➔ カメラアクセス(RTSP)」 の連鎖 
             13:44:14 [BACnet Gateway] Unauthorized Write (Object: Gate) --> normalized_ip: 10.0.5.22
             | (1 seconds later...)
             13:44:15 [RTSP Server] Camera Feed Accessed --> normalized_ip: 10.0.5.22
    ```

---

#### 4. ARPスプーフィング攻撃（L2中間者攻撃の検知）
攻撃者がネットワーク内で偽のARPレスポンスを撒き散らし、通信を盗聴・改ざんしようとした際の検知です。

*   **送信した攻撃コード（Python/Scapy）:**
    ```python
    # IP 192.168.151.21 に対し、異なる2つのMACアドレスを連続送信して衝突を発生させる
    pkt1 = Ether(src="00:11:22:33:44:55")/ARP(op=2, psrc="192.168.151.21", hwsrc="00:11:22:33:44:55")
    pkt2 = Ether(src="aa:bb:cc:dd:ee:ff")/ARP(op=2, psrc="192.168.151.21", hwsrc="aa:bb:cc:dd:ee:ff")
    
    realtime_ids.process_packet(pkt1)
    realtime_ids.process_packet(pkt2)
    ```
*   **発振メカニズム:**
    `ot-ids` のインメモリARPテーブル監視ロジックが「同一IPを異なるMACアドレスが主張した」ことをフラグ検出。`arp_spoof_detected` スパンを発行し、トップの `CRITICAL ALERTS` のカウント数を押し上げます。

---

## 【評価編】パフォーマンス評価：エッジリソースの劇的な削減と実測値

本アーキテクチャの最大の恩恵は、エッジ側（ローエンドPC）における監視・転送リソース消費の極小化です。ラボ環境（第11世代 Core i7, メモリ32GB）での稼働中の実測値（`docker stats`コマンド結果）を示します。

*   **otel-collector (ログ変換・転送ハブ)**: CPU 0.27% / MEM 40.11MiB
*   **ot-ids (相関推論・事前通知API)**: CPU 0.04% / MEM 132.8MiB
*   **hmi-nodered (HMI・操作ログ起点)**: CPU 0.54% / MEM 77.29MiB

（※参考：環境内で最も負荷が高いのは映像配信エミュレータであり、監視システム自体のオーバーヘッドは全体で1%にも満たない状態です）

パケットの全量保存や重厚な相関分析、TSDBのインデックス作成といったヘビーな処理をすべてSaaS側に逃がすことで、エッジ側の監視用コンテナ群は極めて低いCPU使用率と数十MBのメモリ消費量に収まっています。
この「超低負荷」な実績こそが、限られたリソースしか持たない現場において、SaaSオフロード型アーキテクチャが極めて現実的で持続可能な選択肢であることを明確に裏付けています。

---

## 結びに代えて：迫る法規制と中小企業におけるSplunk Observabilityの可能性

2026年10月より本格化するサイバー関連法案（経済安全保障推進法に基づくインフラ・サプライチェーン防護の強化など）により、これまでOT/ICS環境の監視をスコープ外としてきた中小・中堅の製造業やインフラ事業者も、急ピッチなセキュリティ強化を迫られています。

しかし、現場のリアルな声として「専任のセキュリティエンジニアがいない」「数千万規模の重厚長大なオンプレミスSIEMを導入・運用する予算もリソースもない」という企業が大多数です。
本記事で実証した **「OpenTelemetry Collectorを用いたエッジでのデータ最適化」 と 「Splunk Observability CloudによるSaaS型監視」** のアーキテクチャは、まさにそうした企業に対する強力な最適解になり得ます。

総額3万円の中古ローエンドPCでサクサクと稼働する本ラボ環境が証明するように、高価なアプライアンスサーバーは一切不要です。極小の初期投資とリソースでスモールスタートを切り、要件の拡大に合わせてSaaSの利点を活かしてシームレスにスケールさせることができます。

「Splunk＝大規模エンタープライズ向けの重厚なシステム」という先入観をアップデートし、OTelの軽量さとSaaSの俊敏性を掛け合わせることで、Splunk Observability Cloudは予算とリソースに悩む中小企業のOTセキュリティを根本から底上げする、最強のB2Bソリューションになると思料します。
