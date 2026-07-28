---
title: "第11.5章：Splunk OT/ICSダッシュボード拡張 ─ 非同期・時間差攻撃が暴く「相関分析の限界」"
---

# 第11.5章：Splunk OT/ICSダッシュボード拡張 ─ 非同期・時間差攻撃が暴く「相関分析の限界」

---

> **💡 全ソースコード公開**
> 本ラボ環境を構成する `docker-compose.yml`、自作のOT-IDSスクリプト、Node-REDのフロー設定ファイル（JSON）など、すべてのコードはGitHubにて公開しています。
> [GitHubリポジトリはこちら](https://github.com/schutzz/ot-security-lab)

> **⚠️ 倫理的注意事項（Ethical Disclaimer）**
> 本章に記載される攻撃手法はすべて**筆者の自宅ローカル環境内でのみ**検証されたものであり、外部ネットワークや他者のシステムに対して一切実行していません。攻撃コードの全文は**意図的に省略・抽象化**しており、再現を促す目的ではありません。
> 攻撃のフルシナリオおよび倫理的なRed Teaming演習の実施方法については、**第9章「HMI視野の完全欺瞞と通信傍受・改ざんのシミュレーション」** を参照してください。

---

## 1. 概要と本章の位置づけ

前章（第11章）では、**OpenTelemetry Collector × Splunk Observability Cloud** による統合可観測性（Observability）基盤を構築し、OT/ICSの監視データをSaaSに集約するアーキテクチャを実証しました。

本章では、その構築済みの基盤を**「攻撃を受けたとき、何が見えて何が見えないのか？」** という観点で検証します。具体的には：

1. **Node-RED HMI（統合Webコックピット）へのOTLPメトリクスパイプライン増設**
2. **Splunk Observability Cloud 専用ダッシュボード「相関分析限界実証ダッシュボード」の新設**
3. **非同期・時間差ステルス攻撃の実行と、ダッシュボード上での観測結果の検証**

を通じて、**「情報は確かに届いている。しかし相関分析が追いつかない」** という、可観測性基盤の構造的な死角を明らかにします。

---

## 2. 【課題編】非同期・時間差攻撃がもたらす「相関分析の破綻」

### なぜ従来の相関検索は無力化するのか

これまでのOTセキュリティ監視では、**「同一IPアドレスからの短時間（例: 2秒以内）のアクセス」** や **「単一プロトコルの連続エラー」** をSIEMで条件バインド（Correlation Rule）するのが一般的でした。

しかし、高度インフラ攻撃者が意図的に **WAN遅延 + 時間差ウエイト** を挿入する「非同期・時間差手法」に対しては、このアプローチは完全に無力化します。

```
[攻撃者 (Red Team)]
   │
   ├── (1) 変電所Aへ偵察パケット送信 ─── [変電所A: 予兆発生]
   │
   │  ＜ WAN遅延 50ms ＋ 2.5秒の時間差ウエイト ＞
   │
   └── (2) 変電所Bへ制御コマンド送信 ─── [変電所B: 遮断器トリップ]
```

### 3つの破綻メカニズム

#### ① タイムスタンプ・ウィンドウのバインド失敗

従来のSIEM相関検索は、例えば「2秒以内に同一送信元から発生したイベントを1つの攻撃チェーンとして結合する」というルールで動作します。

攻撃者が意図的に2.5秒の時間差を置くと、SIEMはこの2つのイベントを **「変電所Aの軽微な設定変更」と「変電所Bの設備トリップ」という無関係な2つの単発障害** として認識し、アラートが孤立します。

#### ② 閾値（Threshold）検知の完全スルー

一定時間内のパケット急騰（Volume Spike）を監視するルールは、**時間を置いた数パケットの送信によって一切発火しません**。攻撃者が1パケットずつ、間隔を空けて送信する限り、量的閾値に到達しないためです。

#### ③ サービスマップの分断

W3C Trace Context (Trace ID) が存在しない場合、可観測性プラットフォームのトポロジー表示において、変電所Aと変電所Bの関連性が **点線すら描画されず完全に分断** されます。

---

## 3. 【基盤改修編】OTLPメトリクスパイプラインの構築

### 3.1 改修の背景：なぜトレースだけでは不十分だったか

第11章で構築した基盤は、Node-RED HMI → OTel Collector → Splunk への **Zipkin トレース（スパン）送信パイプライン** でした。しかし、Splunk Observability Cloud のダッシュボードで `data()` 関数を使用してリアルタイム可視化しようとしたところ、**トレーススパンは `data()` 関数から直接参照できない** という壁に直面しました。

Splunk Observability Cloud のダッシュボードは **Metric Time Series（MTS）** を前提としており、APMトレースは別モジュールに格納されます。つまり、**ダッシュボードのリアルタイムパネルにOTイベントを表示するには、別途メトリクスパイプラインを構築する必要がある** のです。

### 3.2 otel-collector-config.yaml への `metrics` パイプライン追加

既存のトレース用 Zipkin receiver に加えて、**OTLP HTTP receiver（ポート 4318）** と **メトリクスパイプライン** を追加しました。

```yaml
receivers:
  zipkin:
    endpoint: 0.0.0.0:9411
  otlp:                        # ← 追加
    protocols:
      http:
        endpoint: 0.0.0.0:4318  # OTLP HTTP receiver

# ... (processors は既存のまま) ...

exporters:
  otlp:
    endpoint: "ingest.${SPLUNK_REALM}.signalfx.com:443"
    headers:
      "X-SF-Token": "${SPLUNK_ACCESS_TOKEN}"
  signalfx:                    # ← 追加（メトリクス専用 exporter）
    access_token: "${SPLUNK_ACCESS_TOKEN}"
    realm: "${SPLUNK_REALM}"

service:
  pipelines:
    traces:
      receivers: [zipkin]
      processors: [memory_limiter, resourcedetection, resource, batch]
      exporters: [otlp, debug]
    metrics:                   # ← 追加（メトリクスパイプライン）
      receivers: [otlp]
      processors: [memory_limiter, resourcedetection, resource, batch]
      exporters: [signalfx, debug]
```

**設計意図**: トレースは従来どおり Zipkin → OTLP exporter → Splunk APM へ。メトリクスは新設の OTLP HTTP receiver → SignalFx exporter → Splunk Infrastructure Monitoring へ。2つの独立したパイプラインを並走させます。

### 3.3 Node-RED コックピットフロー (`cockpit_flow.json`) への改修

#### 改修①：`breaker_status` ゲージメトリクスの10秒ポーリング送信

遮断器の状態をSplunkダッシュボードで**常時監視**するため、Node-REDのグローバル変数 `is_tripped` を10秒間隔でポーリングし、OTLP JSON 形式でメトリクスを送信するノード群を追加しました。

```
[inject: Every 10s] → [function: Build breaker_status gauge] → [http request: POST to Collector]
```

Function ノードの処理概要（メトリクスペイロード構築）：

```javascript
// Node-RED グローバル変数から状態を取得
var isTripped = global.get('is_tripped') || false;
var val = isTripped ? 1 : 0;  // 正常=0, TRIPPED=1

// OTLP JSON メトリクス形式で送信
msg.payload = {
  "resourceMetrics": [{
    "resource": {
      "attributes": [
        {"key": "service.name", "value": {"stringValue": "hmi-nodered"}}
      ]
    },
    "scopeMetrics": [{
      "metrics": [{
        "name": "breaker_status",
        "gauge": {
          "dataPoints": [{
            "asInt": val.toString(),
            // ... 省略
          }]
        }
      }]
    }]
  }]
};
```

送信先: `http://host.docker.internal:4318/v1/metrics`（ホストOS上の otel-collector）

#### 改修②：`correlation_timeout` ゲージメトリクスの同時送信

Panel 4（相関限界警告）用に、`breaker_status` と同時に `correlation_timeout` メトリクスも送信するよう改修しました。

- **正常時**: `correlation_timeout = 0`
- **攻撃後（is_tripped=true）**: `correlation_timeout = 1`

これにより、**「相関ウィンドウを超過した攻撃が発生したかどうか」** をダッシュボード上でバイナリ表示できます。

#### 改修③：ページロード時のサーバー状態同期

外部（攻撃スクリプト等）から `/api/breaker` を叩いた場合、サーバー側の状態は更新されますが、ブラウザに表示されているコックピットUI は更新されないという問題がありました。

原因は、コックピットの HTML/JavaScript が**クライアントサイドのみで状態管理**しており、ページロード時にサーバーから現在状態を取得するロジックが存在しなかったためです。

これを解決するため、`<script>` セクションの末尾に初期化コードを追加しました。

```javascript
// ページロード時にサーバー状態を同期
fetch('/api/status').then(r => r.json()).then(d => {
  if (d.is_tripped) {
    // 遮断器表示を全トリップ状態に更新
    Object.keys(d.cb_states).forEach(k => {
      updateCbUI(k.replace('CB', ''), d.cb_states[k]);
    });
    // バッジ・IED・UPS表示を攻撃状態に切替
    // ... 省略
  }
}).catch(e => {});
```

---

## 4. 【ダッシュボード構築編】Splunk「相関分析限界実証ダッシュボード」の新設

Splunk Observability Cloud 上に **「仮想変電所 OT Zero Trust SOC Dashboard」** を新設し、4つのパネルを配置しました。

### 4.1 Panel 1: 遮断器一斉開放ステータス（Single Value）

**SignalFlow:**
```python
A = data('breaker_status', filter=filter('service.name', 'hmi-nodered')).publish(label='BREAKER OPEN ATTACK SPIKES')
```

- **正常時**: `0`（緑）── 全遮断器 CLOSED
- **攻撃時**: `1`（赤）── 1台以上の遮断器が TRIPPED

**Color 設定**: `Color by` → `Value` に変更。閾値 `1` で赤色に切替。

### 4.2 Panel 2: リアルタイムセキュリティログフィード（Event Feed）

**SignalFlow:**
```python
events(eventType='OT_SECURITY_EVENT', filter=filter('grid', 'Kyiv-North-330kV')).publish(label='Kyiv-Grid Security Log Feed')
```

攻撃スクリプトの各ステージ実行時に **SignalFx Events API (`/v2/event`)** へカスタムイベントを直接 POST することで、攻撃の進行状況がリアルタイムでフィードに流れます。

送信するイベント（4種）:

| ステージ | イベント種別 (`attack_type`) | 内容 |
|:---|:---|:---|
| Stage 1 | `RECON` | DNP3偵察パケット送信 |
| Stage 2 | `CORRELATION_GAP` | 時間差ウエイト（2.5秒） |
| Stage 3 | `BREAKER_TRIP` | 遮断器全段開放コマンド |
| Stage 4 | `GRID_BLACKOUT` | グリッド停電確認 |

### 4.3 Panel 3: サービストポロジーテーブル（Table）

**SignalFlow:**
```python
A = data('breaker_status', filter=filter('service.name', 'hmi-nodered')).publish(label='hmi-nodered')
B = data('breaker_open_count', filter=filter('service.name', 'hmi-nodered')).sum().publish(label='Attack Events Total')
```

当初は APM の `sf.service.request.count` メトリクスを使用し、Cluster Map（トポロジーマップ）表示を目指していました。しかし、**Splunk Observability Cloud の試用版では APM MetricSets が利用不可**であったため、送信済みのカスタムメトリクスを使った Table 表示に変更しました。

テーブル列: `hmi-nodered` / `service.name` / `grid` / `host.name` / `os.type` / `deployment.environment`

### 4.4 Panel 4: 分散時間差アタック相関限界警告パネル（Single Value）

**SignalFlow:**
```python
A = data('correlation_timeout', filter=filter('service.name', 'hmi-nodered')).publish(label='Correlation Window Alert')
```

- **正常時**: `0` ── 相関ウィンドウ内
- **攻撃後**: `1`（赤）── 相関タイムアウト検知

---

## 5. 【実証編】非同期・時間差攻撃の実行と観測結果

> **⚠️ 注記**: 攻撃スクリプトの全文は倫理的配慮から掲載しません。攻撃手法の詳細については第9章を参照してください。本セクションでは**観測結果の分析**に焦点を当てます。

### 5.1 攻撃シナリオの概要

```
Stage 1: 変電所Aへ偵察パケット送信（DNP3プロトコル）
            ↓
Stage 2: WAN遅延シミュレーション（2.5秒の時間差）
            ↓
Stage 3: HMI /api/breaker へ遮断器全段開放コマンド
            ↓
Stage 4: 攻撃結果検証（全CB TRIPPED確認）
```

攻撃スクリプトは、各ステージの実行時にSignalFx Events APIへカスタムイベントを送信し、Splunkダッシュボードのログフィード（Panel 2）にリアルタイムで記録されます。

### 5.2 ダッシュボード観測結果


> **📸 以下のスクリーンショットを挿入**
> Splunk ダッシュボード「仮想変電所 OT Zero Trust SOC Dashboard」攻撃実行後の全4パネル表示
> ※ Zenn 公開時に `![Splunk OT/ICS 相関分析限界実証ダッシュボード](https://static.zenn.studio/user-upload/xxx.png)` に差し替え

攻撃実行後のダッシュボードには、以下の状態が表示されます。

| Panel | 表示内容 | 読み取れること |
|:---|:---|:---|
| **Panel 1** 遮断器一斉開放 | `1.00`（赤） | 遮断器がTRIPPED状態であることは分かる |
| **Panel 2** セキュリティログ | `OT_SECURITY_EVENT` | 個々のイベントは記録されている |
| **Panel 3** トポロジー | `hmi-nodered` のみ | **hmi-nodered以外のサービスが見えない** |
| **Panel 4** 相関限界警告 | `1.00`（赤） | 相関タイムアウトが発生したことは分かる |

### 5.3 「見えているのに繋がらない」──相関分析の限界

ここが本章の核心です。

ダッシュボードを見ると、**すべてのデータは確かに届いています**。Panel 1 は遮断器が落ちたことを示し、Panel 2 にはイベントが流れ、Panel 4 は相関タイムアウトを検知しています。

しかし、SOC アナリストがこのダッシュボードだけを見た場合、**以下の疑問には答えられません**：

> **「Stage 1 の偵察パケットと Stage 3 の遮断器開放は、同一の攻撃チェーンの一部なのか？」**

#### なぜ答えられないのか

1. **Panel 1（Single Value）** は「今、遮断器が開いている」という事実しか示さない。**誰が・いつ・何の結果として**開いたのかは不明。

2. **Panel 2（Event Feed）** は個々のイベントを時系列で表示するが、Stage 1 と Stage 3 の間に2.5秒の空白がある。この2つのイベントが **同一攻撃チェーンの一部** なのか、**偶然の同時発生** なのかを判別する手段がない。

3. **Panel 3（Table）** には `hmi-nodered` しか表示されない。変電所A（sub_a_ied）と変電所B（sub_b_dnp3）のサービスが **同じテーブルに登場しない** ため、拠点間の攻撃横断を可視化できない。

4. **Panel 4（Single Value）** は「相関ウィンドウを超えた」と警告するが、**何と何の相関が失敗したのか**は示さない。

これが、**「情報は届いている。しかし相関分析が追いつかない」** という構造的限界の正体です。

---

## 6. 【落とし穴記録】実装で遭遇したトラブル集

> 「うまくいった手順書」だけでなく、**「こうして失敗した」という記録こそが実践の価値**です。

### 落とし穴 1：`data('spans', ...)` は APM トレースを参照できない

Splunk Observability Cloud の `data()` 関数は **Metric Time Series (MTS) 専用**です。APMトレーススパンは `data()` では直接参照不可能であり、`histogram()` も無効でした。ダッシュボードにOTイベントを表示するには、**トレースとは別にメトリクスパイプラインを構築する**必要がありました。

### 落とし穴 2：`.env` のトークン未設定

otel-collector のログに `rpc error: code = Unauthenticated desc = invalid token` が出力されていたにもかかわらず、受信ログ（`Traces: spans: 1`）のみを確認して「届いている」と誤認。**受信成功と転送成功は別**であることを学びました。

### 落とし穴 3：Node-RED Function ノードの `require()` 制限

Zipkinスパン生成のために `require('crypto')` を使用したところ、Function ノードが **サイレントに停止**。Node-RED のサンドボックス環境では、Node.js モジュールの動的ロードが制限されています。`Math.random()` による代替実装で解決しました。

### 落とし穴 4：Single Value パネルの小数点表示が消せない

`breaker_status` メトリクス（値: `0` or `1`）を Single Value パネルで表示すると `1.00` と小数点以下が付きます。SignalFlow に `.floor()` を追加しても、Edit chart の「Maximum precision value」を `0` に設定しても、**UIレンダリング層で小数点が付与される仕様**のため解決できませんでした。OTLP 経由の整数値が内部的に `double` 型で処理されている可能性があります。

### 落とし穴 5：コックピットUIとサーバー状態の乖離

外部から `/api/breaker` を叩くとサーバー側の状態は更新されますが、ブラウザのコックピットは**クライアントサイドのみの状態管理**だったため反映されませんでした。ページロード時に `/api/status` を fetch して状態を同期する初期化コードの追加で解決しました。

---

## 7. まとめと次回への展望

### 本章で実証されたこと

| 観点 | 結果 |
|:---|:---|
| **データの到達性** | メトリクス・イベントともにSplunkに到達している ✅ |
| **個別イベントの検知** | 遮断器トリップ、偵察パケット等は個別に検知可能 ✅ |
| **攻撃チェーンの結合** | **Stage 1 と Stage 3 が同一攻撃であることを自動的に結合する手段がない** ❌ |
| **拠点間の横断可視化** | **変電所Aと変電所Bを1つの攻撃として関連付けられない** ❌ |

### 得られた教訓

可観測性プラットフォームは「データを集める」ことには優れていますが、**「データを攻撃文脈で結び付ける」ことは自動ではできません**。タイムスタンプや送信元IPに頼る従来の相関検索は、攻撃者が意図的に時間差を挿入するだけで容易に破綻します。

### 次回（Phase 3）への展望

この死角を打破するため、次回は **W3C Trace Context（Trace ID）を物理OT通信へ拡張・付与** し、どれほど時間が離れていても一瞬で一本の「攻撃チェーン（Trace Tree）」として自動統合される **決定論的防御** を構築します。

```
[Before: Phase 2-2]
  Stage 1 (偵察) ──── 2.5秒 ──── Stage 3 (攻撃)
       ↓                              ↓
  孤立イベント A                 孤立イベント B
  （相関不能 = UNLINKED）

[After: Phase 3 (W3C Trace Context)]
  Stage 1 (偵察) ──── 2.5秒 ──── Stage 3 (攻撃)
       ↓                              ↓
  Trace ID: abc123               Trace ID: abc123
       └──────── 同一チェーン ────────┘
  （自動統合 = LINKED）
```
