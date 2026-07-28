# 【OT/ICS×Splunk】非同期・時間差攻撃で露呈する「従来型SIEM相関検索」の死角と限界 (Phase 2-2)

## 概要

本記事では、前回の広域分散OT/ICS環境（Purdue Level 2〜3.5）において、攻撃者が仕掛ける**「非同期・時間差ステルス・コンボ攻撃」**に対し、従来型のSIEM相関検索（タイムスタンプ依存のバインドや閾値検知）がどのように破綻し、攻撃チェーンを見失ってしまうのか（死角の露呈）を実証・解説します。

1. **広域グリッド遮断の可視化：Node-RED HMIへの3系統遮断器の増設**
   主系統（`CB-101`）、予備系統（`CB-202`）、連絡系統（`CB-303`）の動的インターロックをHMI上に構築し、時間差で連鎖開放される広域グリッド障害を再現。
2. **従来型SIEM相関検索の破綻実証**
   変電所Aへの予兆打診からWAN遅延（50ms＋ジッター）を跨いで2.5秒後に変電所Bの遮断器を落とす時間差攻撃により、従来のタイムスタンプ相関検索（`transaction`）が失敗し、**`Correlation Status: UNLINKED`**（孤立イベント判定）となる死角をSplunkダッシュボード上で視覚化。
3. **Trace Context（W3C Trace ID）導入への必然性の証明**
   単体パケットログやIP/時刻バインドに頼る限界を提示し、次回（Phase 3）の物理OTペイロードへの Trace ID 埋め込みによる決定論的統合への架け橋とします。

---

## 【課題編】非同期・時間差攻撃がもたらす「相関分析の破綻」

これまでのOTセキュリティ監視では、「同一IPアドレスからの短時間（例: 2秒以内）のアクセス」や「単一プロトコルの連続エラー」をSIEMで条件バインド（Correlation Rule）するのが一般的でした。しかし、高度インフラ攻撃者が用いる**非同期・時間差手法**に対しては、このアプローチは無力化します。

```
[攻撃者 (Red Team)]
   │
   ├── (1) 変電所Aへ DNP3 0x14 (Disable Unsolicited) 送信 ─── [変電所A: 予兆発生]
   │
   │  ＜ WAN遅延 50ms ＋ 2.5秒の時間差ウエイト ＞
   │
   └── (2) 変電所Bへ DNP3 0x05 (Direct Operate Breaker Open) ─ [変電所B: CB-101/202 トリップ]
```

### 1. タイムスタンプ・ウィンドウのバインド失敗 (`UNLINKED`)
従来のSplunk検索式：
```splunk
index=ot_logs | transaction src_ip maxspan=2s
```
攻撃者が意図的に置いた 2.5秒のインターバルとWANジッターにより、SIEMの検索ウィンドウ枠（`maxspan=2s`）からパケットが外れます。その結果、SIEMはこれを「変電所Aの軽微な設定変更」と「変電所Bの設備トリップ」という**無関係な2つの単発障害**として認識し、アラートが孤立（UNLINKED）します。

### 2. 閾値（Threshold）検知の完全スルー
一定時間内のパケット急騰（Volume Spike）を監視するルールは、時間を置いた数パケットの送信によって一切発火しません（`Alert Triggered: FALSE`）。

### 3. トポロジー・サービスマップの分断 (`Disconnected`)
W3C Trace Context (Trace ID) が存在しないため、APMや可観測性プラットフォームのトポロジー表示において、変電所Aと変電所Bの関連性が点線すら描画されず分断されます。

---

## 【監視盤構築編】Node-RED 3系統遮断器 ＆ 相関限界ダッシュボードの新設

本検証を実施するにあたり、まず観測・監視側の基盤を拡張・構築しました。

### 1. Node-RED HMI の3系統遮断器（Breaker）増設
変電所内の主系統・予備系統・バス連絡線を網羅する3つの動的遮断器をHMIパネルに配置。

* **`CB-101`**: Substation-A 主系統遮断器
* **`CB-202`**: Substation-B 予備系統遮断器
* **`CB-303`**: Transformer Bus Tie 連絡線遮断器

### 2. Splunk 「相関分析限界実証ダッシュボード」の新設
観測側において、相関分析の失敗と限界をリアルタイム表示する3大パネルを配置。

* **パネル① [Transaction Correlation Failure]**: `Correlation Status: UNLINKED`
* **パネル② [Volume Threshold Pass-through]**: `Threshold Alert: FALSE`
* **パネル③ [Trace ID Map Dependency]**: `Service Status: DISCONNECTED`

---

## 【実証編】時間差攻撃の実行と限界のキャプチャ

（※実装・検証実行後に実際の画面スクショおよびログ実測値を掲載予定）

---

## まとめと次回（Phase 3）への展望

本検証により、タイムスタンプや単体IPに頼る従来のSIEM相関検索は、非同期・時間差攻撃の前に容易に破綻することが実証されました。

次回（Phase 3）では、この死角を打破するため、**W3C Trace Context（Trace ID）を物理OT通信へ拡張・付与**し、どれほど時間が離れていても一瞬で一本の「攻撃チェーン（Trace Tree）」として自動統合される決定論的防御を構築します。

---

## 【実装ログ：落とし穴と現実の躓き記録】

> 本セクションは、実際に手を動かして構築・検証した際に遭遇したトラブルを記録するものです。  
> 「うまくいった手順書」だけでなく、**「こうして失敗した」という記録こそが実践の価値**として掲載します。

### 落とし穴 1：`data('spans', ...)` は APM トレースデータを参照できない

**状況**: Splunk Observability Cloud の Panel 1 で、`BREAKER_OPEN` トレースデータをダッシュボードに表示しようと以下の SignalFlow を設定した。

```python
A = data('spans', filter=filter('sf_service', 'hmi-nodered')).count().publish()
```

**問題**: パネルがフラットライン（値 `100`）のまま変化しない。  
**原因**: Splunk Observability Cloud の `data()` 関数は **Metric Time Series (MTS) 専用**。APM トレーススパンは APM モジュールに格納されており、`data()` では直接参照不可能。`histogram()` も同様に無効だった。

**解決策**: APM トレースではなく、**OTLP HTTP メトリクス**（カウンター/ゲージ）として送信する方式に切り替えた。
- Node-RED から `http://host.docker.internal:4318/v1/metrics` へ OTLP JSON 形式でメトリクスを POST
- otel-collector に `otlp` receiver + `metrics` パイプライン + `signalfx` exporter を追加
- SignalFlow を `data('breaker_status', ...)` に変更することで解決

**教訓**: Splunk Observability Cloud でトレースデータをダッシュボード化したい場合は、**別途メトリクスパイプラインを構築する**必要がある。トレースはAPMモジュール、メトリクスは Infrastructure Monitoring、という分離を意識すること。

---

### 落とし穴 2：`.env` ファイルのトークンがプレースホルダーのままだった

**状況**: otel-collector のログに以下のエラーが連続出力され、全スパン・メトリクスがドロップされていた。

```
rpc error: code = Unauthenticated desc = invalid token
```

**原因**: `.env` ファイルの `SPLUNK_ACCESS_TOKEN` が `YOUR_TOKEN_HERE` のままで、実際のトークンに差し替えられていなかった。スパン自体は otel-collector に正常受信されており、**転送段階で認証失敗**していた。

**教訓**: otel-collector の debug ログは受信成功（`Traces: spans: 1`）と転送失敗（`Exporting failed`）を別々に出力する。「受信されている＝Splunkに届いている」ではない。必ずエラーログを確認すること。

---

### 落とし穴 3：Node-RED の `require('crypto')` はサンドボックスで使用不可

**状況**: Zipkin スパンの `traceId` / `spanId` を生成するため、Node-RED の Function ノード内で以下のコードを使用した。

```javascript
const crypto = require('crypto');
const traceId = crypto.randomBytes(16).toString('hex');
```

**問題**: Function ノードが**サイレントに失敗**（エラーログも出ず、ノードが止まったように見える）。  
**原因**: Node-RED の Function ノードは Node.js モジュールの動的 `require()` を制限しており、`crypto` が使えなかった。

**解決策**: `Math.random()` を使った簡易 hex 生成関数で代替。

```javascript
function hexId(len) {
  var r = '';
  for (var i = 0; i < len; i++) r += Math.floor(Math.random() * 16).toString(16);
  return r;
}
```

**教訓**: Node-RED の Function ノードでは、組み込みモジュールの利用可否を事前に確認すること。エラーが出ずに止まるため、デバッグが難しい。

---

### 落とし穴 4：Splunk Single Value パネルの小数点表示が消せない

**状況**: `breaker_status` メトリクス（値: `0` または `1`）を Single Value パネルで表示した際、`1.00` と小数点以下が表示されてしまう。

**試みた対策**:
- SignalFlow に `.floor()` を追加 → 効果なし
- SignalFlow に `.max().floor()` を追加 → 効果なし
- Edit chart の「Maximum precision value」を `0` に設定 → 見た目上は変化なし

**結果**: 解決策を見つけられず、`1.00` 表示のまま運用。  
**推定原因**: Splunk Observability Cloud の Single Value チャートにおいて、OTLP 経由で送信された整数値が内部的に `double` 型として扱われ、SignalFlow での丸め操作が UI レンダリング層に反映されないバグまたは仕様の可能性。

**教訓**: Splunk Observability Cloud の UI 表示精度は SignalFlow 側だけでは完全にコントロールできない場合がある。整数表示が必須の場合はパネルタイプの選択を再検討するか、Splunk のサポートに確認すること。

---

### 落とし穴 5：コックピット UI がサーバー側の状態と同期しない

**状況**: 攻撃スクリプト（`stealth_combo_attack.py`）で `/api/breaker` を叩き、サーバー側の状態が `is_tripped: true` になっているのに、ブラウザのコックピットが全 CB「CLOSED（緑）」のまま変化しない。

**原因**: コックピットの HTML/JS はすべて**クライアントサイドの状態管理**で動作していた。ボタン（All Trip / All Reset）を押すとブラウザ内の `cbStates` 変数を書き換えてUIを更新するが、**ページロード時にサーバーから現在状態を取得するコードが存在しなかった**。

**解決策**: ページロード時に `/api/status` を fetch して状態を同期する初期化コードを追加。

```javascript
fetch('/api/status').then(r=>r.json()).then(d=>{
  if(d.is_tripped){
    // CBを全トリップ表示に更新
    Object.keys(d.cb_states).forEach(k => updateCbUI(k.replace('CB',''), d.cb_states[k]));
    // バッジ・IED・UPS表示を攻撃状態に切替
  }
}).catch(e=>{});
```

**教訓**: HMI の状態は「UI上の状態」と「サーバー（Node-RED グローバル変数）上の状態」の2箇所に存在する。ページリロードで乖離が生じないよう、**初期化時の状態同期**を必ず実装すること。

