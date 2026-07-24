# OT/ICS Zero Trust Monitoring Lab (Local Docker Encapsulated)

ウクライナ電力網攻撃（Sandworm事例）の教訓から生まれた、**ローカルPC上で完結する超軽量な「Zero Trust OT監視ラボ」**のリポジトリです。

---

## 🎯 アーキテクチャと設計思想

本ラボは **K.I.S.S. (Keep It Simple, Stupid)** の原則に基づき、ローカルリソースを極限まで節約しつつ、実効性の高いゼロトラスト防御をシミュレートします。

```
[Level 0-3 OT Closed Net (internal: true)]
  │
  ├── 1. ot-ids (Python: IEC-60870-5-104 Substation Simulator)
  │      └── Breaker Open Attack Spikes (ASDU C_SC_NA_1)
  │
  └── 2. otel-collector (OpenTelemetry Collector)
         └── Bearer Token Authorization (SuperSecretToken2026)
                │
                ▼ (HTTP/1.1 Ingest Stream)
  ┌───────────────────────────────┐
  │ 3. loki-proxy (Nginx Auth)    │ ◄── 401 Unauthorized Block for Untrusted Traffic!
  └───────────────┬───────────────┘
                  │ (Pass Through)
                  ▼
  ┌───────────────────────────────┐
  │ 4. loki (Schema-on-Read Engine)│
  └───────────────┬───────────────┘
                  │
[Level 4-5 Management Net]
  │
  └── 5. grafana (Port 3000 - Auto Provisioned Dashboard)
```

1. **Purdueモデルの論理絶縁 (`internal: true`)**
   Dockerの閉域ネットワークを用いて、Level 0-3（OT現場網）をホストOSおよび外部インターネットから物理的・論理的に完全切断。
2. **仮想変電所（IEC 104プロトコル）シミュレータ**
   攻撃者による変電所遮断器（Breaker）の一斉不正開放コマンド（ASDU C_SC_NA_1）をリアルタイムに疑似生成。
3. **Bearer Tokenによるゼロトラスト関所 (Nginx Auth Proxy)**
   OT網侵入後のログ偽装・横移動を阻止するため、Lokiの前にリバースプロキシを配置。正当なアクセストークンを持たない通信を `401 Unauthorized` で確実にブロック。
4. **OTel Collectorの自律トークン付与**
   `bearertokenauth` 拡張機能を用い、正規エッジ機器のみがトークンを付与して安全にログを転送。
5. **超軽量な Schema-on-Read 監視 (Grafana + Loki)**
   転置インデックスを作らず、全監視スタックを合わせても **メモリ175MB未満、CPU 1.7%未満** という超低負荷動作を実現。

---

## 🚀 Quick Start (ワンコマンドデプロイ)

以下のスクリプトを実行するだけで、設定ファイル生成からコンテナ起動、Grafanaダッシュボードの自動登録までが完了します。

```bash
bash init_zero_trust_lab.sh
```

---

## 🧪 動作確認・実験ガイド

### 1. ダッシュボードでのリアルタイム可視化
1. ブラウザで **`http://localhost:3000`** にアクセス（認証不要・自動ログイン）。
2. ダッシュボード **`⚡ 仮想変電所 OT Zero Trust SOC Dashboard`** を開く。
3. 攻撃発生時の**赤色スパイクグラフ**と、下段のリアルタイムLOGフィードを観察。

### 2. ゼロトラスト遮断実験（401 Unauthorized）
ターミナルでトークン無しのリクエストを送信し、Nginx関所で弾かれることを確認します：

```bash
# トークンなし ➔ 401 Unauthorized で即座にブロック
docker exec ot_zero_trust_lab-loki-proxy-1 wget -S --spider http://127.0.0.1:3100/loki/api/v1/push

# 正当なBearer Token付き ➔ 通過 (405 Method Not Allowed)
docker exec ot_zero_trust_lab-loki-proxy-1 wget -S --header="Authorization: Bearer SuperSecretToken2026" --spider http://127.0.0.1:3100/loki/api/v1/push
```

---

## 📜 ライセンス
MIT License
