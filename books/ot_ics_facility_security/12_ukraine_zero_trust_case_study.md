---
title: "第12章：ウクライナ送電網攻撃事例に学ぶファシリティ防衛とゼロトラスト実践"
---

# 第12章：ウクライナ送電網攻撃事例に学ぶファシリティ防衛とゼロトラスト実践

---

## 1. はじめに

これまでの章では、自作のOT/ICSラボ環境に対し、Purdueモデルに基づいたDMZネットワーク分離や、Splunk Observabilityを用いた統合可観測性基盤の構築、各種サイバー攻撃の検証を行ってきました。

最終章となる本章では、これまでの全11章で得た技術的知見をさらに拡張し、SaaS前提のエンタープライズ構成とは異なり、ローカル環境で完結する「超軽量なOT監視ラボ」の設計・構築を実践します。

さらに、歴史的OT攻撃である「ウクライナ電力網攻撃（2015年/2016年）」の教訓に基づき、内部ネットワーク侵入後の横移動（Lateral Movement）や不正コマンド・ログ注入を防ぐ**「ゼロトラスト・アーキテクチャ（Bearer Token動的認証）」**を監視通信に組み込む実装アプローチについて検証・解説します。

---

## 2. ウクライナ電力網攻撃から学ぶ「単一認証情報の脆弱性」

サイバーセキュリティにおいて、Sandwormグループによるウクライナ配電会社（Kyivoblenergo等）への攻撃事例は非常に有名な教訓を残しています。攻撃者は以下のステップを踏んでインシデントを引き起こしました。

1. **認証情報の窃取**: フィッシング等により保守作業員のVPNログイン情報（ID/Password）を入手。
2. **境界の突破**: 多要素認証（MFA）が未実装であったため、正規ユーザーとしてOTネットワーク内部（SCADA/HMI環境）へ侵入。
3. **制御命令の不正発行**: 正規のSCADA管理ツールやプロトコルコマンドを悪用し、変電所の遮断器（Breaker）を片っ端から開放して広域停電を引き起こした。

この事例が示している最大の教訓は、**「正当なログイン情報を持っている（または内部ネットワークに存在する）＝何でも操作可能である」という境界型・単一認証への過度な信頼が致命的な脅威になる** という点です。

どれほど厳格な境界防御を敷いていても、資格情報が窃取されて内部へ到達された場合、検証のない通信はすべて悪用されるリスクを孕んでいます。

---

## 3. Grafana / Loki / OTel の選定根拠と設計思想

ウクライナ事例のようなリスクに対処するには、内部通信ログを低負荷に集約しつつ、通信ごとの個別認証を強制する監視基盤が必要です。

本章では「K.I.S.S. (Keep It Simple, Stupid)」の原則に基づき、ローカル環境で軽快に動作するオープンソーススタックを構築します。

### ① なぜ Grafana Loki なのか？ (Schema-on-Read)

Grafana Loki は **Schema-on-Read（読み出し時スキーマ適用）** の設計思想を採用しています。

* **インデックス化するのはメタデータ（ラベル）のみ**: ログ本文はインデックス化せず、時間区切りで圧縮された「チャンク（Chunk）」として保存します。
* **高速な並列Grep検索**: 検索時に必要なチャンクのみを展開して並列Grepを行うため、メモリ消費量が既存SIEMの数十分の一から数百分の一に抑えられます。

---

### ② Grafana Dashboard Provisioning によるUI自動構成

設定ファイルによってダッシュボード構成を自動定義するプロビジョニング機能を導入します。

```yaml
# dashboards.yaml
apiVersion: 1
providers:
  - name: 'OT Zero Trust Substation'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards/json
```

この仕組みにより、読者が環境を立ち上げた瞬間、一切の手動設定なしで上部に「攻撃スパイクの時系列グラフ」、下部に「Lokiへ送られたリアルタイムログフィード」が自動描画される監視画面が完成します。

![仮想変電所 OT Zero Trust SOC Dashboard](/images/ukraine_zero_trust_grafana_log_feed.png)
*(図: 仮想変電所 OT Zero Trust SOC Dashboard。上段に「遮断器一斉開放アタック (Breaker Open Attack Spikes)」、下段に「仮想変電所 (Kyiv-North-330kV) リアルタイムログフィード」が表示されている様子)*

> **💡 Tips: OTel Collector と Loki のラベル構造について**
> OTel Collector Contrib版からLokiへログを送信する際、デフォルトでは `exporter="OTLP"` という最小限のラベルが付与され、ログ本文がJSON形式で転送されます。そのため、LogQLクエリは `{exporter="OTLP"}` を基点に `|= "BREAKER_OPEN"` のように本文フィルタルールを記述するのが確実です。

---

### ③ 設計思想1：コンテナネットワークによるPurdueモデルの絶縁

```yaml
networks:
  ot_closed_net:
    driver: bridge
    internal: true  # ← ホスト外部との通信を完全に遮断
  mgmt_net:
    driver: bridge
```

`internal: true` を付与することで、ホストOS（ローカルPC）からのルーティングすら完全に遮断された「絶対閉域網（Purdue Level 0〜3）」を構成できます。

---

### ④ 設計思想2：監視基盤へのゼロトラスト認証（Bearer Token）の導入

Nginxによるリバースプロキシ（認証関所）を配置し、OTel Collectorからの通信に対して厳密な Bearer Token 検証を必須化します。

* **Loki-Proxy (Nginx)**: リクエストヘッダーの `Authorization: Bearer <TOKEN>` を検証し、不正通信を `401 Unauthorized` で拒絶。
* **OTel Collector**: `bearertokenauth` 拡張機能を有効化し、有効なトークンを自動付与してログを安全に転送。

---

## 4. 全自動デプロイIaCカプセルスクリプト

設定ファイルの作成から、仮想変電所（IEC 60870-5-104プロトコル）シミュレータの起動までを1つのシェルスクリプトにカプセル化しました。

`init_zero_trust_lab.sh` として保存し、実行するだけで全環境が立ち上がります。

```bash
#!/bin/bash
set -e

echo "[+] Zero Trust OT/ICS Local Docker Lab のカプセル化展開を開始します"

LAB_DIR="ot_zero_trust_lab"
mkdir -p ./${LAB_DIR}/grafana/provisioning/datasources
mkdir -p ./${LAB_DIR}/grafana/provisioning/dashboards/json
mkdir -p ./${LAB_DIR}/nginx
mkdir -p ./${LAB_DIR}/ot-ids
mkdir -p ./${LAB_DIR}/ot_data
cd ./${LAB_DIR}

# 1-1. Grafanaの自動構成 (Lokiデータソース登録)
cat << 'EOF' > grafana/provisioning/datasources/datasource.yaml
apiVersion: 1
datasources:
  - name: Loki
    type: loki
    access: proxy
    url: http://loki:3100
    isDefault: true
    version: 1
    editable: false
EOF

# 1-2. Grafanaの自動構成 (ダッシュボードプロビジョニング)
cat << 'EOF' > grafana/provisioning/dashboards/dashboards.yaml
apiVersion: 1
providers:
  - name: 'OT Zero Trust Substation'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    options:
      path: /etc/grafana/provisioning/dashboards/json
EOF

# 2. ゼロトラスト認証関所 (Nginx Reverse Proxy)
cat << 'EOF' > nginx/nginx.conf
events {}
http {
    server {
        listen 3100;

        location /loki/api/v1/push {
            if ($http_authorization != "Bearer SuperSecretToken2026") {
                return 401 "Unauthorized: Invalid or Missing Bearer Token";
            }
            proxy_pass http://loki:3100;
        }
    }
}
EOF

# 3. 仮想変電所 (IEC-104) シミュレータ
cat << 'EOF' > ot-ids/virtual_substation.py
import json, time, random, os
LOG_FILE = "/var/log/ot_data/ids.json"
def log_event(event_type, action, status, threat_level="info"):
    event = {
        "attributes": {"time": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime())},
        "substation": "Kyiv-North-330kV", "protocol": "IEC-60870-5-104",
        "event": event_type, "action": action, "threat_level": threat_level, "status": status
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")
    print(f"Logged: {event['action']}")
if __name__ == "__main__":
    if os.path.exists(LOG_FILE): os.remove(LOG_FILE)
    while True:
        log_event("ASDU_M_ME_NA_1", "Voltage_Check", "Normal")
        time.sleep(2)
        if random.randint(1, 5) == 1:
            print("[!] INCOMING ATTACK DETECTED")
            # 遮断器(Breaker)の一斉不正開放攻撃
            for ioa in range(401, 404):
                log_event("ASDU_C_SC_NA_1", f"BREAKER_OPEN_IOA_{ioa}", "Executed", "critical")
                time.sleep(0.5)
EOF

cat << 'EOF' > ot-ids/Dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY virtual_substation.py .
CMD ["python", "-u", "virtual_substation.py"]
EOF

# 4. OpenTelemetry Collector (トークン自律付与)
cat << 'EOF' > otel-collector-config.yaml
extensions:
  bearertokenauth:
    token: "SuperSecretToken2026"
receivers:
  filelog/ot_hmi:
    include: [ /var/log/ot_data/*.json ]
    start_at: beginning
    operators:
      - type: json_parser
        timestamp:
          parse_from: attributes.time
          layout: '%Y-%m-%dT%H:%M:%S.%LZ'
processors:
  resource:
    attributes:
      - key: environment
        value: "zero-trust-lab"
        action: insert
      - key: architecture
        value: "pattern1-token-auth"
        action: insert
exporters:
  loki:
    endpoint: "http://loki-proxy:3100/loki/api/v1/push"
    auth:
      authenticator: bearertokenauth
service:
  extensions: [bearertokenauth]
  telemetry:
    logs:
      level: info
  pipelines:
    logs:
      receivers: [filelog/ot_hmi]
      processors: [resource]
      exporters: [loki]
EOF

# 5. Docker Compose
cat << 'EOF' > docker-compose.yml
version: '3.8'
networks:
  ot_closed_net:
    driver: bridge
    internal: true
  mgmt_net:
    driver: bridge
services:
  loki:
    image: grafana/loki:2.9.2
    command: -config.file=/etc/loki/local-config.yaml
    networks:
      - ot_closed_net
      - mgmt_net
    restart: unless-stopped
  loki-proxy:
    image: nginx:alpine
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    networks:
      - ot_closed_net
    restart: unless-stopped
    depends_on:
      - loki
  grafana:
    image: grafana/grafana:10.2.2
    environment:
      - GF_AUTH_ANONYMOUS_ENABLED=true
      - GF_AUTH_ANONYMOUS_ORG_ROLE=Admin
      - GF_AUTH_DISABLE_LOGIN_FORM=true
    ports:
      - "3000:3000"
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning:ro
    networks:
      - mgmt_net
    restart: unless-stopped
    depends_on:
      - loki
  otel-collector:
    image: otel/opentelemetry-collector-contrib:0.91.0
    command: ["--config=/etc/otelcol-contrib/config.yaml"]
    volumes:
      - ./otel-collector-config.yaml:/etc/otelcol-contrib/config.yaml:ro
      - ./ot_data:/var/log/ot_data:ro
    networks:
      - ot_closed_net
    restart: unless-stopped
    depends_on:
      - loki-proxy
  ot-ids:
    build: ./ot-ids
    volumes:
      - ./ot_data:/var/log/ot_data
    networks:
      - ot_closed_net
    restart: unless-stopped
EOF

echo "[+] 設定ファイルの生成完了。Dockerコンテナをバックグラウンドで起動します"
docker-compose up -d --build

echo "[+] 展開完了"
echo "[!] ブラウザで http://localhost:3000 にアクセスしてください"
```

---

## 5. 【実証編】アーキテクチャの検証結果

### ① 仮想変電所（IEC 104）遮断器一斉開放攻撃の動的グラフ可視化

仮想変電所シミュレータから攻撃イベント（遮断器一斉開放: `BREAKER_OPEN`）が発生すると、Grafanaのダッシュボード上にリアルタイムで攻撃スパイクとログストリームが描画されます。

![仮想変電所 OT Zero Trust SOC Dashboard](/images/ukraine_zero_trust_grafana_log_feed.png)
*(図: 遮断器一斉開放攻撃が発生した際のGrafanaダッシュボード。上段のグラフに「遮断器一斉開放アタック (Breaker Open Attack Spikes)」、下段に「仮想変電所 (Kyiv-North-330kV) リアルタイムログフィード」のJSONイベントログが流れる)*

---

### ② ゼロトラスト認証関所（Nginx Proxy）による不正アクセス遮断の証明

トークンなし（または不正トークン）でログ送信を直接試みた場合：

```bash
$ docker exec ot_zero_trust_lab-loki-proxy-1 wget -S --spider http://127.0.0.1:3100/loki/api/v1/push
Connecting to 127.0.0.1:3100...
HTTP/1.1 401 Unauthorized
```

結果、Nginx関所で即座に **`401 Unauthorized`** が返され、認証のないパケット注入が確実に阻止されます。

一方、正規の Bearer Token を持った OTel Collector からの通信は関所を無事通過し、Lokiへ届くことが確認されました。

---

### ② 物理リソース消費量の実測値 (`docker stats`)

| コンテナ名 | 役割 | CPU使用率 | メモリ使用量 |
| :--- | :--- | :--- | :--- |
| **`loki`** | ログ蓄積 (Schema-on-Read) | 0.73% | 38.82 MiB |
| **`loki-proxy`** | ゼロトラスト認証関所 (Nginx) | 0.00% | 2.50 MiB |
| **`otel-collector`** | エッジ計装・トークン付与 | 0.77% | 41.26 MiB |
| **`ot-ids`** | 仮想変電所シミュレータ | 0.00% | 6.58 MiB |
| **`grafana`** | UI / ダッシュボード | 0.12% | 81.79 MiB |

*(実測値: 監視スタック全体を合わせてもメモリ消費量は175MB以下、CPU使用率は1.7%以下という超低負荷動作を実証)*

---

## 6. おわりに：本書の総括とOTゼロトラストの未来

本書では、Dockerを用いた基礎的なコンテナ環境構築とPurdueモデルの分離（第1章〜第3章）から始まり、Modbus/TCP・BACnet・RTSPプロトコルの自作エミュレーション、WiresharkやLuaによるバイナリ解析（第4章〜第8章）、さらにMITRE ATT&CK for ICSに準拠したRed Teaming演習とHMI隠蔽攻撃（第9章）、そしてSplunkやLoki/OTelを用いた高度なSOC監視・ゼロトラスト認証（第10章〜第12章）まで、一貫したOTセキュリティの旅を完走しました。

ウクライナ送電網攻撃事例が示した通り、これからのOTセキュリティにおいては「境界の保護」だけでなく、「境界を破られて内部侵入された後に、いかに無検証な横移動（Lateral Movement）を抑止し、可視性と制御を維持するか」という**内部ゼロトラスト原則の適用**が不可欠となります。

本書で構築したハンズオン環境とコード群が、読者の皆様のOT/ICSセキュリティにおける学びと実践の一助となれば幸いです。
