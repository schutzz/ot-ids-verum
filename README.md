# OT Security Lab (Docker-based Hands-on Environment)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?logo=docker&logoColor=white)](https://www.docker.com/)
[![Zenn](https://img.shields.io/badge/Zenn-Technical_Articles-3EA8FF?logo=zenn&logoColor=white)](https://zenn.dev/schutzz)

**OT Security Lab** は、Dockerコンテナ環境のみで制御システム（OT/ICS）、産業プロトコル（DNP3, IEC 61850 GOOSE, Modbus/TCP）、可観測性基盤（OpenTelemetry, Zeek, Splunk Observability Cloud）、および攻撃エミュレーション（MITRE CALDERA for OT）を高度に再現・ハンズオン検証できるオープンソースのセキュリティ基盤です。

詳細な設計思想・検証結果・技術解説は [Zenn（@schutzz）の連載記事](https://zenn.dev/schutzz) にて順次公開しています。

---

## 📂 リポジトリ構成

本リポジトリは、検証シナリオに応じて独立した2つの防衛シリーズに整理されています。

```text
ot-security-lab/
├── 02_Power_Grid_Defense/       # ⚡ 【推奨】次世代電力網防衛シリーズ (完全独立環境)
│   ├── docker-compose.yml       # 変電所A/B, WANルーター, Zeek, OTel, HMIの全ネットワーク定義
│   ├── sub_a_ied/               # 変電所A IED (DNP3 / GOOSE通信)
│   ├── sub_b_hmi/               # 変電所B HMI (Node-RED コックピット)
│   ├── wan_router/              # L3 WAN 境界ルーター (遅延・パケット制御)
│   ├── zeek/                    # Zeek (CISA ICSNPP 産業プロトコルパケット解析)
│   ├── otel/                    # OpenTelemetry Collector (エッジ計装・メトリクス変換)
│   ├── attacks/                 # CALDERA C2連携・非同期時間差攻撃スクリプト
│   ├── caldera/                 # MITRE CALDERA (Ability T0855 / Adversary YAML)
│   └── dashboards/              # 🚨 Splunk Observability Cloud ダッシュボード定義 (JSON)
│
├── 01_Facility_Security/        # 🏢 施設警備システムシリーズ (基礎フェーズ)
│   ├── docker-compose.yml       # モーションセンサー・ゲートエミュレータ・HMI環境
│   └── sensor-emulator/         # Modbus/TCP メモリ汚染・改ざん検証環境
│
└── scripts/                     # 補助解析スクリプト群 (IDSパーサー等)
```

---

## ⚡ クイックスタート: 次世代電力網防衛環境 (`02_Power_Grid_Defense`)

最先端の「広域電力網 ✕ 可観測性 ✕ 攻撃エミュレーション」環境を以下の数コマンドで起動できます。

### 1. 環境起動

```bash
git clone https://github.com/schutzz/ot-security-lab.git
cd ot-security-lab/02_Power_Grid_Defense

# 全コンテナ環境のビルド＆バックグラウンド起動
docker-compose up -d --build

# Node-RED HMI フローの自動デプロイ
python deploy_flow.py
```

### 2. 稼働確認

コンテナ起動後、ブラウザおよびAPI経由でシステムが正常稼働しているか確認できます。

* **HMI (Node-RED Cockpit)**: `http://localhost:1880/`
* **HMI ステータス API 確認**:
  ```bash
  python -c "import urllib.request; print(urllib.request.urlopen('http://localhost:1880/api/status').read().decode())"
  ```
  *(正常時出力例: `{"is_tripped": false, "cb_states": {"CB101": true, ...}, "ups_soc": 100}`)*

---

## 🎯 主な検証テーマと機能

1. **非同期・時間差ステルス攻撃の再現**
   * サンディ・スタイルの電力網障害攻撃（`stealth_combo_attack.py`）により、エフェメラルポートの動的変更と意図的な時間差ウェイト（`maxspan` 超過）による相関分析の死角を実証。
2. **MITRE CALDERA for OT 連携**
   * カスタム Ability（`T0855`）および Adversary プロファイルを組み込み、C2 サーバから一発で高度な攻撃シナリオを発火・再生可能。
3. **Splunk Observability Cloud 統合**
   * `02_Power_Grid_Defense/dashboards/` 内の JSON をインポートすることで、全6パネルのリアルタイム監視・相関検索限界アラートダッシュボードを即座に構築可能。

---

## ⚠️ 倫理的注意事項（Ethical Disclaimer）

本リポジトリに含まれるコードおよび検証スクリプトは、MITRE ATT&CK for ICS マトリクスに基づき SOC/SIEM や可観測性基盤の盲点を安全に検証評価（Adversary Emulation）するための防衛研究目的で公開されています。許可されていない第三者のシステムに対する攻撃行為への悪用を厳重に禁じます。

---

## 📜 ライセンス

本プロジェクトは [MIT License](LICENSE) のもとで公開されています。
