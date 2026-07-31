# 次世代電力網防衛ラボ（ot-security-lab）完全展開マニュアル

本ドキュメントは、「eBPF (XDP) 前衛 ✕ Zeek 後衛 ハイブリッド防衛アーキテクチャ」 を含む広域分散スマートグリッド・サイバーレンジ（仮想環境）をローカル環境（Linux / WSL2）上に展開し、再現検証を行うためのステップ・バイ・ステップ指示書です。

---

## 1. 前提条件と動作環境

本サイバーレンジは、高度なカーネルレイヤー（XDP）と高度な可観測性パイプライン（OTel + Splunk）を組み合わせているため、以下の環境を推奨します。

### 推奨環境
* **OS**: Linux (Ubuntu 22.04 LTS / 24.04 LTS 推奨) または Windows 11 (WSL2 Ubuntu)
* **Linux Kernel**: 5.15 以上（eBPF/XDP および BPF Pinning サポート必須）
* **必須ソフトウェア**:
  * **Docker**: v24.0 以上
  * **Docker Compose**: v2.20 以上 (Compose V2 必須)
  * **Python**: 3.10 以上（検証・攻撃スクリプト実行用）
  * **ethtool**: ネットワークオフロード無効化用
* **オプショナル（eBPF再ビルド時）**:
  * `clang`, `llvm`, `libbpf-dev`, `linux-tools-generic` (bpftool)

---

## 2. 事前準備と環境変数の設定

### リポジトリのクローン
```bash
git clone https://github.com/schutzz/ot-security-lab.git
cd ot-security-lab
```

### 環境変数（.env）のセットアップ
`Splunk Observability Cloud` と連携する場合は、認証情報を設定します。
※ Splunkと連携しない場合（ローカルログ検証のみ）でも、プレースホルダーのまま起動可能です。

```bash
cp .env.example .env
```

`.env` の編集例：
```env
SPLUNK_REALM=jp0
SPLUNK_ACCESS_TOKEN=your_actual_splunk_o11y_ingest_token_here
```

---

## 3. サイバーレンジの展開と起動

本ラボでは、`docker-compose.yml` の Profile 機能を活用し、「従来環境（Zeekのみ）」と「ハイブリッド環境（eBPF+Zeek）」を柔軟に切り替えられるよう設計されています。

### 3.1 通常起動（全変電所ノード ＋ 従来型 Zeek 監視網）

まずはベースとなる仮想電力網インフラおよび可観測性パイプラインを立ち上げます。

```bash
docker compose up -d
```

#### 起動するコンテナ群の役割：
* `wan_router`: WAN/LAN 境界ルーター（Linux `tc` で 50ms の遅延注入）
* `cc_scada_master`: 中央給電指令所 (Level 3 SCADA Master)
* `sub_a_ied_01` / `sub_a_ied_02`: 変電所A (DNP3 / IEC 61850 GOOSE)
* `sub_b_rtu_hmi`: 変電所B (Node-RED HMI & DNP3 RTU)
* `zeek_tap`: 後衛ディープ・パケット・インスペクション (Zeek DPI)
* `otel_collector`: OpenTelemetry Collector (OTLP ログ・トレース変換)

---

### 3.2 ハイブリッド防衛モードへの切り替え (`eBPF Vanguard` の有効化)

eBPF (XDP) による L7 浅層パーサー・パケットドロップ機能を有効化する場合は、付属の制御スクリプト `toggle_engine.sh` を使用します。

```bash
# スクリプトに実行権限を付与
chmod +x toggle_engine.sh

# ハイブリッドモード (eBPF Vanguard 有効化) へ切替
./toggle_engine.sh hybrid
```

※ 手動でDockerコマンドを叩く場合は以下と同等です：
```bash
docker compose --profile ebpf up -d ebpf_agent
```

---

## 4. 攻撃シナリオの再演と A/B テスト検証

本環境では、Phase 2 の攻撃スクリプトを用いて「従来のZeek単体」と「eBPF+Zeekハイブリッド」の防衛性能差を定量比較できます。

### 4.1 ネットワークオフロードの無効化（検証前の鉄則）
正確なパケットキャプチャとXDPの正常動作のため、ホスト/WSL2のオフロードをオフにします。

```bash
sudo ethtool -K eth0 gro off lro off tso off gso off 2>/dev/null || true
```

---

### 4.2 飽和アタック（DDoS / ノイズフラッド）シナリオの実行

約60万パケットの超高密度UDPフラッドノイズを射出し、ZeekのCPU負荷とパケットドロップ率を測定します。

```bash
# 攻撃スクリプトの実行（別ターミナルから）
python3 attacks/phase2_1_flood.py
```

#### 期待される検証結果：
1. **従来モード (`./toggle_engine.sh legacy`)**:
   * `zeek_tap` の CPU 使用率が **96% 超**に高騰。
   * `capture_loss.log` にて **35% 以上のパケットドロップ** が発生。
2. **ハイブリッドモード (`./toggle_engine.sh hybrid`)**:
   * `ebpf_agent` (XDP) がノイズパケットをカーネル空間で 100% 破棄（`XDP_DROP`）。
   * `zeek_tap` の CPU 使用率は **0.1% 〜 0.5%** に抑制。パケットドロップ率は **0%** を維持。

---

### 4.3 ステルス攻撃と W3C Trace Context 保持の検証

DNP3 の正規制御コマンド（`0x14` Disable Unsolicited / `0x05` Direct Operate）を含んだ隠密攻撃を実行し、eBPFが誤ドロップを起こさず、後衛のZeek/Splunkへ正常に Trace Context が伝達されるか確認します。

```bash
python3 attacks/phase2_2_stealth.py
```

#### 期待される検証結果：
* `ebpf_agent` は DNP3 のマジックバイト（`0x05 0x64`）を識別し `XDP_PASS` を判定。
* 後衛の Zeek が正常にログ化し、Splunk APM / Observability 上で `IT_to_OT_Killchain_DNP3` のトレースツリーが途切れることなく完璧に描画されます。

---

## 5. トラブルシューティングと良くある落とし穴

### Q1. `ebpf_agent` コンテナが `EPERM` (Operation not permitted) で落ちる
* **原因**: コンテナに `CAP_BPF` / `CAP_NET_ADMIN` / `CAP_SYS_ADMIN` が不足しているか、Linuxカーネルが古すぎます。
* **対策**: `docker-compose.yml` 内の `cap_add` 設定（`BPF`, `NET_ADMIN`, `PERFMON`, `SYS_ADMIN`）を確認してください。決して `--privileged` を付与しないでください。

### Q2. WSL2 環境で eBPF / XDP が動作しない
* **原因**: WSL2 のデフォルトカーネルで BPF/XDP 機能が無効化されている場合があります。
* **対策**: WSL2 のカーネルを 5.15 以上に更新（`wsl --update`）し、必要に応じて `.wslconfig` でネスト化ハイパーバイザおよび BPF サポートを有効にしてください。

---

## 6. ライセンスと免責事項

* **License**: MIT License
* **Ethical Disclaimer**: 本リポジトリのコードおよび検証手法は、**MITRE ATT&CK for ICS マトリクスに基づく防衛・可観測性基盤の安全性評価**を目的として構築されたものです。許可されていない第三者のシステムに対する悪用・攻撃行為を固く禁じます。
