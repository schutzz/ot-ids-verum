# OT Security Lab: 次世代電力網防衛サイバーレンジ (Phase 1 〜 Phase 4 集大成)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Architecture: Hybrid eBPF+Zeek](https://img.shields.io/badge/Architecture-eBPF%20%2B%20Zeek%20Hybrid-blue.svg)]()
[![Observability: Dual Sink (APM + Node Graph)](https://img.shields.io/badge/Observability-Splunk%20%2B%20Elasticsearch%20%2B%20Grafana-purple.svg)]()

本リポジトリは、Docker環境上に構築された**広域分散型スマートグリッド（仮想電力網）のサイバーレンジおよびハイブリッド防衛・可観測性検証プラットフォーム**です。

Purdue Model (Level 0〜3) に準拠した変電所インフラ、DNP3 / IEC 61850 GOOSE などの産業制御プロトコル、MITRE CALDERA による多層攻撃シナリオ、そして **「W3C Trace Context による IT-to-OT 因果追跡 (OOB)」** および **「eBPF Vanguard ✕ Zeek Rearguard ハイブリッド防衛」** の両機能を備え、それぞれの効果を動的に ON/OFF 切り替えて定量検証できる 4象限テスト基盤（4-Quadrant Matrix Testing Platform）を提供します。

---

## 本ラボの核となる 4象限マトリクス検証 (4-Quadrant Matrix Testing)

防衛メカニズムおよび追跡機能の効果を独立かつ客観的に定量測定するため、本環境では **前衛XDPノイズフィルタ (`ebpf_on`)** と **OOBトレース追跡エージェント (`oob_on`)** の 2 軸独立トグル制御を備えています。

| 象限 | eBPF (XDP Vanguard) | OOB (Trace Context) | 起動コマンド | 主な検証目的・アナリシス役割 |
|:---|:---:|:---:|:---|:---|
| **Q1: ベースライン** | **OFF** | **OFF** | `docker compose up -d` | 従来型IDS環境。Zeek単体でのパケットドロップ率やCPU飽和の限界測定 |
| **Q2: OOB単体検証** | **OFF** | **ON** | `docker compose --profile oob_on up -d` | ノイズ遮断なし状態での純粋なIT-to-OTトレースID付与率（Hit Rate）と処理遅延の測定 |
| **Q3: XDP単体検証** | **ON** | **OFF** | `docker compose --profile ebpf_on up -d` | トレース追跡なしで、XDPノイズカット機能のみがZeekのパケット救出に寄与する効果の独立測定 |
| **Q4: フルハイブリッド** | **ON** | **ON** | `docker compose --profile ebpf_on --profile oob_on up -d` | 前衛での高速ノイズ遮断 ✕ 後衛での因果チェーン追跡を両立する完全防衛状態 |

---

## 全体アーキテクチャ ＆ データフロー図

```mermaid
flowchart TD
    subgraph WAN["WAN (172.16.0.0/24)"]
        Attacker["external_attacker\n(172.16.0.99)"]
    end

    subgraph Router["境界ルーター (tc delay 50ms)"]
        WanRouter["wan_router\n(172.16.0.254 / 10.0.10.254)"]
    end

    subgraph CC["CC LAN (10.0.10.0/24)"]
        SCADA["cc_scada_master\n(10.0.10.10)"]
        JumpServer["jump_server\n(172.16.0.100 / 10.0.10.1)"]
    end

    subgraph Substation["変電所 LAN (10.0.20.0/24, 10.0.30.0/24)"]
        IED1["sub_a_ied_01\n(10.0.20.10 - DNP3/GOOSE)"]
        HMI["sub_b_rtu_hmi\n(10.0.30.10 - Node-RED HMI & RTU)"]
    end

    subgraph Defense["OOB トレース ＆ ハイブリッド防衛要塞"]
        XDP["ebpf_agent (XDP Vanguard)\n[L7 Shallow Parser / Ring 0]"]
        TXAgent["ebpf_tx_agent\n[kprobe tcp_sendmsg OOB Tracker]"]
        Zeek["zeek_tap (DPI Rearguard)\n[zeekctl Cluster Engine]"]
        Redis["oob_redis / oob_webdis\n(OOB Trace Key Store)"]
    end

    subgraph Pipeline["可観測性パイプライン (Dual Sink)"]
        Vector["vector (Log Router & VRL Engine)"]
        Splunk["Splunk Observability Cloud\n(APM Trace Tree)"]
        ES["Elasticsearch 8.x\n(ot-topology-edges / nodes)"]
        Grafana["Grafana Node Graph Panel\n(http://localhost:3000)"]
    end

    Attacker -->|1. E2E Pivot SSH/Auth| JumpServer
    JumpServer -->|2. DNP3 Strike (FC=5)| HMI
    JumpServer ..>|3. kprobe hook| TXAgent
    TXAgent -->|4. SET hash_key| Redis

    HMI -. "TAP/Mirror" .-> XDP
    Attacker -. "Noise Flood" .-> XDP

    XDP -- "XDP_DROP (ノイズ破棄)" --> Drop(("破棄"))
    XDP -- "XDP_PASS (正規OTパケット)" --> Zeek
    Zeek -- "5. dnp3.log / conn.log" --> Vector
    Vector -- "6. REST GET (orig_h)" --> Redis
    Redis -- "7. Trace ID (Hit/Color)" --> Vector

    Vector -->|8a. OTLP Export| Splunk
    Vector -->|8b. Bulk Index| ES
    Grafana -->|9. Node Graph Query| ES
```

---

## 実測リソース消費量 (`docker stats`)

完全版ハイブリッドラボ（eBPF Vanguard ✕ Zeek ✕ Vector ✕ Redis ✕ 全仮想IED）の平時稼働状態の実測値です。

```text
CONTAINER NAME    CPU %     MEM USAGE / LIMIT     MEM %     PIDS
ebpf_agent        0.03%     512KiB / 15.55GiB     0.00%     1
ebpf_tx_agent     0.04%     3.07MiB / 15.55GiB    0.02%     2
zeek_tap          2.99%     384.2MiB / 15.55GiB   2.41%     80
vector            2.81%     40.59MiB / 15.55GiB   0.25%     15
otel_collector    2.01%     95.32MiB / 15.55GiB   0.60%     14
sub_b_rtu_hmi     0.00%     118.1MiB / 15.55GiB   0.74%     14
sub_a_ied_01      0.02%     26.25MiB / 15.55GiB   0.16%     2
sub_a_ied_02      0.01%     17.01MiB / 15.55GiB   0.11%     1
cc_scada_master   0.03%     21.00MiB / 15.55GiB   0.13%     2
wan_router        0.00%     16.05MiB / 15.55GiB   0.10%     1
jump_server       0.00%     19.36MiB / 15.55GiB   0.12%     2
oob_webdis        0.15%     2.78MiB / 15.55GiB    0.02%     9
oob_redis         0.55%     5.66MiB / 15.55GiB    0.04%     5
------------------------------------------------------------------
合計 (Total)      8.64%     749.90MiB             4.70%     148
```

- **eBPFローダーメモリ使用量**: わずか **512 KiB** （1MB未満の極小フットプリント）
- **全システム合計メモリ**: **750 MiB台** (Zeekクラスター・Vector・Redis・全仮想IED含む)
- **CPU使用率合計**: **9.0% 未満** (平時)

---

## フェーズ別構成と全機能一覧 (Phase 1 〜 Phase 4)

### Phase 1: 仮想スマートグリッド基盤の構築 (Purdue Level 0〜3)
* **ネットワーク分離と遅延注入**: Linux `tc` (Traffic Control) を使用し、WAN/LAN 境界ルーター経由で 50ms の通信遅延を正確に模擬。
* **産業制御プロトコル実装**:
  * **DNP3**: 変電所 RTU 制御（FC `0x05` Direct Operate 遮断器開閉、FC `0x14` Disable Unsolicited）
  * **IEC 61850 GOOSE**: 変電所間高速保護継電器アライアンス（L2 パケット）
  * **SNMPv2c**: 変電所非常用 UPS 補機電源制御 (`.1.3.6.1.2.1.33.1.1.4`)
* **Node-RED HMI**: 現場の遮断器状態（OPEN/CLOSE）およびメタデータをリアルタイム描画。

### Phase 2: MITRE CALDERA による多層攻撃 ✕ 監視破綻の実測
* **CALDERA C2 オーケストレーション**:
  * **Stage 1 (境界突破)**: 窃取トークンによる JumpServer 境界認証の無傷すり抜け
  * **Stage 2 (消音化)**: DNP3 FC `0x14` 送出による RTU 自発発報の強制停止
  * **Stage 3 (連鎖物理破壊)**: DNP3 FC `0x05` (遮断器強制作動) ✕ SNMP (UPS強制作動停止) の二重打撃
  * **Stage 4 (飽和ノイズ攻撃)**: 約60万パケットの超高密度 UDP フラッド連射
* **監視破綻の定量立証**: ユーザー空間 DPI (Zeek) の CPU 使用率が 96.4% に高騰し、35.88% のパケットドロップが発生して監視網が物理破綻することを証明。

### Phase 3: W3C Trace Context による IT-to-OT 因果追跡
* **分散トレース連携**: OpenTelemetry Collector ＋ Vector ＋ Splunk Observability Cloud 構成。
* **相関ID注入**: DNP3 アプリケーションヘッダーおよび内部イベントログへ W3C Trace Context (`traceparent`) を統合。
* **因果関係の可視化**: 単純なIP/ポート相関検索の限界を克服し、境界侵入から変電所ブラックアウトに至るキルチェーンを単一の APM トレースツリーとして可視化。

### Phase 4: eBPF Vanguard ✕ Zeek Rearguard ハイブリッド防衛 ＆ 可視化基盤

* **Phase 4-4-1 (カーネル防衛 ✕ OOBエンリッチメント完結)**:
  * **eBPF (XDP) L7 浅層パーサー (Vanguard)**: `libbpf` 製エージェント。動的オフセット計算 (`OFFSET FLAT`) により DNP3 (`0x05 0x64`) および Modbus 構造を Ring 0 で判定・ノイズ破棄。
  * **BPF Pinning ("不沈空母" 化)**: `/sys/fs/bpf/xdp_pass` へのピン留めにより、コンテナ停止後もカーネル内でパケットドロップが自律継続。
  * **Zeek zeekctl クラスター構成 (Rearguard)**: `Log::set_buf(DNP3::LOG, F)` でログ即時フラッシュ化、`capture-loss` ポリシーでドロップ追跡。
  * **OOB トレースコンテキスト エンリッチメント**: `ebpf_tx_agent` (`tcp_sendmsg` kprobe) が Redis に `orig_h` キー (TTL=300s) で W3C Trace Context を事前登録。Vector が VRL で一貫した `trace_id` を DNP3 ログへ結合 (`enrichment_status: hit` 100% 達成)。
  * **XDP カウンター分離エクスポート**: `ebpf_agent` (read_only / curl非搭載) の `xdp_counter_map` をピン共有し、`ebpf_tx_agent` が Webdis / Vector 経由で `xdp.drop.total` / `xdp.pass.total` を可視化。

* **Phase 4-4-2 (Elasticsearch ✕ Grafana Node Graph 統合拡張)**:
  * **Dual Sink ログパイプライン**: Vector から Splunk APM への転送に加え、Elasticsearch 8.x へトポロジーログ (`ot-topology-edges-*`, `ot-topology-nodes-*`) および XDP メトリクス (`xdp-metrics-*`) をバルク同時転送。
  * **Grafana Node Graph Panel**: 外部攻撃者 (`external_attacker`: 172.16.0.99) から JumpServer (172.16.0.100) を経由する E2E Pivot 侵入を `Attacker ➔ JumpServer ➔ RTU` という一気通貫のアタックチェーン（動的に赤く染まるトポロジーマップ）として直感的に描画。

---

## クイックスタート & 展開手順

動作環境要件（Linux/WSL2 Kernel 5.15+）、環境構築、4象限テスト実行手順などの詳細なマニュアルは以下を参照してください。

* **[詳細な環境展開マニュアル (DEPLOYMENT.md)](./DEPLOYMENT.md)**

### 4象限切り替え実行コマンド

```bash
# 1. リポジトリのクローン
git clone https://github.com/schutzz/ot-security-lab.git
cd ot-security-lab/02_Power_Grid_Defense

# 2. 環境変数の作成
cp .env.example .env

# --- [4象限 起動パターン] ---

# Q1: ベースライン (Zeekのみ / eBPF OFF / OOB OFF)
docker compose up -d

# Q2: OOB単体検証 (OOB ON / eBPF OFF)
docker compose --profile oob_on up -d

# Q3: XDP単体検証 (eBPF ON / OOB OFF)
docker compose --profile ebpf_on up -d

# Q4: フルハイブリッド (eBPF ON + OOB ON)
docker compose --profile ebpf_on --profile oob_on up -d

# 起動後、Zeek クラスターを有効化
docker exec zeek_tap zeekctl deploy

# --- [E2E Pivot 攻撃シミュレーションの実行] ---
docker exec red-team python3 /attacks/external_e2e_pivot_attack.py

# --- [検証ログ確認] ---
# enrichment_status の hit/miss 確認
docker logs vector 2>&1 | grep enrichment_status | tail -10

# Redis キーと TTL の確認
docker exec oob_redis redis-cli MONITOR
```

---

## 関連技術・連載記事 (Zenn)

本ラボの構築プロセス、カーネル内部の挙動解像度、実測データ等については Zenn の連載記事にて詳細に解説しています。

* **Phase 1**: [Dockerで挑む次世代電力網防衛（構築編）](https://zenn.dev/schutzz)
* **Phase 2**: [CALDERA複合攻撃 ✕ 境界突破 ✕ 監視破綻実測編](https://zenn.dev/schutzz)
* **Phase 3**: [W3C Trace Context による IT-to-OT 因果追跡編](https://zenn.dev/schutzz)
* **Phase 4-1**: [eBPFセキュア最小実装と基礎研究編](https://zenn.dev/schutzz)
* **Phase 4-ex**: [TCミラーリング再構築](https://zenn.dev/schutzz)
* **Phase 4-2 & 4-3**: [eBPF✕Zeek ハイブリッド実証と不沈空母化](https://zenn.dev/schutzz)
* **Phase 4-4-1**: [仮想電力網環境への組み込みと究極のZeek救出作戦](https://zenn.dev/schutzz)
* **Phase 4-4-2**: [Elasticsearch ✕ Grafana Node Graph Panel 統合](https://zenn.dev/schutzz)

---

## 免責事項 (Ethical Disclaimer)

本リポジトリで提供される検証コードおよびアーキテクチャ構成は、MITRE ATT&CK for ICS マトリクスに基づき SOC/SIEM や可観測性基盤の盲点を安全に検証評価（Adversary Emulation）するための防衛研究目的で作成されたものです。許可されていない第三者のシステムや実環境に対する攻撃・破壊行為への悪用を固く禁じます。

* **License**: [MIT License](LICENSE)
