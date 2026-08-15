# OT-IDS Verum 展開マニュアル

> ✅ **この文書はPhase 0〜11完了時点のアーキテクチャを反映しています。**
> 本書は`02_Power_Grid_Defense/`（Signal1〜6・GOOSE/Modbusパープルチーミング）のみを対象とします。
> 旧`01_Facility_Security/`（前作の一部）は前身リポジトリ（[ot-security-lab](https://github.com/schutzz/ot-security-lab)）側にのみ保全されており、本リポジトリからは削除済みです。

---

## 1. 前提条件

* **Docker**: v24.0以上、**Docker Compose**: v2.20以上（Compose V2必須）
* **OS**: 制約なし（Linux/macOS/Windows+Docker Desktop、いずれでも動作確認済み）。旧アーキテクチャで前提としていたeBPF/XDP（カーネル5.15以上、Linux専用）は、既定の起動プロファイルでは**不要**（後述）
* ディスク空き容量：数GB（Elasticsearchの永続ボリューム分。長期稼働させる場合は増える）

## 2. クローンと配置

```bash
git clone https://github.com/schutzz/ot-ids-verum.git
cd ot-ids-verum/02_Power_Grid_Defense
```

## 3. `.env`の作成

`.env`はリポジトリに含まれていません（`.gitignore`対象）。以下の内容で新規作成してください。

```bash
cat > .env <<'EOF'
WEBDIS_HOST_IP=10.0.10.15
ENABLE_OOB=0
EOF
```

* `WEBDIS_HOST_IP`：旧Redis自己申告方式（OOB-context-bind）用。Signal1〜6の判定ロジックには不要だが、`ebpf_tx_agent`（既定では起動しない、後述）が参照するため念のため設定
* `ENABLE_OOB`：`0`で自己申告方式を無効化（Signal1〜6のみで判定）。`1`にすると`red-team`等が旧方式のRedis登録も行うようになる（Precision/Recall評価用、決定事項#20参照）
* `docker-compose.yml`には`otel_collector`というサービスが定義されていますが、これは前作（Splunk Observability Cloud連携）時代の未整理コンポーネントで、Signal1〜6の判定には一切関与しません。`SPLUNK_ACCESS_TOKEN`等の環境変数は**設定不要**です（詳細は9章）

## 4. 起動

```bash
docker compose --profile legacy up -d
```

**`--profile legacy`が必須です。** 付けずに`docker compose up -d`だけ実行すると、Zeek（`zeek_tap`）が起動しません。これは`zeek_tap`が`profiles: [legacy, ebpf_on]`に属しているためです（`ebpf_on`は後述の通り現在は非機能なので使わないでください）。

初回起動時は各コンテナがOSパッケージ・pipパッケージをインストールするため、数分かかります。`docker compose logs -f zeek_tap`等で完了を待ってください。

## 5. Elasticsearchの初期設定（必須）

Signal1〜6の相関ロジック（Index Template・Transform・Enrich Policy・Ingest Pipeline）は、コンテナ起動だけでは作成されません。Elasticsearchが応答するようになったら、以下を実行してください。

```bash
# elasticsearchの起動を待つ
until curl -s localhost:9200 > /dev/null; do sleep 2; done

bash setup_elasticsearch.sh
```

これで以下が作成されます：

| 種別 | 名前 | 役割 |
|---|---|---|
| Index Template | `ot_logs_template` | `ot-logs-*`の主要フィールドを`keyword`型に固定（先に登録しないと既存indexには遡って適用されない） |
| Transform | `last_read_per_src` | Signal3判定用、`src_ip`ごとの最新READ時刻を集約 |
| Transform | `ot_signal_correlation` | Signal2/3/4/5/6の観測結果を`src_ip`単位で`ot-detection-results`に合算 |
| Enrich Policy | `last_read_lookup_policy` | Signal3判定ロジックが参照するREAD実績のルックアップ |
| Enrich Policy | `detection_lookup_policy` | Grafana反映用の検知結果ルックアップ |
| Ingest Pipeline | `dnp3_control_sbo_check` | Signal3（SBOバイパス）本体の判定ロジック |
| Ingest Pipeline | `topology_node_enrich` | Node Graph用ノードへの検知結果反映 |

以降は`es-enrich-refresher`コンテナが60秒間隔でEnrich Policyを自動更新し続けます（手動`_execute`は不要）。

## 6. 動作確認

**Grafana**（http://localhost:3000 、admin/admin）：ダッシュボードは`grafana/provisioning`から自動読み込みされるため、追加設定は不要です。

**検知の疎通確認**：`Phase-ex/`にテストスクリプト一式があります。

```bash
docker exec cc_scada_master python3 /phase-ex/run_test.py test_1_negative_zone.py 10.0.10.10 cc_scada_master
```

正常に動作していれば、クリーン状態確認→送信→`ot-detection-results`への反映まで自動で行われ、結果サマリが表示されます。個々のテストスクリプトの一覧は`Phase-ex/README.md`を参照してください。

## 7. shadow modeについて

既定では`SHADOW_MODE=false`（`vector`サービスの環境変数）になっており、判定結果がGrafana上で赤（危険）として表示されます。判定ロジックの検証だけ行い、可視化には反映させたくない場合は`SHADOW_MODE=true`に変更して`docker compose --profile legacy up -d --force-recreate vector`してください。

## 8. GOOSE/Modbus検知（Phase 8/9、オプション）

`sub_a_ied_01`/`sub_a_ied_02`（GOOSE）・`sub_b_plc_01`（Modbus）・`goose-anomaly-sidecar`・`goose-spicy-sidecar`は、`--profile legacy`に含まれるため既定で起動します。これらはSignal1〜6の相関エンジン（`ot_signal_correlation`）には統合されておらず、それぞれ独立したindex（`ot-logs-goose-*`等）に書き込まれる別系統の検知です（詳細はREADME参照）。

## 9. 既知の制限・トラブルシューティング

* **`ebpf_on`プロファイルは使わないでください**：`ebpf_agent`/`ebpf_tx_agent`は、`network_mode: host`が指すインターフェースがホスト自体のプライマリNICであり、ラボのDockerブリッジ内トラフィックに構造的に到達できないため、起動しても常にDROP/PASSカウンタが0のまま機能しません（技術的負債#6、正式に退役方針）。Signal1〜6・GOOSE・Modbusいずれの検知もeBPFに依存しません
* **`otel_collector`は無視してください**：前作のSplunk連携時代の未整理コンポーネントです。起動はしますが送信先（Splunk）の認証情報が無いため送信に失敗するだけで、実害はありません。将来的に`docker-compose.yml`から削除予定です
* **Suricataがアラートを出さない場合**：まれに、AF_PACKETキャプチャがプロミスキャスモードで開始されないことがあります（`suricata.yaml`の`promisc: yes`はAF_PACKETソケット自体の設定であり、OS/カーネル側の`ip link`のプロミスキャスフラグとは別物）。`docker exec suricata_ids ip link show eth0`で`PROMISC`が付いていない場合は`docker exec suricata_ids ip link set eth0 promisc on`を実行してください（コンテナ再作成のたびに揮発します）
* **CC_LANミラーリングが機能しない場合**：`wan_router`の起動直後に`setup_mirror.sh`が実行されるため通常は自動で解決しますが、`docker exec wan_router tc -s filter show`で4インターフェース（WAN/SUB_B/CC_LAN/SUB_A）全てに`mirred egress mirror`が設定されているか確認できます

## 免責事項 (Ethical Disclaimer)

本リポジトリで提供される検証コードおよびアーキテクチャ構成は、MITRE ATT&CK for ICS マトリクスに基づき SOC/SIEM や可観測性基盤の盲点を安全に検証評価（Adversary Emulation）するための防衛研究目的で作成されたものです。許可されていない第三者のシステムや実環境に対する攻撃・破壊行為への悪用を固く禁じます。
