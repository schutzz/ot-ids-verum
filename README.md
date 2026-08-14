# OT-IDS Verum: 自己申告に頼らないOT/ICS侵入検知への挑戦

[![Status: Work In Progress](https://img.shields.io/badge/Status-Work%20In%20Progress-orange.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Architecture: Zeek+Suricata+Vector+Elasticsearch](https://img.shields.io/badge/Architecture-Zeek%20%2B%20Suricata%20%2B%20Vector%20%2B%20Elasticsearch-blue.svg)]()

> ⚠️ **このリポジトリは現在進行中の作業です（Work In Progress）。**
> まだ完成形ではなく、実装・検証・設計変更が継続的に行われています。README・コード・ドキュメント間で記述が一時的に食い違っている箇所がある可能性があります。

---

## このリポジトリは何か

[`ot-security-lab`](https://github.com/schutzz/ot-security-lab)（Phase 1〜4、Docker上の広域分散スマートグリッド構築、W3C Trace Context によるIT-to-OT因果追跡、eBPF✕Zeekハイブリッド防衛）の続編にあたるプロジェクトです。ただし単なる機能追加ではなく、**検知手法そのものを問い直す方法論の転換**を行っています。

### なぜ作り直しているのか

`ot-security-lab` で構築した検知基盤は、突き詰めると「攻撃者（＝検証を行う自分自身）が Redis に `trace_id` を自己申告し、それを Vector が照合できたら『攻撃だ』と判定する」という仕組みに終始していました。攻撃者が自己申告するという前提を置かなければ機能しない検知は、本物の攻撃者を検知できるのか——この違和感が、本リポジトリの出発点です。

`ot-security-lab` は記事の記述と一致する状態（[`6780791`](https://github.com/schutzz/ot-security-lab/commit/6780791)相当）で凍結し、そこから先の「自己申告に頼らず、Zeek・Suricata・eBPFが観測した客観的事実だけで検知する」という新しい方法論の実装を、このリポジトリで別系統として進めています。

## 現在の検知アーキテクチャ（Signal1〜6）

Redis自己申告方式は「検知シグナル」としての役割から外し、Signal1〜6のPrecision/Recall評価用の正解ラベル源へと位置づけを転換しました。本番の判定ロジックは、以下6つの客観的シグナルのOR合成のみで構成されています。

| Signal | 内容 | 検出手段 |
|---|---|---|
| 1 | ゾーン逸脱 | 自前allowlist（Vector VRL） |
| 2 | 危険ファンクションコード | Suricata独自ルール |
| 3 | SBOバイパス（READ実績なしでの制御） | ICSNPP-DNP3 + Elasticsearch Transform/Enrich Policy |
| 4 | レート異常（バースト接続） | Zeek SumStats |
| 5 | プロトコル整合性違反（CRC不正等） | Zeek `weird.log` |
| 6 | IT→OTキルチェーン相関 | Elasticsearch EQL（HTTPピボット→DNP3制御のsequence検知） |

判定結果は Elasticsearch → Grafana（Node Graph / Signal別内訳 / Precision-Recall推移）で可視化しています。

Signal1〜6とは別に、GOOSE（IEC 61850）・Modbusについても独立したsidecar/検知ロジック（後述のPhase8・9）を実装していますが、こちらは`ot_signal_correlation`（Signal1〜6の統合相関エンジン）には統合しておらず、位置づけは仮称のSignal7・8です。

## 現在の到達点

- **Phase 0〜4**: 検知ロジック（Signal1〜6）の実装・shadow mode検証（13本の陰性/陽性/複合テストによる剥離試験）
- **Phase 5**: Signal3（SBOバイパス）・Signal6（IT→OTキルチェーン）の相関基盤実装
- **Phase 6**: shadow mode解除・Redis役割転換・Precision/Recall実証
- **Phase 7**: Grafanaダッシュボードの全面見直し（誤ったフィールド命名規約、パネル設定のハードコード参照、datasource設定ミス等、可視化層に潜んでいた複数のバグを是正）
- **Phase 8**: パープルチーミングサイクル（GOOSE/IEC 61850・Modbus）。既存OSSの成熟度によって着地点が異なることを実証——GOOSEは簡易sidecar検知の構造的限界（MACなりすまし耐性の欠如）を明示、Modbusは最後までSuricata/Vector側の検知実装を完走
- **Phase 9**: 未知プロトコルへの対応。既存パーサーが薄いGOOSEを題材に、Spicyで自作パーサーを実装し、ペイロード内容（StNum/SqNum）に基づく異常検知を独立sidecar方式（Signal7）で実現
- **Phase 10**: バーストフラッド耐性の実測。前作（PowerGrid）で確認された高負荷時のパケットロス・CPU飽和が、現行ラボの構成・規模では再現しないことを実測で確認し、eBPF Vanguardの実装は見送り
- **Phase 11**: 総合攻撃シナリオの実証とPDCAサイクルの証明（進行中）。個々のシグナルの正しさではなく、検知結果を人間が読み解けるかという運用可能性を検証する最終フェーズ

実装過程では、CRCの1バイトからElasticsearchのAPI仕様の1行まで、想定より遥かに多くの落とし穴を踏んでいます。その一つひとつの切り分け・検証の記録は、以下のZenn連載記事で追っていただくのが一番早いです。

## 記事はこちらで随時更新しています

👉 **[https://zenn.dev/schutzz](https://zenn.dev/schutzz)**

このリポジトリのコード単体よりも、「なぜその実装に至ったか」「何を切り分けて何が分かったか」という過程そのものが本編です。詳しくは記事を見てもらえると嬉しいです。

## 元プロジェクト（Phase 1〜4）

`ot-security-lab` は本プロジェクトの前身であり、独立したリポジトリとして凍結・保全されています。

👉 **[https://github.com/schutzz/ot-security-lab](https://github.com/schutzz/ot-security-lab)**

## 免責事項 (Ethical Disclaimer)

本リポジトリで提供される検証コードおよびアーキテクチャ構成は、MITRE ATT&CK for ICS マトリクスに基づき SOC/SIEM や可観測性基盤の盲点を安全に検証評価（Adversary Emulation）するための防衛研究目的で作成されたものです。許可されていない第三者のシステムや実環境に対する攻撃・破壊行為への悪用を固く禁じます。

* **License**: [MIT License](LICENSE)
