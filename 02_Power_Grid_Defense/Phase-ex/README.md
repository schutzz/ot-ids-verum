# Phase-ex — OT IDS OOB脱却計画 検証スクリプト一式

計画書 `blog_project/plans/Phase4/Ot ids oob脱却計画.md`（Phase 3〜4）で使用した、DNP3トラフィック生成・検知検証用のスクリプトを集約したディレクトリ。以前は`02_Power_Grid_Defense/`直下や、リポジトリ外のスクラッチ領域に散在していたものを、ブログ執筆・将来の再検証のために整理した。

## 配置と再現方法

`docker-compose.yml`で`cc_scada_master`・`external_attacker`の両コンテナに、このディレクトリ全体を`/phase-ex:ro`として読み取り専用マウントしている。`docker compose up -d`するだけで両コンテナ内にこのディレクトリの全スクリプトが揃う（過去のように`docker cp`で個別に配置する必要はない）。

`external_e2e_pivot_attack.py`のみ、`docker-compose.yml`側で`/attacks/external_e2e_pivot_attack.py`にも別途マウントされている（既存の`/attacks/`配下の他スクリプトとの並び・実行慣習を踏襲するため）。

## ファイル一覧

| ファイル | 役割 |
|---|---|
| `dnp3_frame.py` | DNP3フレーム生成の共通ユーティリティ。`build_dnp3_frame()`（CRC計算込み、Signal5用に`valid_crc=False`で意図的に破壊可能）と`build_dnp3_frame_with_crob()`（Group12 Var1 CROBオブジェクト付き、Signal3/ICSNPP検証用）を提供。全テストスクリプトが依存する |
| `run_test.py` | テスト実行ハーネス。`python3 run_test.py <test_script> <target_src_ip> <container_name>`で、クリーン状態確認→テスト実行→Enrich Policy再実行→Transform同期待機(35秒)→結果サマリ出力、の5ステップを自動化 |
| `test_1_negative_zone.py`〜`test_5_negative_crc.py` | 陰性テスト#1〜5（Signal1〜5がそれぞれ正常運用トラフィックで誤検知しないことの確認） |
| `test_7_positive_zone.py` | 陽性テスト#7（Signal1: ゾーン逸脱単体） |
| `test_8_positive_fc5.py` | 陽性テスト#8（Signal2: 危険FC単体） |
| `test_10_positive_rate.py` | 陽性テスト#10（Signal4: レート異常バースト） |
| `test_11_positive_crc.py` | 陽性テスト#11（Signal5: プロトコル整合性違反） |
| `test_crob_select.py` / `test_crob_operate.py` / `test_crob_direct_operate.py` | CROBオブジェクト実装の検証用（SELECT/OPERATE/DIRECT_OPERATEそれぞれで`dnp3_crob`イベントが発火し`dnp3_control.log`に記録されることを個別確認した際のスクリプト） |
| `generate_sbo_traffic.py` | SELECT(fc=3)→OPERATE(fc=4)の正規SBOシーケンスを送信する、Phase1由来の参照実装 |
| `external_e2e_pivot_attack.py` | 複合テスト#13用。当初はCRCフィールドが丸ごと欠落した構造破綻ペイロードのハードコード値を使っていたが、`dnp3_frame.build_dnp3_frame()`ベースに修正済み。fc=5固定・100接続中10接続のみ`valid_crc=False`にし、Signal2/4/5を意図的に混在させる設計 |

## テスト実施状況

テスト#1〜13の仕様・実行結果は計画書のセクション7を参照。#3・#9（Signal3判定ロジック未実装）と#6・#12（Signal6/EQL未実装）はPhase5待ちで保留中。

## 実行例

```bash
# コンテナ内で直接実行する場合
docker exec cc_scada_master python3 /phase-ex/test_1_negative_zone.py

# run_test.py経由（クリーン確認・結果サマリまで自動化）
cd Phase-ex
python3 run_test.py test_8_positive_fc5.py 10.0.10.10 cc_scada_master
```
