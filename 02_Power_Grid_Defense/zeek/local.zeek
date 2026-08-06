# ==============================================================================
# 自家製Dragos 次世代電力網防衛：Zeek インダストリアル設定
# ==============================================================================

# Use built-in Zeek protocol support instead of package-based extensions.
# `@load packages` fails when package paths are not initialized in this image.
@load base/frameworks/cluster

# capture_loss.log 有効化 (Phase 2-1 再演用: Zeek のパケットドロップ率を記録)
# zeekctl クラスタ構成でも Worker → Logger 経由で capture_loss.log に書き出される
@load policy/misc/capture-loss


# AF_PACKET プラグインのロード
redef AF_Packet::fanout_id = 23;

# OTプロトコル (DNP3, Modbus等) アナライザの有効化
@load base/protocols/conn
@load base/protocols/dnp3
@load base/protocols/snmp

# OpenTelemetry インストラクション対応向け JSON 構成出力化
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;
redef ignore_checksums = T;

# 問題②対策 (アプローチ1): DNP3ログバッファリング無効化
# バースト攻撃時のZeek内部バッファ滞留(0.5〜2秒)を解消し、
# パケット解析直後にディスクへ即フラッシュさせる。
event zeek_init() &priority=-5
    {
    Log::set_buf(DNP3::LOG, F);
    }
