# ==============================================================================
# 自家製Dragos 次世代電力網防衛：Zeek インダストリアル設定
# ==============================================================================

@load packages
@load base/frameworks/cluster

# AF_PACKET プラグインのロード
redef AF_Packet::fanout_id = 23;

# OTプロトコル (DNP3, Modbus等) アナライザの有効化
@load icsnpp/dnp3
@load icsnpp/modbus

@load base/frameworks/notice
@load base/protocols/conn
@load base/protocols/dnp3
@load base/protocols/snmp

# OpenTelemetry インストラクション対応向け JSON 構成出力化
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;
redef ignore_checksums = T;
