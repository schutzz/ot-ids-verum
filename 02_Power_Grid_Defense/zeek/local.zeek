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
# Phase8-2(Modbusサイクル): コメントには当初から「Modbus等」とあったが、
# 実際には@load base/protocols/modbusが漏れていた(zeek -NNではANALYZER_MODBUSが
# enabledと出るためC++/Binpacアナライザ自体はデフォルト有効だが、それは
# modbus.logを書き出すスクリプト側(Modbus::LOGストリーム定義)のロードとは
# 別レイヤーの話であり、確認なしに「動く」と即断すべきではない、という判断で追加)
@load base/protocols/conn
@load base/protocols/dnp3
@load base/protocols/modbus
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

@load packages

@load base/frameworks/sumstats
@load base/frameworks/notice

export {
    redef enum Notice::Type += {
        OT_IDS::Rate_Anomaly
    };
}

event zeek_init() {
    local r1: SumStats::Reducer = [$stream="ot.dnp3.connect", $apply=set(SumStats::SUM)];

    SumStats::create([
        $name = "ot-dnp3-rate-check",
        $epoch = 10sec,
        $reducers = set(r1),
        $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
            return result["ot.dnp3.connect"]$sum;
        },
        $threshold = 2.0,
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([$note=OT_IDS::Rate_Anomaly,
                    $msg=fmt("Rate anomaly: %s -> burst connections", key$str),
                    $sub=fmt("%.0f connections in window", result["ot.dnp3.connect"]$sum),
                    $src=to_addr(key$str),
                    $identifier=key$str]);
        }
    ]);
}

event connection_established(c: connection) {
    if (c$id$resp_p == 20000/tcp) {
        print fmt("DEBUG: observed connection from %s", c$id$orig_h);
        SumStats::observe("ot.dnp3.connect",
            [$str=cat(c$id$orig_h)],
            [$num=1]);
    }
}
