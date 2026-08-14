"""
Phase8-2(Modbusサイクル 8-0/8-1相当): 疑似PLC(Modbus TCPサーバー)。

sub_b_lan(10.0.30.0/24)に、既存のDNP3ベースのsub_b_rtu_hmiとは別ベンダーの
Modbus対応PLCという想定で配置する。GOOSEサイクルのsub_a_ied_01(正常系送信元)
に相当する、Modbusサイクルの最初の疎通確認対象。

現時点ではサーバーの疎通確認(modbus.logの生成確認)が目的のため、保持コイル・
レジスタの初期値は全てゼロの最小構成。異常系(GOOSE poisoningのような書き込み
改ざん等)は8-1完了後、別スクリプトとして追加する想定(sub_a_ied_02の
send_goose_poison.pyと同じ「別スクリプトとして追加」パターンを踏襲)。
"""

import logging

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("modbus_plc")


def build_context() -> ModbusServerContext:
    # di=discrete inputs, co=coils, hr=holding registers, ir=input registers
    # 全て100アドレス分、初期値ゼロで確保(疎通確認用の最小構成)
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, [0] * 100),
        ir=ModbusSequentialDataBlock(0, [0] * 100),
    )
    return ModbusServerContext(slaves=store, single=True)


if __name__ == "__main__":
    log.info("[+] Starting Modbus TCP PLC server on 0.0.0.0:502 ...")
    context = build_context()
    StartTcpServer(context=context, address=("0.0.0.0", 502))
