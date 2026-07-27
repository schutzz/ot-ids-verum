---
title: "第3章：Modbus/TCP センサーエミュレータ開発（前編）"
---

# 第3章：Modbus/TCP センサーエミュレータ開発（前編）

---

前回は、Docker Composeを用いてOT領域のネットワーク分離基盤（L2分離）を構築し、HMIとなるNode-REDを固定IPで起動させました。

今回は、Rustを用いてModbus/TCPプロトコルを話す仮想センサー機器（エミュレータ）をゼロから開発していきます。

---

## 1. センサーエミュレータの要件定義と目的

開発に入る前に、今回作成するModbus/TCP仮想センサーの要件を定義します。

* **目的**: 外部ライブラリを一切使用せず（Rust `std` のみ）、生バイトを直接操作するModbus/TCP仮想センサーの開発
* **通信**: TCP `0.0.0.0:502`（マルチスレッド接続対応）
* **対象機能**: Function Code `0x04` (Read Input Registers) のみサポート
* **データ規格**: 16bit幅 / ビッグエンディアン変換 (`.to_be_bytes()`)
* **レジスタ構成**: 
  * レジスタ 0: 侵入検知センサー（`0x0001` = ON）として振る舞う
  * レジスタ 1: 温度センサー（`255` = 25.5℃）として振る舞う
* **制約事項**: 専用クレート（ライブラリ）の使用禁止。不正パケット受信時はパニックを起こさず、生バイトをログにダンプする。

---

### なぜ外部ライブラリを使用しないのか？

#### ① プロトコル内部のバイナリ構造を完全に掌握するため
既存のModbusライブラリ（`tokio-modbus` 等）を使用すると、パケットの組み立てやヘッダ処理が隠蔽（ブラックボックス化）されてしまいます。TCPソケットの生バイト列（`[u8]`）から手動でパース・構築することで、MBAPヘッダやエンディアン変換といったModbus/TCPの物理的・バイナリ的構造を根本から理解・制御することができます。

#### ② 不正パケットやエラー時の挙動を自在にコントロール・可視化するため
一般的なライブラリでは、規格外の不正なパケットが届いた際に自動で例外処理や切断処理が行われてしまいます。今回はセキュリティや解析の学習も兼ねているため、不正パケットも生バイトのまま標準出力にダンプ・解析し、ログ分析に活かせるようにします。

---

### 💡 補足：自作しない場合の実務における代案（Python・ライブラリ・既存ツール）

本書ではModbus/TCPのMBAPヘッダーやエンディアン変換、バイナリ構造を根本から解剖・学習するため、あえてRust標準ライブラリ（生ソケット）によるゼロからの手作り実装を行っています。

しかし、**実際の現場や実務プロジェクトにおいて、プロトコルスタックをゼロから手作りにすることは稀であり、以下のような既存ライブラリやツールを活用するのが主流かつ圧倒的に効率的です。**

#### 代案1: Python + `pymodbus`（最も標準的で主流なアプローチ）
Pythonの業界標準ライブラリ `pymodbus` を利用すれば、わずか数10行のコードで高機能なModbus/TCPサーバー（エミュレータ）を構築できます。

```python
# pymodbus を利用した Modbus/TCP サーバーの簡易例
from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext

# 入力レジスタ (Input Registers: FC 0x04) のデータブロックを作成
# アドレス 0x00 に 0x0001 (ON)、アドレス 0x01 に 255 (25.5℃) を初期配置
store = ModbusSlaveContext(
    ir=ModbusSequentialDataBlock(0, [0x0001, 255])
)
context = ModbusServerContext(slaves=store, single=True)

print("[+] Starting Modbus/TCP Server via pymodbus on 0.0.0.0:502...")
StartTcpServer(context=context, address=("0.0.0.0", 502))
```

* **メリット**: 非同期処理（`asyncio`）への対応、主要ファンクションコードの全サポート、各種エラー応答の自動生成が数行で完了します。

#### 代案2: Python + `Scapy`（パケット生成・ファジング用途）
パケット解析・生成ライブラリ `Scapy` を使用すれば、特定のフィールドだけを意図的に書き換えた不正パケット（ファジングパケット）の送信やプロトタイプ検証が容易に行えます。

#### 代案3: GUIシミュレータ（Modbus Pal / ModSim32 / Diagnostic tools）
プログラムを一切書かず、GUI画面上でレジスタ値の変更や接続テストを行いたい場合は、**Modbus Pal**（Javaベースのクロスプラットフォームシミュレータ）や **ModSim32** 等のフリーソフト/商用ツールを利用するのが一般的です。

---

## 2. Rustによるソースコードの実装

要件定義に沿って、Rustで実装したメインプログラム（`src/main.rs`）が以下になります。

```rust
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

fn handle_client(mut stream: TcpStream) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    println!("[+] New connection from {}", peer_addr);

    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                println!("[-] Connection closed by {}", peer_addr);
                break;
            }
            Ok(n) => {
                println!("\n[>] Raw packet received ({} bytes): {:02X?}", n, &buf[..n]);

                if n < 12 {
                    eprintln!("[!] Packet too short for Modbus/TCP: {} bytes", n);
                    continue;
                }

                // --- MBAP Header Parsing ---
                let trans_id = u16::from_be_bytes([buf[0], buf[1]]);
                let proto_id = u16::from_be_bytes([buf[2], buf[3]]);
                let length   = u16::from_be_bytes([buf[4], buf[5]]);
                let unit_id  = buf[6];

                println!("[MBAP] TransID=0x{:04X}, ProtoID=0x{:04X}, Length={}, UnitID={}", 
                         trans_id, proto_id, length, unit_id);

                // --- PDU Parsing ---
                let func_code  = buf[7];
                let start_addr = u16::from_be_bytes([buf[8], buf[9]]);
                let quantity   = u16::from_be_bytes([buf[10], buf[11]]);

                println!("[PDU]  FC=0x{:02X}, StartAddr=0x{:04X}, Quantity={}", 
                         func_code, start_addr, quantity);

                if func_code != 0x04 {
                    eprintln!("[!] Unsupported Function Code: 0x{:02X}", func_code);
                    continue;
                }

                // --- Build Modbus Response ---
                let byte_count = (quantity * 2) as u8;
                let mut response = Vec::new();

                // 1. MBAP Header Reflection
                response.extend_from_slice(&trans_id.to_be_bytes());
                response.extend_from_slice(&proto_id.to_be_bytes());
                response.extend_from_slice(&(3 + byte_count as u16).to_be_bytes());
                response.push(unit_id);

                // 2. PDU Response
                response.push(func_code);
                response.push(byte_count);

                // 3. Register Data
                for i in 0..quantity {
                    let reg_addr = start_addr + i;
                    let val: u16 = match reg_addr {
                        0 => 0x0001, // Register 0: Intrusion Detection Sensor (0x0001 = ON)
                        1 => 255,    // Register 1: Temperature Sensor (25.5 ℃ scaled x10)
                        _ => 0x0000,
                    };
                    response.extend_from_slice(&val.to_be_bytes());
                }

                println!("[>] Responding with {} bytes", response.len());
                println!("    Response raw bytes hex dump: {:02X?}", response);

                if let Err(e) = stream.write_all(&response) {
                    eprintln!("[!] Write error to {}: {}", peer_addr, e);
                    break;
                }
            }
            Err(e) => {
                eprintln!("[!] Read error from {}: {}", peer_addr, e);
                break;
            }
        }
    }
}

fn main() -> std::io::Result {
    let addr = "0.0.0.0:502";
    println!("==================================================");
    println!("   Modbus/TCP Sensor Emulator (Rust Raw Socket)   ");
    println!("   Listening on: {}", addr);
    println!("==================================================");

    let listener = TcpListener::bind(addr)?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    handle_client(stream);
                });
            }
            Err(e) => {
                eprintln!("[!] Connection accept error: {}", e);
            }
        }
    }
    Ok(())
}
```

---

### プログラムの主な処理ブロック解説

* **`TcpListener` による待ち受け**：ポート502で接続を監視し、接続ごとにスレッド（`thread::spawn`）を立ち上げて非同期にクライアントに対応します。
* **MBAPヘッダのパース**：先頭7バイトからトランザクションID・プロトコルID・データ長・ユニットIDをデコードします。
* **PDUの解析とレスポンス構築**：ファンクションコード `0x04` を検出後、指定されたレジスタ数に応じてデータをビッグエンディアン（`.to_be_bytes()`）に変換して返答します。

---

## 3. プロジェクト設定とフォルダ構成

Rustのプロジェクト設定ファイルである `Cargo.toml` は以下のようになります。

```toml
[package]
name = "sensor-emulator"
version = "0.1.0"
edition = "2021"

[dependencies]
```

* **`[package]`**: プロジェクト名やRustエディション（2021）を定義します。
* **`[dependencies]`**: 外部ライブラリを一切使わないため完全に空としています。

これらの作成が終わった段階で、プロジェクトのディレクトリ構造は以下のようになります。

```
ot-sensor-emulator/
├── Cargo.toml
└── src/
    └── main.rs
```

---

## 4. ビルドと通信テストの実行

ソースコードが完成したので、実際にビルドして実行してみます。

![](https://static.zenn.studio/user-upload/7074b0d1b3bc-20260720.png)

無事にSensor Emulatorが起動し、OSのネットワークスタックに対して「待ち受け（Listening）」を確立した状態になりました。

次に、別ターミナルを開き、`nc`（netcat）コマンドを用いてエミュレータへ命令データ（生バイト）を送信し、返ってきた結果を表示させます。

```bash
echo -ne "\x00\x01\x00\x00\x00\x06\x01\x04\x00\x00\x00\x02" | nc -w 1 127.0.0.1 502 | xxd
```

![](https://static.zenn.studio/user-upload/9fdc390000e7-20260720.png)

送信後、ターミナルには以下の応答結果が表示されました。

```
00000000: 0001 0000 0007 0104 0400 0100 ff             .............
```

---

### 応答結果（xxd出力）の読み解き方

* **`00000000:`**：`xxd` コマンドが付与したメモリオフセット（アドレスの開始位置）の表示です。
* **`.............`**：右側のドット群はASCII印字可能文字の表示領域です。

続いて、実際のパケットの中身を解剖していきます。

#### MBAPヘッダ (先頭7バイト)

* **`0001`** (Offset 0x00 - 0x01): **Transaction Identifier** (リクエストとレスポンスを紐付ける識別子。送信リクエストの値をそのまま反射)
* **`0000`** (Offset 0x02 - 0x03): **Protocol Identifier** (0x0000 = Modbusプロトコル)
* **`0007`** (Offset 0x04 - 0x05): **Length** (残りデータ長。Unit ID 1B ＋ PDU 6B ＝ 7バイト)
* **`01`** (Offset 0x06): **Unit Identifier** (スレーブ機器ID = 1号機)

#### PDU (Protocol Data Unit - 残り6バイト)

* **`04`** (Offset 0x07): **Function Code** (`0x04` = Read Input Registers 正常応答)
* **`04`** (Offset 0x08): **Byte Count** (続くデータの合計バイト数。2レジスタ分で4バイト)
* **`0001`** (Offset 0x09 - 0x0A): **データ1** (レジスタ0の返り値：侵入検知ON)
* **`00ff`** (Offset 0x0B - 0x0C): **データ2** (レジスタ1の返り値：25.5℃)

エミュレータがソケットから生バイト列を正しくパースし、Modbus/TCPの仕様通りに1バイトのオフセットズレもエンディアンの崩れもなくバイナリパケットを構築して応答したことが証明されました。

---

## 5. エミュレータ動作ログの完全解析

エミュレータ側のターミナルを確認すると、内部の動作ログが以下の様に出力されています。

![](https://static.zenn.studio/user-upload/99efd7def0d5-20260720.png)

ログのトレース解説は以下の通りです。

### ① コネクションの確立（TCPハンドシェイク）
```
[+] New connection from 127.0.0.1:60450
```
* **内部挙動**: ポート502で待機中にクライアント（`nc`）からSYNパケットが到達し、TCPの3ウェイ・ハンドシェイクが完了しました。

### ② 受信バッファからの読み出しと物理バイトのダンプ
```
[>] Raw packet received (12 bytes): [00, 01, 00, 00, 00, 06, 01, 04, 00, 00, 00, 02]
```
* **内部挙動**: 入力された12バイトの生データが、1バイトの欠損もなくエミュレータのメモリ空間に展開されています。

### ③ MBAPヘッダの構造体マッピング（ビッグエンディアン解析）
```
[MBAP] TransID=0x0001, ProtoID=0x0000, Length=6, UnitID=1
```
* **内部挙動**: 先頭7バイトから各フィールドをビッグエンディアン（`u16::from_be_bytes`）で正確にデコードしています。
  * `[00, 01]` → `TransID = 0x0001`
  * `[00, 00]` → `ProtoID = 0x0000`
  * `[00, 06]` → `Length = 6`
  * `[01]` → `UnitID = 1`

### ④ PDU（Protocol Data Unit）の解析
```
[PDU]  FC=0x04, StartAddr=0x0000, Quantity=2
```
* **内部挙動**: `FC=0x04`（Read Input Registers）、`StartAddr=0x0000`（開始アドレス0番地）、`Quantity=2`（2レジスタ要求）を特定しました。

### ⑤ レスポンスバッファの構築と送出
```
[>] Responding with 13 bytes
    Response raw bytes hex dump: [00, 01, 00, 00, 00, 07, 01, 04, 04, 00, 01, 00, FF]
```
* **内部挙動**: 送信バッファを構築し、13バイトのバイナリパケットをネットワークへ送出しました。

### ⑥ ソケットの破棄（TCPティアダウン）
```
[-] Connection closed by 127.0.0.1:60450
```
* **内部挙動**: クライアント側の切断を検知し、ソケットのFD（ファイルディスクリプタ）を安全にクローズしました。

---

## 6. おわりに

今回は、外部ライブラリを一切使わず、Rustの標準ライブラリのみで生バイトを直接操作するModbus/TCPセンサーエミュレータを実装し、その低レイヤーな挙動を解析しました。

次回（後編）は、このエミュレータに状態保持（RAM）とFC `0x05`（Write Single Coil）による書き込み機能を拡張し、よりリアルなOT制御機器へと昇華させていきます。
