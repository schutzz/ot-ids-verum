---
title: "第4章：Modbus/TCP センサーエミュレータ開発（後編）"
---

# 第4章：Modbus/TCP センサーエミュレータ開発（後編）

---

前回作成したRust製センサーエミュレータには「メモリ（状態）の保持がない」「書き込み系コマンドが未実装である」という致命的な不備がありました。

今回は、OTシステムの本質である「状態管理（RAM）」と「メモリ汚染の土台」を実装するため、エミュレータのアーキテクチャを大幅に修正・アップデートしていきます。

---

## 1. 浮き彫りになった3つの致命的不備と改修方針

前回のステートレス（状態を持たない）な実装のままでは、現実のOT環境で発生するサイバー攻撃や制御の変化を検証することができません。エミュレータが抱えていた3つの構造的欠陥と、その処置方針を定義します。

| 不備 | 現状の挙動 | あるべき姿 |
| :--- | :--- | :--- |
| **1. メモリ（状態）保持なし** | リクエストの度にハードコード値 `0x0001` を即席生成して返すだけ | 永続的な RAM 空間を持ち、状態を保持・参照する |
| **2. FC 0x05 未実装** | `0x04` 以外は全て無視する | Write Single Coil を受け付け、メモリを書き換える |
| **3. Coil vs Register の不一致** | 16bit幅の Input Register 前提のデータ構造 | 1bit 単位の Coil（ON/OFF 接点）を管理する構造が別途必要 |

---

### 改修に向けたロードマップ

* **Step 1：共有メモリ空間の設計・導入（最優先）**
  * `Arc<Mutex<[u8; 65536]>>` を用いてプロセス全体で共有される64KBの仮想RAM空間をアロケート。各スレッドから排他制御つきでアクセスできるようにし、既存のFC 0x04もこのメモリから読み出す方式に統合します。
* **Step 2：FC 0x05 (Write Single Coil) の実装**
  * 攻撃シナリオの核心となる書き込みコマンド。指定されたアドレスのCoilを 0 または 1 に強制書換（メモリ汚染）し、リクエストのエコーバックとグラフィカルな汚染ログを出力します。
* **Step 3：FC 0x01 (Read Coils) の実装**
  * 書き換えたCoilの状態をHMI側から正しく観測するため、8個のCoilを1バイトに詰めるLSB firstのビットパッキング処理を実装します。
* **Step 4：既存 FC 0x04 のメモリ連動化**
  * Input Registerも共有メモリから動的に読み出す方式に統一し、一貫性のあるメモリアーキテクチャへ昇華させます。

---

## 2. 状態保持・メモリ汚染対応版 Rust ソースコード

改修をすべて施した、ステートフル対応の完全版ソースコード（`src/main.rs`）です。

```rust
use std::io::{Read, Write, stdout};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Docker環境ではstdoutがフルバッファリングされるため、
/// 出力の都度フラッシュを行うマクロを定義する。
macro_rules! log {
    ($($arg:tt)*) => {{
        println!($($arg)*);
        let _ = stdout().flush();
    }};
}

macro_rules! log_err {
    ($($arg:tt)*) => {{
        eprintln!($($arg)*);
        let _ = stdout().flush();
    }};
}

// ==========================================
// 物理メモリ空間の定義
// ==========================================
const MEMORY_SIZE: usize = 65536;
const COIL_BASE: usize = 0x0000;
const INPUT_REGISTER_BASE: usize = 0x1000;

type SharedMemory = Arc<Mutex<[u8; MEMORY_SIZE]>>;

/// 共有メモリを初期化し、デフォルトのセンサー値を書き込む
fn init_memory() -> SharedMemory {
    let mut memory = [0u8; MEMORY_SIZE];

    // --- Coil 領域の初期値 ---
    // Coil 0: 侵入検知センサー (初期値: ON = 1)
    memory[COIL_BASE] = 1;

    // --- Input Register 領域の初期値 ---
    let intrusion: u16 = 0x0001;
    let bytes = intrusion.to_be_bytes();
    memory[INPUT_REGISTER_BASE] = bytes[0];
    memory[INPUT_REGISTER_BASE + 1] = bytes[1];

    let temperature: u16 = 0x00FF; // 25.5 ℃ (x10 scaled)
    let bytes = temperature.to_be_bytes();
    memory[INPUT_REGISTER_BASE + 2] = bytes[0];
    memory[INPUT_REGISTER_BASE + 3] = bytes[1];

    Arc::new(Mutex::new(memory))
}

// ==========================================
// MBAPヘッダ構造体 (手動パース用)
// ==========================================
struct MbapHeader {
    transaction_id: u16,
    protocol_id: u16,
    _length: u16,
    unit_id: u8,
}

impl MbapHeader {
    fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 7 {
            return None;
        }
        Some(MbapHeader {
            transaction_id: u16::from_be_bytes([buf[0], buf[1]]),
            protocol_id: u16::from_be_bytes([buf[2], buf[3]]),
            _length: u16::from_be_bytes([buf[4], buf[5]]),
            unit_id: buf[6],
        })
    }

    fn build_response(&self, payload_length: u16) -> [u8; 7] {
        let mut header = [0u8; 7];
        header[0..2].copy_from_slice(&self.transaction_id.to_be_bytes());
        header[2..4].copy_from_slice(&0u16.to_be_bytes());
        header[4..6].copy_from_slice(&payload_length.to_be_bytes());
        header[6] = self.unit_id;
        header
    }
}

// ==========================================
// FC 0x01: Read Coils
// ==========================================
fn handle_read_coils(
    mbap: &MbapHeader,
    buf: &[u8],
    memory: &SharedMemory,
) -> Vec<u8> {
    let start_addr = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let quantity = u16::from_be_bytes([buf[10], buf[11]]) as usize;

    log!(
        "    [FC 0x01] Read Coils: StartAddr=0x{:04X}, Quantity={}",
        start_addr, quantity
    );

    let byte_count = (quantity + 7) / 8;
    let mut coil_bytes = vec![0u8; byte_count];

    let mem = memory.lock().unwrap();
    for i in 0..quantity {
        let addr = COIL_BASE + start_addr + i;
        let bit_val = if addr < MEMORY_SIZE { mem[addr] } else { 0 };
        if bit_val != 0 {
            let byte_idx = i / 8;
            let bit_idx = i % 8;
            coil_bytes[byte_idx] |= 1 << bit_idx;
        }
    }

    let payload_len = 1 + 1 + byte_count as u16;
    let mut response = Vec::new();
    response.extend_from_slice(&mbap.build_response(payload_len));
    response.push(0x01); // Function Code
    response.push(byte_count as u8);
    response.extend_from_slice(&coil_bytes);
    response
}

// ==========================================
// FC 0x04: Read Input Registers
// ==========================================
fn handle_read_input_registers(
    mbap: &MbapHeader,
    buf: &[u8],
    memory: &SharedMemory,
) -> Vec<u8> {
    let start_addr = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let quantity = u16::from_be_bytes([buf[10], buf[11]]).min(125) as usize;

    log!(
        "    [FC 0x04] Read Input Registers: StartAddr=0x{:04X}, Quantity={}",
        start_addr, quantity
    );

    let byte_count = (quantity * 2) as u8;

    let mem = memory.lock().unwrap();
    let mut reg_data = Vec::with_capacity(quantity * 2);
    for i in 0..quantity {
        let offset = INPUT_REGISTER_BASE + (start_addr + i) * 2;
        if offset + 1 < MEMORY_SIZE {
            reg_data.push(mem[offset]);
            reg_data.push(mem[offset + 1]);
        } else {
            reg_data.push(0);
            reg_data.push(0);
        }
    }

    let payload_len = 1 + 1 + byte_count as u16;
    let mut response = Vec::new();
    response.extend_from_slice(&mbap.build_response(payload_len));
    response.push(0x04);
    response.push(byte_count);
    response.extend_from_slice(&reg_data);
    response
}

// ==========================================
// FC 0x05: Write Single Coil (メモリ汚染)
// ==========================================
fn handle_write_single_coil(
    mbap: &MbapHeader,
    buf: &[u8],
    n: usize,
    memory: &SharedMemory,
) -> Vec<u8> {
    let coil_addr = u16::from_be_bytes([buf[8], buf[9]]) as usize;
    let raw_value_hi = buf[10];
    let raw_value_lo = buf[11];

    let new_state: u8 = if raw_value_hi == 0xFF && raw_value_lo == 0x00 {
        1
    } else {
        0
    };

    let target_addr = COIL_BASE + coil_addr;
    let mut mem = memory.lock().unwrap();
    let old_state = if target_addr < MEMORY_SIZE { mem[target_addr] } else { 0 };

    if target_addr < MEMORY_SIZE {
        mem[target_addr] = new_state;
    }

    log!("┌──────────────────────────────────────────────┐");
    log!("│  *** MEMORY WRITE (COIL CONTAMINATION) ***   │");
    log!("├──────────────────────────────────────────────┤");
    log!("│  Address : 0x{:04X} (memory[0x{:04X}])           │", coil_addr, target_addr);
    log!("│  Value   : 0x{:02X} 0x{:02X} → {}                  │", raw_value_hi, raw_value_lo, if new_state == 1 { "ON " } else { "OFF" });
    log!("│  State   : {} → {}                            │", old_state, new_state);
    log!("└──────────────────────────────────────────────┘");

    let payload_len = 5;
    let mut response = Vec::new();
    response.extend_from_slice(&mbap.build_response(payload_len));
    response.extend_from_slice(&buf[7..12]);
    response
}

fn handle_client(mut stream: TcpStream, memory: SharedMemory) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(_) => return,
    };
    log!("[+] New connection from {}", peer_addr);

    let mut buf = [0u8; 512];
    loop {
        match stream.read(&mut buf) {
            Ok(0) => {
                log!("[-] Connection closed by {}", peer_addr);
                break;
            }
            Ok(n) => {
                log!("\n[>] Raw packet received ({} bytes): {:02X?}", n, &buf[..n]);

                let mbap = match MbapHeader::parse(&buf[..n]) {
                    Some(h) => h,
                    None => {
                        log_err!("[!] Failed to parse MBAP header");
                        continue;
                    }
                };

                log!(
                    "    [MBAP] TransID=0x{:04X}, ProtoID=0x{:04X}, UnitID={}",
                    mbap.transaction_id, mbap.protocol_id, mbap.unit_id
                );

                if mbap.protocol_id != 0 {
                    log_err!(
                        "[!] Invalid Protocol ID: 0x{:04X} (expected 0x0000). Dumping raw bytes.",
                        mbap.protocol_id
                    );
                    log_err!("    {:02X?}", &buf[..n]);
                    continue;
                }

                let function_code = buf[7];
                let response = match function_code {
                    0x01 => {
                        log!("    [PDU] FC=0x01 (Read Coils)");
                        handle_read_coils(&mbap, &buf, &memory)
                    }
                    0x04 => {
                        log!("    [PDU] FC=0x04 (Read Input Registers)");
                        handle_read_input_registers(&mbap, &buf, &memory)
                    }
                    0x05 => {
                        log!("    [PDU] FC=0x05 (Write Single Coil)");
                        handle_write_single_coil(&mbap, &buf, n, &memory)
                    }
                    _ => {
                        log_err!(
                            "[!] Unsupported Function Code: 0x{:02X}. Ignoring request.",
                            function_code
                        );
                        log_err!("    Full packet dump: {:02X?}", &buf[..n]);
                        continue;
                    }
                };

                log!("[>] Sending {} bytes", response.len());
                log!("    Response hex dump: {:02X?}", response);

                if let Err(e) = stream.write_all(&response) {
                    log_err!("[!] Write error to {}: {}", peer_addr, e);
                    break;
                }
            }
            Err(e) => {
                log_err!("[!] Read error from {}: {}", peer_addr, e);
                break;
            }
        }
    }
}

// ==========================================
// メインエントリポイント
// ==========================================
fn main() -> std::io::Result {
    let addr = "0.0.0.0:502";

    log!("==================================================");
    log!("  Modbus/TCP Sensor Emulator (Rust Raw Socket)");
    log!("  Listening on: {}", addr);
    log!("==================================================");
    log!("  Memory: {} bytes allocated", MEMORY_SIZE);
    log!("  Coil base:           0x{:04X}", COIL_BASE);
    log!("  Input Register base: 0x{:04X}", INPUT_REGISTER_BASE);
    log!("  Supported FCs: 0x01, 0x04, 0x05");
    log!("==================================================");

    let memory = init_memory();

    let listener = TcpListener::bind(addr)?;

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let mem_clone = Arc::clone(&memory);
                thread::spawn(move || {
                    handle_client(stream, mem_clone);
                });
            }
            Err(e) => {
                log_err!("[!] Connection accept error: {}", e);
            }
        }
    }

    Ok(())
}
```

---

## 3. 改修のポイントサマリ

### ① メモリ空間の導入（ステートフル化）
`Arc<Mutex<[u8; 65536]>>` を用いることで、プロセス全体で単一の64KB仮想RAMを保持。マルチスレッド環境下でも安全に排他制御を行いながら、アドレス空間（Coil領域: `0x0000`~、Input Register領域: `0x1000`~）を分けたメモリ参照・書換を実現しました。

### ② プロトコル拡張（FC 0x01 / FC 0x05）
* **FC 0x01 (Read Coils)**: 共有メモリから指定範囲を読み出し、1バイトあたり8個のCoilを格納するLSB firstのビットパッキングを実装。
* **FC 0x05 (Write Single Coil)**: 攻撃のトリガーとなる書き込み値（`0xFF00` = ON / `0x0000` = OFF）をデコードし、メモリを直接上書き。

### ③ メモリ書き込み時のグラフィカルログ出力
書き込み命令（FC 0x05）を検出した際、アスキーアートによるコンソール枠を表示し、アドレス・新旧状態・生パケットをリアルタイムダンプする仕組みを追加しました。

---

## 4. ビルドと正常状態変異の動作検証

コードの修正が完了したら、コンテナをビルドして起動します。

```bash
docker compose up -d --build
```

![](https://static.zenn.studio/user-upload/5ab6c0ef9ba5-20260720.png)

無事にエミュレータが起動し、ポート502での待ち受けが確立されました。続いて、Pythonのワンライナーを用いて正常な状態変異（読み取り系）の検証を行います。

---

### 検証①：FC 0x01 (Read Coils) による Coil 0 の初期状態確認

```python
python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 502))
pkt = struct.pack('>HHHBBHH', 0x0001, 0x0000, 6, 1, 0x01, 0x0000, 1)
s.sendall(pkt)
r = s.recv(256)
print('RX:', r.hex())
print('Coil 0 =', 'ON' if r[-1] == 1 else 'OFF')
s.close()
"
```

![](https://static.zenn.studio/user-upload/2dcf3f7b02e0-20260720.png)

![](https://static.zenn.studio/user-upload/d07c65e57947-20260720.png)

エミュレータ側のコンソールログでも、リクエストのパースと応答の構築が正しく行われていることが確認できます。

#### 受信データのバイナリ構造解析

返却されたレスポンス `RX: 00010000000401010101` の内訳は以下の通りです。

* **MBAPヘッダ (7 Bytes)**: `0001` (TransID), `0000` (ProtoID), `0004` (Length), `01` (UnitID)
* **PDU (5 Bytes)**: `01` (Function Code), `01` (Byte Count), `01` (Coil Data: 末尾が 1 であるため Coil 0 が ON)

#### この検証によって証明されたこと

* **L3/L4経路の確立**: WSL環境からDockerサブネットへの直接通信制約を `127.0.0.1:502` のポートマッピングによって確実に対処。
* **L7バイナリパーサーの完全性**: Modbusフレーム（MBAP+PDU）のオフセットおよびアライメント判定が正確に実装されていることの証明。
* **共有メモリアクセスの成功**: 単なる固定値のモックではなく、物理メモリ空間（`Arc<Mutex<T>>`）の排他制御を取得し、アドレス `0x0000` の状態を正確にフェッチして返却できたという「メモリRead」の実証。

---

### 検証②：FC 0x04 (Read Input Registers) によるレジスタ初期値の確認

```python
python3 -c "
import socket, struct
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 502))
pkt = struct.pack('>HHHBBHH', 0x0002, 0x0000, 6, 1, 0x04, 0x0000, 2)
s.sendall(pkt)
r = s.recv(256)
print('RX:', r.hex())
val0 = struct.unpack('>H', r[9:11])[0]
val1 = struct.unpack('>H', r[11:13])[0]
print('Reg0 = 0x{:04X}, Reg1 = {}'.format(val0, val1))
s.close()
"
```

![](https://static.zenn.studio/user-upload/ceefbc257238-20260720.png)

![](https://static.zenn.studio/user-upload/91c71ac65c5a-20260720.png)

エミュレータ側でも正常にログが出力されています。

#### 受信データ（FC 0x04 応答）のバイナリ構造解析

今回受信した13バイトのペイロード（`RX: 000200000007010404000100ff`）の分解：

* **MBAPヘッダ (Offset 0x00 - 0x06)**: `0002` (TransID), `0000` (ProtoID), `0007` (Length), `01` (UnitID)
* **PDU (Offset 0x07 - 0x0C)**: `04` (Function Code), `04` (Byte Count: 2レジスタ×2=4バイト), `0001` (Reg0データ), `00ff` (Reg1データ)

#### 本コードにおけるFC 0x04固有の検証成果

* **16ビットデータのエンディアン変換の完全性**: リトルエンディアンのメモリ上からフェッチした値を、上位・下位バイトを反転させることなく正確にネットワークバイトオーダー（ビッグエンディアン）に変換してパッキング（Reg0 = `0x0001`, Reg1 = `0x00FF`）できていることを証明。
* **動的なペイロード長の算出とアライメント**: 要求されたレジスタ数に応じてByte Count（`0x04`）とMBAPのLength（`0x0007`）を動的に算出し、メモリアライメントを崩さずに出力。
* **連続アドレス空間からのバースト読み出し**: 開始アドレス `0x0000` から2個の連続した16ビット領域を、インデックスオーバーランを起こさずに安全にフェッチ。

---

## 5. おわりに

今回は、ステートレスだった仮想センサーエミュレータに対して `Arc<Mutex<T>>` による共有メモリ空間を導入し、FC 0x01（Read Coils）および FC 0x05（Write Single Coil）の基盤を実装しました。

さらに、Pythonを用いた生バイト送信により、L3/L4からL7層、そしてメモリReadに至るまでの一連のアーキテクチャが正常に機能していることを実証しました。

次回は、今回実装した FC 0x05（Write Single Coil）を実際に悪用し、センサーの物理状態を強制書き換えするメモリ汚染攻撃（センサー隠蔽）の検証に踏み込んでいきます。
