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
// 65536バイトの共有メモリ配列をOTデバイスの「RAM」として使用する。
//
// メモリマップ:
//   0x0000 ~ 0x0FFF : Coil 領域 (1バイト = 1 Coil, 値は 0 or 1)
//                     FC 0x01 (Read Coils) / FC 0x05 (Write Single Coil) が操作
//   0x1000 ~ 0xFFFF : Input Register 領域 (2バイト = 1 Register, ビッグエンディアン)
//                     FC 0x04 (Read Input Registers) が参照
//
const MEMORY_SIZE: usize = 65536;
const COIL_BASE: usize = 0x0000;
const INPUT_REGISTER_BASE: usize = 0x1000;

/// 共有メモリの型エイリアス
type SharedMemory = Arc<Mutex<[u8; MEMORY_SIZE]>>;

/// 共有メモリを初期化し、デフォルトのセンサー値を書き込む
fn init_memory() -> SharedMemory {
    let mut memory = [0u8; MEMORY_SIZE];

    // --- Coil 領域の初期値 ---
    // Coil 0: 侵入検知センサー (初期値: ON = 1)
    memory[COIL_BASE] = 1;

    // --- Input Register 領域の初期値 ---
    // Register 0 (offset 0x1000-0x1001): 侵入検知 (0x0001 = ON)
    let intrusion: u16 = 0x0001;
    let bytes = intrusion.to_be_bytes();
    memory[INPUT_REGISTER_BASE] = bytes[0];
    memory[INPUT_REGISTER_BASE + 1] = bytes[1];

    // Register 1 (offset 0x1002-0x1003): 温度 (25.5℃ x10 = 255 = 0x00FF)
    let temperature: u16 = 0x00FF;
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
    /// 生バイト列の先頭7バイトからMBAPヘッダを手動スライスでパースする
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

    /// MBAPヘッダをレスポンス用バイト列として構築する (Lengthは呼び出し側で指定)
    fn to_response_bytes(&self, payload_length: u16) -> [u8; 7] {
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
        if addr < MEMORY_SIZE && mem[addr] != 0 {
            coil_bytes[i / 8] |= 1 << (i % 8);
        }
    }
    drop(mem);

    let response_len = (1 + 1 + 1 + byte_count) as u16;
    let header = mbap.to_response_bytes(response_len);

    let mut response = Vec::with_capacity(7 + 2 + byte_count);
    response.extend_from_slice(&header);
    response.push(0x01);
    response.push(byte_count as u8);
    response.extend_from_slice(&coil_bytes);

    log!(
        "    [FC 0x01] Response: ByteCount={}, CoilData={:02X?}",
        byte_count, coil_bytes
    );

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
            reg_data.push(0x00);
            reg_data.push(0x00);
        }
    }
    drop(mem);

    let response_len = (1 + 1 + 1 + byte_count) as u16;
    let header = mbap.to_response_bytes(response_len);

    let mut response = Vec::with_capacity(7 + 2 + reg_data.len());
    response.extend_from_slice(&header);
    response.push(0x04);
    response.push(byte_count);
    response.extend_from_slice(&reg_data);

    log!(
        "    [FC 0x04] Response: ByteCount={}, RegData={:02X?}",
        byte_count, reg_data
    );

    response
}

// ==========================================
// FC 0x05: Write Single Coil
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
    let old_state = if target_addr < MEMORY_SIZE {
        let old = mem[target_addr];
        mem[target_addr] = new_state;
        old
    } else {
        log_err!(
            "    [!] WARNING: Coil address 0x{:04X} out of bounds (max 0x{:04X})",
            coil_addr,
            MEMORY_SIZE - 1
        );
        0
    };
    drop(mem);

    log!("    ┌──────────────────────────────────────────────┐");
    log!("    │  *** MEMORY WRITE (COIL CONTAMINATION) ***   │");
    log!("    ├──────────────────────────────────────────────┤");
    log!(
        "    │  Address : 0x{:04X} (memory[0x{:04X}])         ",
        coil_addr, target_addr
    );
    log!(
        "    │  Value   : 0x{:02X} 0x{:02X} → {}                ",
        raw_value_hi,
        raw_value_lo,
        if new_state == 1 { "ON" } else { "OFF" }
    );
    log!(
        "    │  State   : {} → {}                              ",
        old_state, new_state
    );
    log!("    │  Raw req : {:02X?}", &buf[..n]);
    log!("    └──────────────────────────────────────────────┘");

    let header = mbap.to_response_bytes(6);

    let mut response = Vec::with_capacity(12);
    response.extend_from_slice(&header);
    response.push(0x05);
    response.push(buf[8]);
    response.push(buf[9]);
    response.push(raw_value_hi);
    response.push(raw_value_lo);

    response
}

// ==========================================
// クライアント接続ハンドラ
// ==========================================
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
                log!("\n[<] Received {} bytes from {}", n, peer_addr);
                log!("    Raw hex dump: {:02X?}", &buf[..n]);

                if n < 12 {
                    log_err!(
                        "[!] Packet too small: {} bytes (minimum 12 bytes required)",
                        n
                    );
                    log_err!("    Dumped bytes: {:02X?}", &buf[..n]);
                    continue;
                }

                let mbap = match MbapHeader::parse(&buf) {
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
fn main() -> std::io::Result<()> {
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
