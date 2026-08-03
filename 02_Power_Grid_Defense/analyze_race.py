import subprocess
import json
import pandas as pd
import matplotlib.pyplot as plt
import sys

def get_tx_logs():
    print("[*] Fetching TX logs from ebpf_tx_agent container...")
    try:
        out = subprocess.check_output(["docker", "logs", "ebpf_tx_agent"], stderr=subprocess.STDOUT).decode("utf-8")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error fetching docker logs: {e.output.decode('utf-8')}")
        sys.exit(1)
        
    tx_data = []
    decoder = json.JSONDecoder()
    for line in out.splitlines():
        text = line.strip()
        if not text:
            continue

        idx = 0
        while idx < len(text):
            try:
                obj, end = decoder.raw_decode(text[idx:])
                idx += end
                if isinstance(obj, dict) and "t_tx_epoch" in obj:
                    tx_data.append(obj)
                # skip any whitespace or separators between concatenated JSON objects
                while idx < len(text) and text[idx].isspace():
                    idx += 1
            except json.JSONDecodeError:
                break
    return tx_data

def get_rx_logs():
    print("[*] Fetching RX logs from vector container...")
    try:
        # Vector log is /var/log/zeek/vector_eval.log
        out = subprocess.check_output(["docker", "exec", "vector", "cat", "/usr/local/zeek/logs/vector_eval.log"]).decode("utf-8")
    except subprocess.CalledProcessError as e:
        print(f"[-] Error fetching vector logs: {e}")
        sys.exit(1)
        
    rx_data = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Some Vector outputs may contain full span records with embedded race_log JSON.
        if isinstance(record, dict):
            if "trace_id" in record:
                rx_data.append(record)
                continue
            if "race_log" in record and isinstance(record["race_log"], str):
                try:
                    embedded = json.loads(record["race_log"])
                    if "trace_id" in embedded:
                        rx_data.append(embedded)
                        continue
                except json.JSONDecodeError:
                    pass
            if "traceId" in record:
                record["trace_id"] = record["traceId"]
                rx_data.append(record)
                continue

    return rx_data

def main():
    tx_data = get_tx_logs()
    rx_data = get_rx_logs()
    
    if not tx_data or not rx_data:
        print("[-] Missing data. Ensure both containers are running and microburst attack was executed.")
        return
        
    print(f"[+] Parsed {len(tx_data)} TX events and {len(rx_data)} RX events.")
    
    df_tx = pd.DataFrame(tx_data)
    df_rx = pd.DataFrame(rx_data)
    
    # Merge by trace_id
    df_merged = pd.merge(df_tx, df_rx, on="trace_id", how="inner")
    print(f"[+] Successfully matched {len(df_merged)} trace IDs.")
    
    if len(df_merged) == 0:
        print("[-] No matching trace IDs found!")
        return
        
    # Calculate dt in milliseconds
    # t_tx_epoch, t_reg, t_rx_eval are all in nanoseconds
    df_merged["dt_reg_ms"] = (df_merged["t_reg"] - df_merged["t_tx_epoch"]) / 1_000_000.0
    df_merged["dt_rx_ms"] = (df_merged["t_rx_eval"] - df_merged["t_tx_epoch"]) / 1_000_000.0
    df_merged["delta_t_ms"] = (df_merged["t_rx_eval"] - df_merged["t_reg"]) / 1_000_000.0
    
    # Identify False Misses (where RX evaluation happened BEFORE Webdis registration completed)
    # i.e., delta_t_ms < 0
    false_misses = df_merged[df_merged["delta_t_ms"] < 0]
    
    print("\n" + "="*50)
    print("  Race Condition Analysis Results")
    print("="*50)
    print(f"Total Evaluated Packets : {len(df_merged)}")
    print(f"Average Webdis Reg Time : {df_merged['dt_reg_ms'].mean():.2f} ms")
    print(f"Average Vector Eval Time: {df_merged['dt_rx_ms'].mean():.2f} ms")
    print(f"Average Delta T         : {df_merged['delta_t_ms'].mean():.2f} ms")
    print("-" * 50)
    print(f"False Misses (Delta T < 0): {len(false_misses)} ({len(false_misses)/len(df_merged)*100:.2f}%)")
    
    # Check if Vector's enrichment_status matches our physical proof
    vector_misses = df_merged[df_merged["enrichment_status"] == "miss"]
    print(f"Vector Logged 'miss'      : {len(vector_misses)}")
    
    if len(false_misses) == len(vector_misses):
        print("[+] SUCCESS: The physical time difference perfectly correlates with Vector's miss count!")
    else:
        print("[-] WARNING: Discrepancy between physical delta T and Vector log status.")
        
    # Plotting
    plt.figure(figsize=(10, 6))
    
    plt.hist(df_merged["delta_t_ms"], bins=30, color='skyblue', edgecolor='black', alpha=0.7)
    plt.axvline(x=0, color='red', linestyle='--', linewidth=2, label='Race Condition Boundary (t_rx = t_reg)')
    
    plt.title("OOB Context Binding: Race Condition Distribution\n(Microburst Load Test)", fontsize=14)
    plt.xlabel("Delta t = T_rx_eval - T_reg (milliseconds)", fontsize=12)
    plt.ylabel("Frequency (Packet Count)", fontsize=12)
    plt.legend()
    plt.grid(axis='y', alpha=0.75)
    
    output_file = "race_condition_histogram.png"
    plt.savefig(output_file, dpi=300, bbox_inches='tight')
    print(f"\n[+] Histogram saved to {output_file}")

if __name__ == "__main__":
    main()
