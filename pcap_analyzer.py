#!/usr/bin/env python3

import os
import subprocess
import csv
import io
import re
from datetime import datetime
from collections import defaultdict

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading

# CONFIG
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"  # adjust if needed
DEFAULT_OUTPUT = "pcap_output"
TSHARK_FIELDS = [
    "frame.time_epoch",
    "frame.number",
    "frame.len",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "tcp.stream",
    "dns.qry.name",
    "http.request.method",
    "http.host",
    "http.request.uri",
    "http.file_data",   # potential file upload data
    "data.text"         # raw payload (hex/text) when available
]
# OWASP regex signatures (lowercase matching)
OWASP_PATTERNS = {
    "sql_injection": [r"\bor\b\s+1=1\b", r"union\s+select", r"xp_cmdshell", r"select.+from.+where"],
    "xss": [r"<script\b", r"onerror\s*=", r"javascript:"],
    "cmd_injection": [r";\s*ls\b", r"\|\s*cat\s+/etc/passwd", r"&&\s*rm\s"],
    "path_traversal": [r"\.\./", r"/etc/passwd"],
    "file_upload": [r"\.php\b", r"\.jsp\b", r"\.asp\b"]
}
# 

def ensure_tshark_exists():
    if os.path.exists(TSHARK_PATH):
        return TSHARK_PATH
    # fallback to system path
    try:
        subprocess.run([TSHARK_PATH], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        # try system tshark
        try:
            subprocess.run(["tshark", "-v"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "tshark"
        except Exception:
            return None
    return TSHARK_PATH

def export_pcap_to_csv(pcap_path, csv_path):
    
    tshark = ensure_tshark_exists()
    if not tshark:
        raise RuntimeError("tshark not found. Please install Wireshark/TShark and set TSHARK_PATH.")

    # Build args
    args = [tshark, "-r", pcap_path, "-T", "fields"]
    for f in TSHARK_FIELDS:
        args += ["-e", f]
    # CSV formatting: header=yes, separator=,
    args += ["-E", "header=y", "-E", "separator=,", "-E", "quote=d"]  # quote fields with double-quotes

    # Run and write directly to csv_path
    with open(csv_path, "wb") as out_f:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = proc.communicate()
        if proc.returncode not in (0, 1):  # tshark returns 1 for "some lines unparsable" sometimes
            raise RuntimeError(f"TShark error: {stderr.decode('utf-8', errors='replace')}")
        out_f.write(stdout)

def load_csv_to_df(csv_path):
    """
    Read CSV exported by tshark into a DataFrame and normalize columns.
    """
    # read with pandas (it will use double-quote quoting)
    df = pd.read_csv(csv_path, dtype=str, keep_default_na=False)
   
    rename_map = {
        "frame.time_epoch": "ts_epoch",
        "frame.number": "frame_no",
        "frame.len": "frame_len",
        "frame.protocols": "protocols",
        "ip.src": "src_ip",
        "ip.dst": "dst_ip",
        "tcp.srcport": "tcp_sport",
        "tcp.dstport": "tcp_dport",
        "udp.srcport": "udp_sport",
        "udp.dstport": "udp_dport",
        "tcp.stream": "tcp_stream",
        "dns.qry.name": "dns_query",
        "http.request.method": "http_method",
        "http.host": "http_host",
        "http.request.uri": "http_uri",
        "http.file_data": "http_file_data",
        "data.text": "data_text"
    }
    df.rename(columns=rename_map, inplace=True)
    # Create unified ports
    df["src_port"] = df["tcp_sport"].replace("", pd.NA).fillna(df["udp_sport"].replace("", pd.NA))
    df["dst_port"] = df["tcp_dport"].replace("", pd.NA).fillna(df["udp_dport"].replace("", pd.NA))
    # Convert timestamp
    if "ts_epoch" in df.columns:
        try:
            df["timestamp"] = pd.to_datetime(df["ts_epoch"].astype(float), unit="s").dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            df["timestamp"] = df["ts_epoch"]
    else:
        df["timestamp"] = ""
    # numeric lengths
    if "frame_len" in df.columns:
        df["frame_len"] = pd.to_numeric(df["frame_len"], errors="coerce").fillna(0).astype(int)
    else:
        df["frame_len"] = 0
    return df

# Detection functions
def detect_port_scans(df, unique_ports_threshold=30):
    alerts = []
    # count unique destination ports per source IP
    grouped = df.groupby("src_ip")["dst_port"].nunique().dropna()
    for ip, cnt in grouped.items():
        if cnt >= unique_ports_threshold:
            alerts.append({"type": "port_scan", "src_ip": ip, "unique_dst_ports": int(cnt)})
    return alerts

def detect_beaconing(df, min_samples=6, std_tol=3.0):
    alerts = []
    if df.empty or "timestamp" not in df.columns:
        return alerts
    df_ts = df.copy()
    df_ts["ts_dt"] = pd.to_datetime(df_ts["timestamp"], errors="coerce")
    for src, g in df_ts.groupby("src_ip"):
        if g.shape[0] < min_samples: continue
        diffs = g.sort_values("ts_dt")["ts_dt"].diff().dt.total_seconds().dropna()
        if len(diffs) and np.std(diffs) < std_tol:
            alerts.append({"type": "beaconing", "src_ip": src, "median_interval": float(np.median(diffs)), "samples": int(len(g))})
    return alerts

def detect_large_transfers(df, threshold_bytes=1_000_000):
    alerts = []
    totals = df.groupby("src_ip")["frame_len"].sum()
    for ip, total in totals.items():
        if total >= threshold_bytes:
            alerts.append({"type": "large_transfer", "src_ip": ip, "bytes": int(total)})
    return alerts

def scan_owasp(df):
    alerts = []
    payload_cols = ["http_uri", "http_file_data", "data_text", "dns_query"]
    for idx, row in df.iterrows():
        combined = " ".join([str(row.get(c, "")).lower() for c in payload_cols if c in row])
        if not combined.strip(): continue
        for name, patterns in OWASP_PATTERNS.items():
            for pat in patterns:
                if re.search(pat, combined, re.IGNORECASE):
                    alerts.append({"type": f"owasp_{name}", "packet_index": int(row.get("frame_no", -1) or -1), "excerpt": combined[:300]})
                    break
    return alerts

# Reporting
def generate_reports(df, alerts, outdir, base_name):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    excel_path = os.path.join(outdir, f"{base_name}_summary_{ts}.xlsx")
    html_path = os.path.join(outdir, f"{base_name}_report_{ts}.html")

    # Save Excel
    with pd.ExcelWriter(excel_path, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="packets", index=False)
        pd.DataFrame(alerts).to_excel(writer, sheet_name="alerts", index=False)

    # Charts
    charts = []
    try:
        if not df.empty:
            top_src = df["src_ip"].value_counts().head(10)
            fig = plt.figure(figsize=(6,4))
            top_src.plot(kind="bar")
            plt.title("Top Source IPs")
            plt.tight_layout()
            p1 = os.path.join(outdir, f"{base_name}_top_src.png")
            fig.savefig(p1); plt.close(fig)
            charts.append(p1)

            protos = df["protocols"].value_counts().head(10)
            fig = plt.figure(figsize=(6,4))
            protos.plot(kind="bar")
            plt.title("Protocol Distribution")
            plt.tight_layout()
            p2 = os.path.join(outdir, f"{base_name}_protocols.png")
            fig.savefig(p2); plt.close(fig)
            charts.append(p2)
    except Exception as e:
        print("Chart generation error:", e)

    # HTML
    html_parts = []
    html_parts.append(f"<h1>PCAP Analysis Report: {base_name}</h1>")
    html_parts.append(f"<p>Generated: {datetime.now().isoformat()}</p>")
    for c in charts:
        html_parts.append(f'<img src="{os.path.basename(c)}" style="max-width:900px">')
    html_parts.append("<h2>Alerts</h2>")
    html_parts.append(pd.DataFrame(alerts).to_html(index=False))
    html_parts.append("<h2>Packet Sample</h2>")
    html_parts.append(df.head(200).to_html(index=False))
    with open(html_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html_parts))
    return excel_path, html_path

# Analyzer (high-level)
def analyze_pcap_file(pcap_path, output_dir):
    base = os.path.splitext(os.path.basename(pcap_path))[0]
    out_sub = os.path.join(output_dir, base)
    os.makedirs(out_sub, exist_ok=True)

    csv_path = os.path.join(out_sub, f"{base}_tshark_export.csv")
    
    pcap_mtime = os.path.getmtime(pcap_path)
    if not os.path.exists(csv_path) or os.path.getmtime(csv_path) < pcap_mtime:
        export_pcap_to_csv(pcap_path, csv_path)

    df = load_csv_to_df(csv_path)
    # basic normalization
    for col in ["src_ip","dst_ip","src_port","dst_port","timestamp"]:
        if col not in df.columns:
            df[col] = ""

    # detections
    alerts = []
    alerts += detect_port_scans(df)
    alerts += detect_beaconing(df)
    alerts += detect_large_transfers(df)
    alerts += scan_owasp(df)

    excel, html = generate_reports(df, alerts, out_sub, base)
    return {"excel": excel, "html": html, "alerts": alerts, "rows": len(df)}

# GUI
class PcapAnalyzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("PCAP Analyzer (TShark-based)")
        self.geometry("760x520")
        self.in_files = []
        self.output_dir = os.path.abspath(DEFAULT_OUTPUT)
        self._build()

    def _build(self):
        frame = ctk.CTkFrame(self, corner_radius=8)
        frame.pack(fill="both", expand=True, padx=16, pady=16)
        ctk.CTkLabel(frame, text="PCAP Analyzer (TShark → CSV → Python)", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=(6,10))
        self.file_box = ctk.CTkTextbox(frame, height=140)
        self.file_box.pack(fill="x", padx=6)

        btn_frame = ctk.CTkFrame(frame)
        btn_frame.pack(fill="x", pady=8)
        ctk.CTkButton(btn_frame, text="Add PCAPs", command=self.add_files).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Set Output Folder", command=self.set_output).pack(side="left", padx=6)
        ctk.CTkButton(btn_frame, text="Run Analysis", command=self.start_thread).pack(side="right", padx=6)

        self.progress = ctk.CTkProgressBar(frame)
        self.progress.pack(fill="x", padx=6, pady=12)

    def add_files(self):
        paths = filedialog.askopenfilenames(filetypes=[("PCAP files","*.pcap *.pcapng"),("All files","*.*")])
        for p in paths:
            self.in_files.append(p)
            self.file_box.insert("end", p + "\n")

    def set_output(self):
        d = filedialog.askdirectory()
        if d:
            self.output_dir = d
            messagebox.showinfo("Output set", f"Output folder: {d}")

    def start_thread(self):
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        # do work in thread to avoid GUI freeze
        try:
            total = len(self.in_files)
            for i, f in enumerate(self.in_files):
                self.progress.set(i / total if total else 0)
                self.update_idletasks()
                res = analyze_pcap_file(f, self.output_dir)
                print("Saved:", res.get("excel"), res.get("html"))
            self.progress.set(1.0)
            messagebox.showinfo("Done", "All PCAPs processed.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# CLI 
def cli_main():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--input")
    p.add_argument("-o", "--output", default=DEFAULT_OUTPUT)
    p.add_argument("--gui", action="store_true")
    args = p.parse_args()
    if args.gui:
        app = PcapAnalyzerGUI()
        app.mainloop()
        return
    if args.input:
        print("Processing:", args.input)
        print(analyze_pcap_file(args.input, args.output))

if __name__ == "__main__":
    cli_main()
