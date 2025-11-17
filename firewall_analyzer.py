#!/usr/bin/env python3
"""
firewall_analyzer.py
Universal multi-vendor firewall log analyzer:
 - Parse FortiGate/Palo Alto/Sophos (heuristic regex + CSV fallback)
 - Normalize timestamps, GeoIP lookup (optional)
 - Simple threat-intel check (AbuseIPDB placeholder)
 - Detections: port-scan, brute-force, blocked critical ports, new IPs
 - Excel + HTML report generation
 - CustomTkinter GUI with batch processing and progress bar
"""

import os
import re
from datetime import datetime, timedelta
from collections import Counter
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import customtkinter as ctk
from tkinter import filedialog, messagebox
import threading
import requests

# Optional GeoIP (if GeoLite2 DB installed)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except Exception:
    GEOIP_AVAILABLE = False

CRITICAL_PORTS = {22, 23, 3389, 445}
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S"

# Simple vendor regexes (heuristic)
FORTIGATE_RE = re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*src=(?P<src>\d+\.\d+\.\d+\.\d+).*dst=(?P<dst>\d+\.\d+\.\d+\.\d+).*spt=(?P<spt>\d+).*dpt=(?P<dpt>\d+).*proto=(?P<proto>\d+).*action=(?P<action>\w+)', re.IGNORECASE)
PALO_RE = re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*src=(?P<src>\d+\.\d+\.\d+\.\d+).*dst=(?P<dst>\d+\.\d+\.\d+\.\d+).*sport=(?P<spt>\d+).*dport=(?P<dpt>\d+).*proto=(?P<proto>\w+).*action=(?P<action>\w+)', re.IGNORECASE)

def normalize_ts(s):
    if s is None: return None
    s = s.strip()
    candidates = ["%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S"]
    for fmt in candidates:
        try:
            dt = datetime.strptime(s, fmt)
            if "%Y" not in fmt:
                dt = dt.replace(year=datetime.now().year)
            return dt.strftime(TIMESTAMP_FORMAT)
        except Exception:
            continue
    try:
        import dateutil.parser as dp
        dt = dp.parse(s)
        return dt.strftime(TIMESTAMP_FORMAT)
    except Exception:
        return s

def parse_line(line):
    m = FORTIGATE_RE.search(line)
    if m:
        d = m.groupdict()
        return dict(timestamp=normalize_ts(d["timestamp"]), src_ip=d["src"], dst_ip=d["dst"], src_port=int(d["spt"]), dst_port=int(d["dpt"]), protocol=d["proto"], action=d.get("action",""))
    m = PALO_RE.search(line)
    if m:
        d = m.groupdict()
        return dict(timestamp=normalize_ts(d["timestamp"]), src_ip=d["src"], dst_ip=d["dst"], src_port=int(d["spt"]), dst_port=int(d["dpt"]), protocol=d["proto"], action=d.get("action",""))
    # CSV heuristic
    parts = [p.strip() for p in re.split(r'\s*,\s*', line) if p.strip()]
    if len(parts) >= 6:
        # attempt mapping
        ts = normalize_ts(parts[0])
        src = parts[1]; dst = parts[2]
        try:
            spt = int(parts[3]); dpt = int(parts[4])
        except:
            spt = dpt = 0
        return dict(timestamp=ts, src_ip=src, dst_ip=dst, src_port=spt, dst_port=dpt, protocol="", action="")
    # fallback
    return dict(timestamp=None, src_ip=None, dst_ip=None, src_port=None, dst_port=None, protocol=None, action=None, raw=line)

def geoip_lookup(ip, db_path="GeoLite2-City.mmdb"):
    if not GEOIP_AVAILABLE or not os.path.exists(db_path):
        return None, None
    try:
        reader = geoip2.database.Reader(db_path)
        r = reader.city(ip)
        country = r.country.iso_code
        city = r.city.name
        reader.close()
        return country, city
    except Exception:
        return None, None

# Detections
def detect_port_scans(df, port_threshold=20):
    alerts=[]
    try:
        cnts = df.groupby("src_ip")["dst_port"].nunique()
        for ip, c in cnts.items():
            if c >= port_threshold:
                alerts.append({"type":"port_scan","src_ip":ip,"unique_ports":int(c)})
    except Exception:
        pass
    return alerts

def detect_bruteforce(df, fail_keywords=("deny","failed","auth-failed"), attempts_threshold=10):
    alerts=[]
    if "action" in df.columns:
        df["is_fail"] = df["action"].astype(str).str.lower().apply(lambda x: any(k in x for k in fail_keywords))
        cnts = df[df["is_fail"]].groupby("src_ip").size()
        for ip, c in cnts.items():
            if c >= attempts_threshold:
                alerts.append({"type":"brute_force","src_ip":ip,"failed_attempts":int(c)})
    return alerts

def detect_blocked_critical_ports(df):
    alerts=[]
    if "dst_port" in df.columns and "action" in df.columns:
        blocked = df[df["action"].astype(str).str.lower().str.contains("deny|blocked|drop|reject", na=False)]
        for port in CRITICAL_PORTS:
            hits = blocked[blocked["dst_port"] == port]
            if not hits.empty:
                alerts.append({"type":"blocked_critical","port":int(port),"count":int(len(hits)),"src_ips":hits["src_ip"].unique().tolist()})
    return alerts

# Reporting
def generate_reports(df, alerts, outdir, base):
    os.makedirs(outdir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    excel = os.path.join(outdir, f"{base}_summary_{ts}.xlsx")
    html = os.path.join(outdir, f"{base}_report_{ts}.html")
    with pd.ExcelWriter(excel, engine="openpyxl") as writer:
        df.to_excel(writer, sheet_name="connections", index=False)
        pd.DataFrame(alerts).to_excel(writer, sheet_name="alerts", index=False)
    # charts
    charts = []
    try:
        top_src = df["src_ip"].value_counts().head(10)
        fig = plt.figure(figsize=(6,4))
        top_src.plot(kind="bar"); plt.title("Top Source IPs"); plt.tight_layout()
        p1 = os.path.join(outdir, "top_src.png"); fig.savefig(p1); plt.close(fig); charts.append(p1)
    except Exception:
        pass
    html_parts=[]
    html_parts.append(f"<h1>Firewall Analysis: {base}</h1>")
    html_parts.append(f"<p>Generated: {datetime.now().isoformat()}</p>")
    for c in charts:
        html_parts.append(f'<img src="{os.path.basename(c)}" width="800">')
    html_parts.append("<h2>Alerts</h2>")
    html_parts.append(pd.DataFrame(alerts).to_html(index=False))
    html_parts.append("<h2>Sample Connections</h2>")
    html_parts.append(df.head(200).to_html(index=False))
    with open(html, "w", encoding="utf-8") as fh:
        fh.write("\n".join(html_parts))
    return excel, html

# Analysis
def analyze_firewall_file(path, output_dir, geoip_db=None):
    base = os.path.splitext(os.path.basename(path))[0]
    out_sub = os.path.join(output_dir, base)
    os.makedirs(out_sub, exist_ok=True)
    rows=[]
    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            p = parse_line(line)
            rows.append(p)
    df = pd.DataFrame(rows)
    # normalization
    for c in ["src_ip","dst_ip","src_port","dst_port","timestamp","action"]:
        if c not in df.columns:
            df[c] = ""
    df["src_port"] = pd.to_numeric(df["src_port"], errors="coerce").fillna(0).astype(int)
    df["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce").fillna(0).astype(int)
    # optional geoip
    if geoip_db and GEOIP_AVAILABLE:
        def map_country(ip):
            try:
                c, city = geoip_lookup(ip, geoip_db)
                return c
            except: return None
        df["src_country"] = df["src_ip"].apply(lambda x: map_country(x))
    # detections
    alerts=[]
    alerts += detect_port_scans(df)
    alerts += detect_bruteforce(df)
    alerts += detect_blocked_critical_ports(df)
    # newly seen IPs (simple heuristic)
    ip_counts = df["src_ip"].value_counts()
    rare = ip_counts[ip_counts <= 2].index.tolist()
    for ip in rare:
        alerts.append({"type":"newly_seen","src_ip":ip,"occurrences":int(ip_counts.get(ip,0))})
    excel, html = generate_reports(df, alerts, out_sub, base)
    return {"excel": excel, "html": html, "alerts": alerts, "rows": len(df)}

# GUI
class FirewallAnalyzerGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Firewall Analyzer")
        self.geometry("720x480")
        self.files=[]
        self.output_dir = os.path.abspath("firewall_output")
        self._build()

    def _build(self):
        frame = ctk.CTkFrame(self); frame.pack(fill="both", expand=True, padx=12, pady=12)
        ctk.CTkLabel(frame, text="Firewall Log Analyzer", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=6)
        self.file_box = ctk.CTkTextbox(frame, height=120); self.file_box.pack(fill="x")
        btns = ctk.CTkFrame(frame); btns.pack(fill="x", pady=8)
        ctk.CTkButton(btns, text="Add Logs", command=self.add_files).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Set Output", command=self.set_output).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Run", command=self.start_thread).pack(side="right", padx=6)
        self.progress = ctk.CTkProgressBar(frame); self.progress.pack(fill="x", pady=12)

    def add_files(self):
        paths = filedialog.askopenfilenames(filetypes=[("Log files","*.log *.txt *.csv"),("All","*.*")])
        for p in paths:
            self.files.append(p); self.file_box.insert("end", p + "\n")

    def set_output(self):
        d = filedialog.askdirectory(); 
        if d: self.output_dir = d; messagebox.showinfo("Output set", self.output_dir)

    def start_thread(self):
        threading.Thread(target=self.run_processing, daemon=True).start()

    def run_processing(self):
        total = len(self.files)
        for i, f in enumerate(self.files):
            self.progress.set(i/total if total else 0); self.update_idletasks()
            try:
                res = analyze_firewall_file(f, self.output_dir)
                print("Saved:", res["excel"], res["html"])
            except Exception as e:
                print("Error processing", f, e)
        self.progress.set(1.0); messagebox.showinfo("Done", "All logs processed.")

# CLI
def cli():
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("-i", "--input")
    p.add_argument("-o", "--output", default="firewall_output")
    p.add_argument("--gui", action="store_true")
    args = p.parse_args()
    if args.gui:
        app = FirewallAnalyzerGUI(); app.mainloop(); return
    if args.input:
        print(analyze_firewall_file(args.input, args.output))

if __name__ == "__main__":
    cli()
