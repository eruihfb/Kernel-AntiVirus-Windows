#!/usr/bin/env python3
import os
import sys
import json
import hashlib
import urllib.request
import urllib.error
import time
from pathlib import Path

try:
    import psutil
except ImportError:
    print("Error: psutil is not installed. Run 'pip install psutil requests' inside your venv.")
    sys.exit(1)

CONFIG_DIR = Path(os.path.expanduser("~")) / ".kernel_av"
CONFIG_FILE = CONFIG_DIR / "config.json"

def load_config():
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except Exception:
            return {}
    return {}

def save_config(config):
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(65536), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"[-] Could not read file {filepath}: {e}")
        return None

def check_virustotal(file_hash):
    config = load_config()
    api_key = config.get("vt_api_key")
    if not api_key:
        print("[-] No VirusTotal API key configured. Run 'python antivirus.py config --key <YOUR_KEY>' first.")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {"malicious": malicious, "suspicious": suspicious, "total": sum(stats.values())}
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found"}
        print(f"[-] VirusTotal API error: {e.code}")
    except Exception as e:
        print(f"[-] Connection error: {e}")
    return None

def audit_processes():
    print("[+] Auditing active processes for high resource usage and anomalies...")
    print(f"{'PID':<6} | {'CPU%':<6} | {'MEM%':<6} | {'Process Name'}")
    print("-" * 50)
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            pinfo = proc.info
            cpu = pinfo['cpu_percent'] or 0.0
            mem = pinfo['memory_percent'] or 0.0
            if cpu > 5.0 or mem > 5.0:
                print(f"{pinfo['pid']:<6} | {cpu:<6.1f} | {mem:<6.1f} | {pinfo['name']}" )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def audit_network():
    print("[+] Auditing active network connections...")
    print(f"{'PROTO':<6} | {'LOCAL ADDRESS':<25} | {'REMOTE ADDRESS':<25} | {'STATUS'}")
    print("-" * 65)
    for conn in psutil.net_connections(kind='inet'):
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        proto = "TCP" if conn.type == 1 else "UDP"
        print(f"{proto:<6} | {laddr:<25} | {raddr:<25} | {conn.status}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        if cmd == "procs":
            audit_processes()
        elif cmd == "net":
            audit_network()
        elif cmd == "config" and len(sys.argv) > 3 and sys.argv[2] == "--key":
            cfg = load_config()
            cfg["vt_api_key"] = sys.argv[3]
            save_config(cfg)
            print("[+] VirusTotal API key saved successfully.")
        else:
            print("Unknown command. Usage: python antivirus.py [procs|net|config --key <KEY>]")
    else:
        print("Kernel-AntiVirus (Windows Port) loaded.")
        print("Usage: python antivirus.py [procs | net | config]")
