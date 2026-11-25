#!/usr/init/env python3
import os
import sys
import json
import hashlib
import urllib.request
import urllib.error
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
        print("[-] No VirusTotal API key configured. Run 'kv api_key <key>' first.")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    req = urllib.request.Request(url, headers={"x-apikey": api_key})
    
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode("utf-8"))
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "total": sum(stats.values())
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not_found"}
        print(f"[-] VirusTotal API error: {e.code}")
    except Exception as e:
        print(f"[-] Connection error: {e}")
    return None

def show_help():
    print("🛡️  Kernel Antivirus Commands:")
    print("  kv status                        - Check if background monitor is running")
    print("  kv api_key <key>                 - Set or update your VirusTotal API key")
    print("  kv stats                         - View scan totals, threats caught, and vault count")
    print("  kv whitelist <path>              - Exclude a trusted file or folder from scans")
    print("  kv unwhitelist <path>            - Remove a path from the whitelist")
    print("  kv config                        - View current settings")
    print("  kv restore_path <dir>            - Set where 'kv restore' places unlocked files")
    print("  kv autoscan_folders <d1,d2,...>  - Set daily scan folders (comma-separated)")
    print("  kv scan_time <HH:MM>             - Set daily scan time (24h format, e.g. 18:00)")
    print("  kv log_autodelete <days>         - Auto-delete logs older than X days (0 = never)")
    print("  kv clear_logs                    - Wipe all log entries immediately")
    print("  kv procs                         - Check running processes for high RAM/CPU & unsigned paths")
    print("  kv scan_procs                    - Scan active process binaries against VirusTotal")
    print("  kv scan <file>                   - Manually scan a specific file right now")
    print("  kv scan_now                      - Trigger the full folder scan immediately")
    print("  kv logs                          - Watch live scan logs (Ctrl+C to exit)")
    print("  kv quarantine                    - List all files locked in quarantine")
    print("  kv restore <filename>            - Unlock and restore a file to restore_path")
    print("  kv purge                         - Permanently delete all quarantined files")
    print("  kv restart / stop / start        - Manage the background service")
    print("  kv uninstall                     - Completely remove Kernel Antivirus")

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
                print(f"{pinfo['pid']:<6} | {cpu:<6.1f} | {mem:<6.1f} | {pinfo['name']}")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def scan_file(filepath):
    path = Path(filepath)
    if not path.exists():
        print(f"[-] File not found: {filepath}")
        return
    print(f"[+] Hashing {path.name}...")
    file_hash = get_file_hash(path)
    if not file_hash:
        return
    print(f"[+] Checking VirusTotal for hash: {file_hash}")
    result = check_virustotal(file_hash)
    if not result:
        return
    if result.get("status") == "not_found":
        print("[+] Clean: File not found in VirusTotal database (unknown/clean file).")
    else:
        mal = result.get("malicious", 0)
        sus = result.get("suspicious", 0)
        if mal > 0 or sus > 0:
            print(f"[-] WARNING: Flagged as malicious by {mal} engines (Suspicious: {sus})!")
        else:
            print("[+] Clean: No malicious detections found.")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        cmd = sys.argv[1]
        args = sys.argv[2:]
        
        if cmd == "procs":
            audit_processes()
        elif cmd == "api_key" and args:
            cfg = load_config()
            cfg["vt_api_key"] = args[0]
            save_config(cfg)
            print("[+] VirusTotal API key saved successfully.")
        elif cmd == "scan" and args:
            scan_file(args[0])
        elif cmd == "config":
            print(json.dumps(load_config(), indent=2))
        else:
            show_help()
    else:
        show_help()