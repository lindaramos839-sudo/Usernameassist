#!/usr/bin/env python3
"""
See
All-in-one network monitor & suspicious-IP investigator.

Features ifi sh nñncluded:
-  monitoring via scapy sniffing (if available) or psutil polling
- Worker queue for controlled enrichment tasks
- Enrichment: reverse DNS, WHOIS, geo (ip-api), TLS cert, async port probe
- Optional AbuseIPDB and VirusTotal lookups (API keys via env vars)
- Optional nmap wrapper (requires nmap binary + --enable-nmap + --scan-consent)
- SQLite storage, JSON + human-readable text logs
- Live terminal dashboard (rich)
- Optional Flask web dashboard with basic auth, filtering & CSV export
- Alerts: desktop notify (notify-send), Slack webhook, SMTP email, Termux notification/vibrate
- Safe defaults: active scans require explicit consent; features skip if deps/keys missing.

IMPORTANT:
- Running packet sniffing requires root privileges.
- Active probes/scans are network actions — ensure you have authorization.
"""

import os
import sys
import time
import json
import socket
import ssl
import threading
import argparse
import sqlite3
import asyncio
import subprocess
import smtplib
import queue
import csv
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from collections import defaultdict, deque

# Third-party imports (optional features handled gracefully)
try:
    import psutil
except Exception:
    psutil = None

try:
    import dns.resolver
except Exception:
    dns = None

try:
    import whois as whois_lib
except Exception:
    whois_lib = None

try:
    import scapy.all as scapy
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

try:
    from rich.live import Live
    from rich.table import Table
    from rich.console import Console
    RICH_AVAILABLE = True
except Exception:
    RICH_AVAILABLE = False

try:
    from flask import Flask, jsonify, request, render_template_string, abort, Response
    FLASK_AVAILABLE = True
except Exception:
    FLASK_AVAILABLE = False

try:
    import nmap as nmaplib
    PY_NMAP = True
except Exception:
    PY_NMAP = False

# -------------------------
# Configuration (tweak with env vars as needed)
# -------------------------
CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL") or 5)
SUSPICIOUS_CONN_THRESHOLD = int(os.getenv("SUSPICIOUS_CONN_THRESHOLD") or 5)
RECENT_WINDOW_SECONDS = int(os.getenv("RECENT_WINDOW_SECONDS") or 60)

OUTPUT_JSON = os.getenv("OUTPUT_JSON") or "netwatcher_output.json"
OUTPUT_TEXT = os.getenv("OUTPUT_TEXT") or "netwatcher_report.txt"
SQLITE_DB = os.getenv("SQLITE_DB") or "netwatcher.db"

PORT_PROBE_ENABLED = os.getenv("PORT_PROBE_ENABLED", "1") != "0"
PORTS_TO_PROBE = [int(x) for x in (os.getenv("PORTS_TO_PROBE") or "22,80,443,3389").split(",") if x]
PORT_PROBE_TIMEOUT = float(os.getenv("PORT_PROBE_TIMEOUT") or 2.0)
MAX_CONCURRENT_PROBES = int(os.getenv("MAX_CONCURRENT_PROBES") or 200)

ENRICHMENT_COOLDOWN = int(os.getenv("ENRICHMENT_COOLDOWN") or 3600)

GEO_LOOKUP_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,query,lat,lon,reverse,proxy,hosting"

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"

CUSTOM_WATCHLIST = os.getenv("CUSTOM_WATCHLIST", "") .split(",") if os.getenv("CUSTOM_WATCHLIST") else []

# Alerts
SLACK_WEBHOOK = os.getenv("SLACK_WEBHOOK_URL")
ALERT_SMTP_HOST = os.getenv("ALERT_SMTP_HOST")
ALERT_SMTP_PORT = int(os.getenv("ALERT_SMTP_PORT") or 0) if os.getenv("ALERT_SMTP_PORT") else None
ALERT_SMTP_USER = os.getenv("ALERT_SMTP_USER")
ALERT_SMTP_PASS = os.getenv("ALERT_SMTP_PASS")
ALERT_EMAIL_TO = os.getenv("ALERT_EMAIL_TO")

# Dashboard auth
DASH_USER = os.getenv("DASH_USER")
DASH_PASS = os.getenv("DASH_PASS")

# nmap
NMAP_BINARY = os.getenv("NMAP_BINARY") or "nmap"

# Termux detection
IS_TERMUX = os.getenv("TERM") is not None and "termux" in os.getenv("PREFIX", "") .lower() if os.getenv("PREFIX") else False
# Instead of risking false TERMUX detection, we also allow environment override
if os.getenv("FORCE_TERMUX") == "1":
    IS_TERMUX = True

# Worker queue
WORKER_COUNT = int(os.getenv("WORKER_COUNT") or 2)
TASK_QUEUE_MAXSIZE = int(os.getenv("TASK_QUEUE_MAXSIZE") or 200)

# -------------------------
# Internal state
# -------------------------
_recent_events = defaultdict(lambda: deque())
_last_enriched = {}
_lock = threading.Lock()
TASK_QUEUE = queue.Queue(maxsize=TASK_QUEUE_MAXSIZE)

console = Console() if RICH_AVAILABLE else None
suspicious_ips = {}  # ip -> last enrichment summary dict

# -------------------------
# Storage initialization
# -------------------------
def init_db():
    conn = sqlite3.connect(SQLITE_DB, check_same_thread=False)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS enrichments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT,
        timestamp TEXT,
        json_record TEXT
    )""")
    conn.commit()
    return conn

_DB_CONN = init_db()

# -------------------------
# Utilities & lookups
# -------------------------
def now_ts():
    return datetime.utcnow().isoformat() + "Z"

def is_private_ip(ip):
    try:
        import ipaddress
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False

def record_connection_event(ip):
    with _lock:
        dq = _recent_events[ip]
        dq.append(time.time())
        cutoff = time.time() - RECENT_WINDOW_SECONDS
        while dq and dq[0] < cutoff:
            dq.popleft()

def recent_conn_count(ip):
    with _lock:
        return len(_recent_events[ip])

def append_json(record):
    try:
        with _lock:
            try:
                with open(OUTPUT_JSON, "r") as f:
                    data = json.load(f)
            except Exception:
                data = []
            data.append(record)
            with open(OUTPUT_JSON, "w") as f:
                json.dump(data, f, indent=2)
    except Exception as e:
        print("Failed to write JSON:", e)

def human_summary_from_enrichment(en):
    lines = []
    lines.append(f"Timestamp: {en.get('timestamp')}")
    lines.append(f"IP: {en.get('ip')}")
    lines.append(f"Reverse DNS: {en.get('reverse_dns') or 'N/A'}")
    geo = en.get('geo')
    if isinstance(geo, dict) and geo.get("status") == "success":
        lines.append(f"Geo: {geo.get('country')} / {geo.get('regionName')} / {geo.get('city')} - ISP: {geo.get('isp')}")
    else:
        lines.append(f"Geo: {geo}")
    who = en.get("whois")
    lines.append(f"WHOIS: {who if who else 'N/A'}")
    tls = en.get('tls_cert')
    if isinstance(tls, dict) and tls.get("subject"):
        lines.append(f"TLS cert subject: {tls.get('subject')}")
    else:
        lines.append(f"TLS cert: {tls}")
    lines.append(f"Port probe: {en.get('port_probe')}")
    lines.append(f"AbuseIPDB: {en.get('abuseipdb')}")
    lines.append(f"VirusTotal: {en.get('virustotal')}")
    if en.get('nmap'):
        lines.append(f"nmap: {en.get('nmap')}")
    lines.append("-" * 60)
    return "\n".join(lines)

def append_text_summary(en):
    try:
        txt = human_summary_from_enrichment(en)
        with _lock:
            with open(OUTPUT_TEXT, "a") as f:
                f.write(txt + "\n")
    except Exception as e:
        print("Failed to write report:", e)

def append_db(en):
    try:
        cur = _DB_CONN.cursor()
        cur.execute("INSERT INTO enrichments (ip, timestamp, json_record) VALUES (?, ?, ?)",
                    (en.get('ip'), en.get('timestamp'), json.dumps(en)))
        _DB_CONN.commit()
    except Exception as e:
        print("SQLite write error:", e)

# -------------------------
# DNS / reverse
# -------------------------
def reverse_dns(ip):
    try:
        if dns:
            # newer dnspython supports resolve_address
            try:
                answers = dns.resolver.resolve_address(ip)
                return str(answers[0]).rstrip('.')
            except Exception:
                pass
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

# -------------------------
# WHOIS
# -------------------------
def whois_lookup(ip):
    if whois_lib is None:
        return {"error": "python-whois not installed"}
    try:
        w = whois_lib.whois(ip)
        # small subset
        return {"domain_name": w.get("domain_name"), "org": w.get("org"), "emails": w.get("emails")}
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Geo lookup
# -------------------------
def geo_lookup(ip):
    try:
        r = requests.get(GEO_LOOKUP_URL.format(ip=ip), timeout=6)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# TLS cert
# -------------------------
def tls_cert_info(ip, port=443):
    try:
        ctx = ssl.create_default_context()
        sock = socket.create_connection((ip, port), timeout=3)
        ss = ctx.wrap_socket(sock, server_hostname=ip)
        cert = ss.getpeercert()
        ss.close()
        return cert
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Async port probe
# -------------------------
async def probe_port(ip, port, timeout):
    loop = asyncio.get_event_loop()
    try:
        fut = loop.create_connection(lambda: asyncio.Protocol(), host=ip, port=port)
        conn = await asyncio.wait_for(fut, timeout=timeout)
        transport, protocol = conn
        transport.close()
        return True
    except Exception:
        return False

async def probe_ports_async(ip, ports, timeout, semaphore_limit):
    sem = asyncio.Semaphore(semaphore_limit)
    results = {}
    async def _probe(p):
        async with sem:
            ok = await probe_port(ip, p, timeout)
            results[p] = ok
    tasks = [_probe(p) for p in ports]
    await asyncio.gather(*tasks)
    return results

def port_probe(ip, ports=None):
    if not PORT_PROBE_ENABLED:
        return {"skipped": "disabled"}
    if ports is None:
        ports = PORTS_TO_PROBE
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        results = loop.run_until_complete(probe_ports_async(ip, ports, PORT_PROBE_TIMEOUT, MAX_CONCURRENT_PROBES))
        loop.close()
        return results
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# AbuseIPDB & VirusTotal
# -------------------------
def abuseipdb_check(ip):
    if not ABUSEIPDB_API_KEY:
        return {"skipped": "no_api_key"}
    try:
        headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
        params = {"ipAddress": ip}
        r = requests.get(ABUSEIPDB_URL, headers=headers, params=params, timeout=6)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"status {r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def virustotal_check(ip):
    if not VIRUSTOTAL_API_KEY:
        return {"skipped": "no_api_key"}
    try:
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        r = requests.get(VIRUSTOTAL_URL.format(ip=ip), headers=headers, timeout=8)
        if r.status_code == 200:
            return r.json()
        else:
            return {"error": f"status {r.status_code}", "body": r.text}
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# nmap wrapper
# -------------------------
def nmap_scan(ip, ports="1-1024", args=None):
    try:
        if PY_NMAP:
            nm = nmaplib.PortScanner()
            extra = args or "-sS -Pn -T3"
            nm.scan(hosts=ip, ports=ports, arguments=extra)
            return nm[ip] if ip in nm.all_hosts() else {}
        else:
            nmap_cmd = [NMAP_BINARY, "-Pn", "-sS", "-p", ports, ip]
            if args:
                nmap_cmd = [NMAP_BINARY] + args.split() + ["-p", ports, ip]
            proc = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=120)
            return {"stdout": proc.stdout, "stderr": proc.stderr, "rc": proc.returncode}
    except FileNotFoundError:
        return {"error": "nmap binary not found"}
    except Exception as e:
        return {"error": str(e)}

# -------------------------
# Alerts
# -------------------------
def send_slack_alert(text):
    if not SLACK_WEBHOOK:
        return {"skipped": "no_webhook"}
    try:
        r = requests.post(SLACK_WEBHOOK, json={"text": text}, timeout=5)
        return {"status": r.status_code, "body": r.text}
    except Exception as e:
        return {"error": str(e)}

def send_email_alert(subject, body):
    if not ALERT_SMTP_HOST or not ALERT_EMAIL_TO:
        return {"skipped": "no_smtp_config"}
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = ALERT_SMTP_USER or "netwatcher@localhost"
        msg["To"] = ALERT_EMAIL_TO
        s = smtplib.SMTP(ALERT_SMTP_HOST, ALERT_SMTP_PORT or 25, timeout=10)
        s.starttls()
        if ALERT_SMTP_USER and ALERT_SMTP_PASS:
            s.login(ALERT_SMTP_USER, ALERT_SMTP_PASS)
        s.send_message(msg)
        s.quit()
        return {"sent": True}
    except Exception as e:
        return {"error": str(e)}

def termux_alert(ip):
    # Requires termux-api installed
    try:
        os.system(f'termux-notification --title "Suspicious IP" --content "IP: {ip}" --priority high')
        os.system("termux-vibrate -d 500")
        return {"termux": "ok"}
    except Exception as e:
        return {"error": str(e)}

def desktop_notify(ip):
    try:
        # Linux notify-send
        if sys.platform.startswith("linux"):
            os.system(f'notify-send "Suspicious IP Detected" "IP: {ip}"')
            # terminal beep
            sys.stdout.write("\a"); sys.stdout.flush()
            return {"desktop": "sent"}
        # Windows fallback
        if sys.platform.startswith("win"):
            try:
                import winsound
                winsound.Beep(1000, 300)
                return {"desktop": "beeped"}
            except Exception:
                return {"error": "winsound failed"}
        # macOS fallback to terminal bell
        sys.stdout.write("\a"); sys.stdout.flush()
        return {"desktop": "bell"}
    except Exception as e:
        return {"error": str(e)}

def send_alerts_if_needed(en):
    # Simple heuristic: abuse score or vt malicious >0 or many recent connections.
    alerts = []
    abuse = en.get("abuseipdb")
    if isinstance(abuse, dict):
        try:
            score = abuse.get("data", {}).get("abuseConfidenceScore")
            if score and int(score) >= 75:
                alerts.append(f"AbuseIPDB score {score}")
        except Exception:
            pass
    vt = en.get("virustotal")
    if isinstance(vt, dict) and vt.get("data"):
        try:
            stats = vt["data"]["attributes"].get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0) if stats else 0
            if malicious and malicious > 0:
                alerts.append(f"VirusTotal malicious engines: {malicious}")
        except Exception:
            pass
    try:
        cnt = recent_conn_count(en.get("ip"))
        if cnt >= (SUSPICIOUS_CONN_THRESHOLD * 3):
            alerts.append(f"High connection count: {cnt}")
    except Exception:
        pass

    if alerts:
        text = f"NetWatcher alert for {en.get('ip')}: " + "; ".join(alerts)
        results = {}
        results["slack"] = send_slack_alert(text) if SLACK_WEBHOOK else {"skipped": "no_slack"}
        results["email"] = send_email_alert(f"NetWatcher Alert: {en.get('ip')}", text + "\n\nFull record:\n" + json.dumps(en, indent=2)) if ALERT_SMTP_HOST else {"skipped": "no_smtp"}
        return results
    return {"no_alert": True}

# -------------------------
# Enrichment pipeline
# -------------------------
def enrich_ip(ip, do_nmap=False, nmap_ports="1-1024", nmap_args=None, scan_consent=False):
    now = time.time()
    last = _last_enriched.get(ip, 0)
    if now - last < ENRICHMENT_COOLDOWN:
        return None
    _last_enriched[ip] = now

    out = {
        "ip": ip,
        "timestamp": now_ts(),
        "reverse_dns": None,
        "whois": None,
        "geo": None,
        "tls_cert": None,
        "port_probe": None,
        "abuseipdb": None,
        "virustotal": None,
        "nmap": None,
    }

    try:
        out["reverse_dns"] = reverse_dns(ip)
    except Exception as e:
        out["reverse_dns"] = {"error": str(e)}

    try:
        if whois_lib:
            out["whois"] = whois_lookup(ip)
    except Exception as e:
        out["whois"] = {"error": str(e)}

    try:
        out["geo"] = geo_lookup(ip)
    except Exception as e:
        out["geo"] = {"error": str(e)}

    try:
        out["tls_cert"] = tls_cert_info(ip)
    except Exception as e:
        out["tls_cert"] = {"error": str(e)}

    if PORT_PROBE_ENABLED:
        try:
            out["port_probe"] = port_probe(ip)
        except Exception as e:
            out["port_probe"] = {"error": str(e)}

    try:
        out["abuseipdb"] = abuseipdb_check(ip)
    except Exception as e:
        out["abuseipdb"] = {"error": str(e)}

    try:
        out["virustotal"] = virustotal_check(ip)
    except Exception as e:
        out["virustotal"] = {"error": str(e)}

    if do_nmap:
        if not scan_consent:
            out["nmap"] = {"skipped": "no_scan_consent"}
        else:
            try:
                out["nmap"] = nmap_scan(ip, ports=nmap_ports, args=nmap_args)
            except Exception as e:
                out["nmap"] = {"error": str(e)}

    # Persist
    append_json(out)
    append_text_summary(out)
    append_db(out)

    # Update live summary for dashboard
    try:
        summary = {
            "hostname": out.get("reverse_dns"),
            "geo": out.get("geo"),
            "port_probe": out.get("port_probe"),
            "abuseipdb": out.get("abuseipdb"),
            "virustotal": out.get("virustotal"),
            "timestamp": out.get("timestamp")
        }
        with _lock:
            suspicious_ips[ip] = summary
    except Exception:
        pass

    # Alerts (desktop/termux + slack/email via helper)
    try:
        # local notify
        if IS_TERMUX:
            try:
                termux_alert(ip)
            except Exception:
                desktop_notify(ip)
        else:
            desktop_notify(ip)
    except Exception:
        pass

    try:
        send_alerts_if_needed(out)
    except Exception:
        pass

    return out

def enqueue_enrichment(ip, reason, do_nmap=False, nmap_ports="1-1024", nmap_args=None, scan_consent=False):
    payload = {
        "ip": ip,
        "reason": reason,
        "do_nmap": do_nmap,
        "nmap_ports": nmap_ports,
        "nmap_args": nmap_args,
        "scan_consent": scan_consent
    }
    try:
        TASK_QUEUE.put_nowait(payload)
        print(f"[{now_ts()}] Queued enrichment for {ip} ({reason})")
        return True
    except queue.Full:
        print("Task queue full; dropping enrichment for", ip)
        return False

# -------------------------
# Worker queue
# -------------------------
def worker_loop(args):
    while True:
        try:
            task = TASK_QUEUE.get()
            if task is None:
                TASK_QUEUE.task_done()
                break
            ip = task.get("ip")
            do_nmap = task.get("do_nmap", False)
            nmap_ports = task.get("nmap_ports", "1-1024")
            nmap_args = task.get("nmap_args", None)
            scan_consent = task.get("scan_consent", False)
            print(f"[{now_ts()}] Worker processing {ip}")
            enrich_ip(ip, do_nmap=do_nmap, nmap_ports=nmap_ports, nmap_args=nmap_args, scan_consent=scan_consent)
            TASK_QUEUE.task_done()
        except Efinush up
xception as e:
            print("Worker error:", e)
            try:
                TASK_QUEUE.task_done()
        
