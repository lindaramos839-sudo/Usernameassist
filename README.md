# Usernameassist

A collection of network monitoring and username utility tools.

## Projects

### 1. NetWatcher - Network Monitor & Suspicious IP Investigator

An all-in-one network monitoring tool that detects and investigates suspicious IP addresses.

#### Features

- Network monitoring via scapy packet sniffing (if available) or psutil connection polling
- Worker queue for controlled enrichment tasks
- Comprehensive IP enrichment:
  - Reverse DNS lookup
  - WHOIS information
  - Geolocation (via ip-api)
  - TLS certificate inspection
  - Asynchronous port probing
  - Optional AbuseIPDB lookups (requires API key)
  - Optional VirusTotal lookups (requires API key)
  - Optional nmap scanning (requires nmap binary and explicit consent)
- SQLite storage with JSON and human-readable text logs
- Live terminal dashboard using rich library
- Optional Flask web dashboard with:
  - Basic authentication
  - Filtering capabilities
  - CSV export
- Multiple alert mechanisms:
  - Desktop notifications (notify-send on Linux)
  - Slack webhook integration
  - SMTP email alerts
  - Termux notifications and vibration (for Android)
- Safe defaults: active scans require explicit consent, features gracefully skip if dependencies or API keys are missing

#### Requirements

**Required:**
- Python 3.7+

**Optional (for enhanced features):**
- `requests` - For API lookups (geo, AbuseIPDB, VirusTotal)
- `psutil` - For network connection monitoring (fallback if scapy unavailable)
- `scapy` - For packet sniffing (requires root privileges)
- `dnspython` - For DNS lookups
- `python-whois` - For WHOIS information
- `rich` - For live terminal dashboard
- `flask` - For web dashboard
- `python-nmap` - For nmap integration
- `nmap` binary - For network scanning

#### Installation

```bash
# Install base dependencies
pip install requests psutil

# Install optional dependencies for full features
pip install scapy dnspython python-whois rich flask python-nmap
```

For Termux users:
```bash
pkg update && pkg install python
pip install requests psutil
# Install termux-api for notifications
pkg install termux-api
```

#### Usage

**Basic monitoring with psutil (recommended for non-root users):**
```bash
python3 netwatcher.py --mode psutil
```

**Packet sniffing with scapy (requires root):**
```bash
sudo python3 netwatcher.py --mode scapy
```

**Live terminal dashboard:**
```bash
python3 netwatcher.py --mode dashboard
```

**Web dashboard:**
```bash
python3 netwatcher.py --mode flask
# Access at http://127.0.0.1:5000
```

**With nmap scanning (requires explicit consent):**
```bash
python3 netwatcher.py --mode psutil --enable-nmap --scan-consent
```

**Customize worker threads:**
```bash
python3 netwatcher.py --mode psutil --workers 4
```

#### Configuration

Configure via environment variables:

**General:**
- `CHECK_INTERVAL` - Seconds between psutil polls (default: 5)
- `SUSPICIOUS_CONN_THRESHOLD` - Connection count to trigger investigation (default: 5)
- `RECENT_WINDOW_SECONDS` - Time window for connection counting (default: 60)
- `WORKER_COUNT` - Number of enrichment worker threads (default: 2)

**Output:**
- `OUTPUT_JSON` - JSON output file (default: netwatcher_output.json)
- `OUTPUT_TEXT` - Text report file (default: netwatcher_report.txt)
- `SQLITE_DB` - SQLite database file (default: netwatcher.db)

**Port Probing:**
- `PORT_PROBE_ENABLED` - Enable port probing (default: 1)
- `PORTS_TO_PROBE` - Comma-separated ports to probe (default: 22,80,443,3389)
- `PORT_PROBE_TIMEOUT` - Timeout per port in seconds (default: 2.0)
- `MAX_CONCURRENT_PROBES` - Max concurrent port probes (default: 200)

**API Keys:**
- `ABUSEIPDB_API_KEY` - AbuseIPDB API key
- `VIRUSTOTAL_API_KEY` - VirusTotal API key

**Alerts:**
- `SLACK_WEBHOOK_URL` - Slack webhook for alerts
- `ALERT_SMTP_HOST` - SMTP server for email alerts
- `ALERT_SMTP_PORT` - SMTP port (default: 25)
- `ALERT_SMTP_USER` - SMTP username
- `ALERT_SMTP_PASS` - SMTP password
- `ALERT_EMAIL_TO` - Alert recipient email

**Dashboard:**
- `DASH_USER` - Web dashboard username (optional)
- `DASH_PASS` - Web dashboard password (optional)
- `FLASK_HOST` - Flask host (default: 127.0.0.1)
- `FLASK_PORT` - Flask port (default: 5000)

**Misc:**
- `CUSTOM_WATCHLIST` - Comma-separated IPs to always enrich
- `ENRICHMENT_COOLDOWN` - Seconds before re-enriching same IP (default: 3600)
- `NMAP_BINARY` - Path to nmap binary (default: nmap)
- `FORCE_TERMUX` - Force Termux mode (1 or 0)

#### Example

```bash
# Set API keys
export ABUSEIPDB_API_KEY="your-key-here"
export VIRUSTOTAL_API_KEY="your-key-here"

# Set Slack webhook
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"

# Start monitoring
python3 netwatcher.py --mode psutil
```

#### Important Notes

- **Root privileges required** for packet sniffing with scapy
- **Active scanning** (port probes, nmap) are network actions - ensure you have authorization
- **API rate limits** apply for AbuseIPDB and VirusTotal
- Active scans require explicit `--scan-consent` flag for safety

### 2. Bruteforce and Scraper Utility

A utility for generating wordlists and scraping user information.

#### Features

- Generate custom wordlists with configurable character sets and lengths
- Repair wordlists by removing duplicates and blank lines
- Scrape usernames from websites to find emails and phone numbers

#### Usage

**Generate a wordlist:**
```bash
python3 bruteforce_and_scraper.py generate abc123 3 5 mywordlist.txt
```

**Repair a wordlist:**
```bash
python3 bruteforce_and_scraper.py repair mywordlist.txt cleaned_wordlist.txt
```

**Scrape usernames:**
```bash
python3 bruteforce_and_scraper.py scrape usernames.txt "https://somesite.com/{username}" results.txt 50
```

## License

See LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

These tools are for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using these tools on any network or system they do not own.
