# Log Attack Analyzer

A Python-based security log analysis tool that automatically detects attack patterns across multiple log formats. Built for SOC analysts to quickly triage incidents and generate actionable reports.

## Features

- **Multi-format log parsing**: SSH auth.log, Apache/Nginx access.log, Windows Event Logs
- **Attack detection modules**:
  - Brute-force login attempts (SSH/RDP) with sliding window analysis
  - Network/web scanning detection (Nmap, Nikto, DirBuster, etc.)
  - SQL injection payload detection in HTTP requests
  - Suspicious PowerShell command detection (encoded commands, Mimikatz, AMSI bypass, etc.)
- **HTML report generation** with:
  - Executive summary with severity breakdown
  - MITRE ATT&CK technique mapping
  - Indicators of Compromise (IOCs) extraction
  - Attack timeline visualization
  - Raw log evidence samples
- **Attack scenario generator** for testing and demonstration
- **Zero dependencies** — runs on Python 3.11+ standard library only

## Architecture

```
log-analyzer/
├── analyzer.py                    # Main entry point & CLI
├── report_generator.py            # HTML report builder
├── generate_attack_scenario.py    # Multi-attack scenario generator
├── parsers/                       # Log format parsers
│   ├── base_parser.py             # Abstract base class
│   ├── ssh_parser.py              # Linux auth.log parser
│   ├── apache_parser.py           # Apache/Nginx access.log parser
│   └── windows_parser.py          # Windows Event Log parser
├── detectors/                     # Attack detection modules
│   ├── base_detector.py           # Alert dataclass & base class
│   ├── bruteforce.py              # Brute-force login detection
│   ├── network_scan.py            # Scanner & enumeration detection
│   ├── sqli.py                    # SQL injection detection
│   └── powershell.py              # Suspicious PowerShell detection
├── sample_logs/                   # Test data
│   ├── auth.log                   # SSH brute-force samples
│   ├── access.log                 # Web scanning & SQLi samples
│   └── windows_events.log         # Windows attack samples
├── requirements.txt
└── .gitignore
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/Raterfy/Log-Attack-Analyzer.git
cd Log-Attack-Analyzer

# Analyze sample logs
python3 analyzer.py -d sample_logs/

# Generate a full attack scenario and analyze it
python3 generate_attack_scenario.py
python3 analyzer.py -d attack_scenario/ -o attack_report.html

# Open the report
open attack_report.html
```

## Usage

```
usage: analyzer.py [-h] [-f FILES [FILES ...]] [-d DIRECTORY] [-o OUTPUT]

Analyze security logs and detect attack patterns.

options:
  -h, --help            show this help message and exit
  -f, --files FILES     Log files to analyze
  -d, --directory DIR   Directory containing log files
  -o, --output OUTPUT   Output HTML report path (default: report.html)
```

## Attack Scenario Generator

The included `generate_attack_scenario.py` creates realistic logs simulating a full attack chain from 12 threat actors:

| Actor | Type | Details |
|---|---|---|
| 203.0.113.50 | SSH brute-force | 45 attempts, succeeds as root |
| 198.51.100.23 | SSH brute-force | 15 attempts |
| 185.220.101.34 | SSH brute-force | 25 attempts (Tor exit node) |
| 192.0.2.100 | SSH brute-force | 8 attempts spread over hours (evasion) |
| 203.0.113.77 | Web scanning | Nmap — 33 paths |
| 192.0.2.200 | Web scanning | Nikto — 20 paths |
| 172.16.50.99 | Web scanning | DirBuster — 35 paths |
| 198.51.100.44 | SQL injection | sqlmap — 20 payloads |
| 45.33.32.156 | SQL injection | Manual — 3 payloads |
| 172.16.0.50 | RDP brute-force | 20 attempts |
| 10.99.88.77 | RDP brute-force | 12 attempts |
| compromised_user | Post-exploitation | Mimikatz, AMSI bypass, AV disable, exfiltration |

```bash
python3 generate_attack_scenario.py
python3 analyzer.py -d attack_scenario/ -o attack_report.html
```

## Detection Details

### Brute-Force Detection (T1110)
Counts failed login attempts per source IP using a sliding time window (default: 5 failed logins within 300 seconds). Severity scales with attempt count:
- 5-9 attempts → LOW
- 10-19 → MEDIUM
- 20-49 → HIGH
- 50+ → CRITICAL

### Network Scanning Detection (T1595)
Identifies scanning tools via user-agent strings (Nmap, Nikto, sqlmap, DirBuster, gobuster, wfuzz) and detects path enumeration by tracking unique URI requests per IP (threshold: 15 unique paths or 3+ sensitive paths).

### SQL Injection Detection (T1190)
Matches HTTP request URIs against 16 regex patterns covering UNION-based, time-based blind, error-based, stacked query, and boolean-based injection techniques. URIs are URL-decoded before analysis.

### PowerShell Detection (T1059.001)
Flags 19 suspicious PowerShell patterns in Windows event logs including encoded commands, download cradles (WebClient, Invoke-WebRequest), credential dumping (Mimikatz), defense evasion (AMSI bypass, AV disable), and reflective loading.

## Sample Output

```
============================================================
  LOG ATTACK ANALYZER — SOC Automation Tool
============================================================

  [*] Parsing attack_scenario/access.log (ApacheLogParser)...
      -> 170 events extracted
  [*] Parsing attack_scenario/auth.log (SSHLogParser)...
      -> 106 events extracted
  [*] Parsing attack_scenario/windows_events.log (WindowsEventParser)...
      -> 57 events extracted

  [+] Total events: 333

  [BruteforceDetector] 3 alert(s)
    🔴 [CRITICAL] Brute-Force Attack from 203.0.113.50
    🟠 [HIGH] Brute-Force Attack from 185.220.101.34
    🟡 [MEDIUM] Brute-Force Attack from 198.51.100.23
  [NetworkScanDetector] 7 alert(s)
  [SQLInjectionDetector] 1 alert(s)
  [PowerShellDetector] 8 alert(s)

  ============================================================
  ANALYSIS COMPLETE
  ============================================================
  Total alerts:  19
  Critical:      5
  High:          11
  Medium:        3
  Unique IPs:    7
  Report saved:  attack_report.html
```

## Extending

### Adding a new parser
1. Create a new file in `parsers/`
2. Inherit from `BaseParser` and implement `parse_file()`
3. Return normalized event dictionaries
4. Register in `parsers/__init__.py` and `analyzer.py`

### Adding a new detector
1. Create a new file in `detectors/`
2. Inherit from `BaseDetector` and implement `detect()`
3. Return `Alert` objects with MITRE ATT&CK mapping
4. Register in `detectors/__init__.py` and `analyzer.py`

## License

MIT
