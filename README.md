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
- **Zero dependencies** — runs on Python 3.11+ standard library only

## Architecture

```
log-analyzer/
├── analyzer.py              # Main entry point & CLI
├── report_generator.py      # HTML report builder
├── parsers/                 # Log format parsers
│   ├── base_parser.py       # Abstract base class
│   ├── ssh_parser.py        # Linux auth.log parser
│   ├── apache_parser.py     # Apache/Nginx access.log parser
│   └── windows_parser.py    # Windows Event Log parser
├── detectors/               # Attack detection modules
│   ├── base_detector.py     # Alert dataclass & base class
│   ├── bruteforce.py        # Brute-force login detection
│   ├── network_scan.py      # Scanner & enumeration detection
│   ├── sqli.py              # SQL injection detection
│   └── powershell.py        # Suspicious PowerShell detection
└── sample_logs/             # Test data
    ├── auth.log             # SSH brute-force samples
    ├── access.log           # Web scanning & SQLi samples
    └── windows_events.log   # Windows attack samples
```

## Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/log-analyzer.git
cd log-analyzer

# Analyze all sample logs
python analyzer.py -d sample_logs/

# Analyze specific files
python analyzer.py -f sample_logs/auth.log sample_logs/access.log

# Custom output path
python analyzer.py -d sample_logs/ -o incident_report.html
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

## Detection Details

### Brute-Force Detection (T1110)
Counts failed login attempts per source IP using a sliding time window (default: 5 failed logins within 300 seconds). Severity scales with attempt count.

### Network Scanning Detection (T1595)
Identifies scanning tools via user-agent strings (Nmap, Nikto, sqlmap, etc.) and detects path enumeration by tracking unique URI requests per IP.

### SQL Injection Detection (T1190)
Matches HTTP request URIs against 16 regex patterns covering UNION-based, time-based blind, error-based, and stacked query injection techniques.

### PowerShell Detection (T1059.001)
Flags suspicious PowerShell patterns in Windows event logs including encoded commands, download cradles, credential dumping tools, and defense evasion techniques.

## Sample Output

Running against the included sample logs:

```
============================================================
  LOG ATTACK ANALYZER — SOC Automation Tool
============================================================

  [*] Parsing sample_logs/access.log (ApacheLogParser)...
      -> 46 events extracted
  [*] Parsing sample_logs/auth.log (SSHLogParser)...
      -> 45 events extracted
  [*] Parsing sample_logs/windows_events.log (WindowsEventParser)...
      -> 18 events extracted

  [+] Total events: 109

──────────────────────────────────────────────────────────────
  Running detection modules...

  [BruteforceDetector] 3 alert(s)
  [NetworkScanDetector] 4 alert(s)
  [SQLInjectionDetector] 1 alert(s)
  [PowerShellDetector] 4 alert(s)

  ============================================================
  ANALYSIS COMPLETE
  ============================================================
  Total alerts:  12
  Report saved:  report.html
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
