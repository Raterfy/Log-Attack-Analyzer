#!/usr/bin/env python3
"""
Log Attack Analyzer — SOC Automation Tool

Parses security logs (SSH, Apache, Windows Event Logs) and automatically
detects attack patterns including brute-force, network scanning, SQL injection,
and suspicious PowerShell activity. Generates an HTML report with IOCs,
attack timeline, and MITRE ATT&CK mapping.

Usage:
    python analyzer.py -f sample_logs/auth.log sample_logs/access.log sample_logs/windows_events.log
    python analyzer.py -d sample_logs/
    python analyzer.py -f sample_logs/auth.log -o my_report.html
"""

import argparse
import os
import sys

from parsers import SSHLogParser, ApacheLogParser, WindowsEventParser
from detectors import (
    BruteforceDetector,
    NetworkScanDetector,
    SQLInjectionDetector,
    PowerShellDetector,
)
from report_generator import generate_report

# Map file patterns to parsers
PARSER_MAP = {
    "auth": SSHLogParser(),
    "ssh": SSHLogParser(),
    "access": ApacheLogParser(),
    "apache": ApacheLogParser(),
    "nginx": ApacheLogParser(),
    "windows": WindowsEventParser(),
    "event": WindowsEventParser(),
}

DETECTORS = [
    BruteforceDetector(),
    NetworkScanDetector(),
    SQLInjectionDetector(),
    PowerShellDetector(),
]


def detect_parser(filepath: str):
    """Auto-detect the right parser based on filename."""
    basename = os.path.basename(filepath).lower()
    for keyword, parser in PARSER_MAP.items():
        if keyword in basename:
            return parser
    return None


def analyze_files(filepaths: list[str], output: str) -> None:
    """Main analysis pipeline."""
    all_events = []
    analyzed_files = []

    print(f"\n{'='*60}")
    print("  LOG ATTACK ANALYZER — SOC Automation Tool")
    print(f"{'='*60}\n")

    # Phase 1: Parse logs
    for filepath in filepaths:
        if not os.path.isfile(filepath):
            print(f"  [!] File not found: {filepath}")
            continue

        parser = detect_parser(filepath)
        if not parser:
            print(f"  [!] Unknown log format: {filepath} (skipping)")
            continue

        print(f"  [*] Parsing {filepath} ({parser.__class__.__name__})...")
        events = parser.parse_file(filepath)
        print(f"      -> {len(events)} events extracted")
        all_events.extend(events)
        analyzed_files.append(filepath)

    if not all_events:
        print("\n  [!] No events found. Check your log files.")
        sys.exit(1)

    print(f"\n  [+] Total events: {len(all_events)}")

    # Phase 2: Run detectors
    print(f"\n{'─'*60}")
    print("  Running detection modules...\n")

    all_alerts = []
    for detector in DETECTORS:
        name = detector.__class__.__name__
        alerts = detector.detect(all_events)
        print(f"  [{name}] {len(alerts)} alert(s)")
        for alert in alerts:
            color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(alert.severity, "⚪")
            print(f"    {color} [{alert.severity}] {alert.title}")
        all_alerts.extend(alerts)

    # Phase 3: Generate report
    print(f"\n{'─'*60}")
    print(f"  Generating report -> {output}\n")

    html = generate_report(all_alerts, analyzed_files)
    with open(output, "w") as f:
        f.write(html)

    # Summary
    severities = {}
    for a in all_alerts:
        severities[a.severity] = severities.get(a.severity, 0) + 1

    unique_ips = {ip for a in all_alerts for ip in a.source_ips if ip and ip != "local"}

    print(f"  {'='*60}")
    print(f"  ANALYSIS COMPLETE")
    print(f"  {'='*60}")
    print(f"  Total alerts:  {len(all_alerts)}")
    print(f"  Critical:      {severities.get('CRITICAL', 0)}")
    print(f"  High:          {severities.get('HIGH', 0)}")
    print(f"  Medium:        {severities.get('MEDIUM', 0)}")
    print(f"  Low:           {severities.get('LOW', 0)}")
    print(f"  Unique IPs:    {len(unique_ips)}")
    print(f"  Report saved:  {output}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Analyze security logs and detect attack patterns.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "-f", "--files",
        nargs="+",
        help="Log files to analyze",
    )
    parser.add_argument(
        "-d", "--directory",
        help="Directory containing log files",
    )
    parser.add_argument(
        "-o", "--output",
        default="report.html",
        help="Output HTML report path (default: report.html)",
    )

    args = parser.parse_args()

    filepaths = []

    if args.files:
        filepaths.extend(args.files)

    if args.directory:
        if not os.path.isdir(args.directory):
            print(f"[!] Directory not found: {args.directory}")
            sys.exit(1)
        for fname in sorted(os.listdir(args.directory)):
            full = os.path.join(args.directory, fname)
            if os.path.isfile(full) and not fname.startswith("."):
                filepaths.append(full)

    if not filepaths:
        parser.print_help()
        print("\n[!] No input files specified. Use -f or -d.")
        sys.exit(1)

    analyze_files(filepaths, args.output)


if __name__ == "__main__":
    main()
