"""Detect network scanning activity (Nmap, Masscan patterns)."""

import re
from collections import defaultdict

from .base_detector import Alert, BaseDetector

# Nmap/Masscan user-agent signatures
SCANNER_UA_PATTERNS = [
    re.compile(r"Nmap", re.IGNORECASE),
    re.compile(r"masscan", re.IGNORECASE),
    re.compile(r"ZmEu", re.IGNORECASE),
    re.compile(r"Nikto", re.IGNORECASE),
    re.compile(r"sqlmap", re.IGNORECASE),
    re.compile(r"DirBuster", re.IGNORECASE),
    re.compile(r"gobuster", re.IGNORECASE),
    re.compile(r"wfuzz", re.IGNORECASE),
]

# Common scan target paths (directory enumeration, admin panels)
SCAN_PATHS = [
    "/admin", "/wp-admin", "/wp-login.php", "/.env", "/phpinfo.php",
    "/phpmyadmin", "/.git/config", "/actuator", "/api/swagger",
    "/server-status", "/debug", "/console", "/shell", "/backup",
]

UNIQUE_PATH_THRESHOLD = 15  # unique URIs from one IP in short time
REQUEST_RATE_THRESHOLD = 50  # total requests in 60 seconds


class NetworkScanDetector(BaseDetector):
    """Detects network/web scanning by analyzing request patterns.

    Signals:
      - Known scanner user-agents
      - High request rate from a single IP
      - Requests hitting many distinct paths (directory enumeration)
      - Probing known sensitive paths
    """

    def detect(self, events: list[dict]) -> list[Alert]:
        web_events = [e for e in events if e.get("source") == "apache"]

        alerts = []
        alerts.extend(self._detect_scanner_ua(web_events))
        alerts.extend(self._detect_path_enumeration(web_events))
        return alerts

    def _detect_scanner_ua(self, events: list[dict]) -> list[Alert]:
        """Flag requests with known scanner user-agents."""
        scanner_hits: dict[str, list[dict]] = defaultdict(list)

        for event in events:
            ua = event.get("user_agent", "")
            for pattern in SCANNER_UA_PATTERNS:
                if pattern.search(ua):
                    scanner_hits[event["src_ip"]].append(event)
                    break

        alerts = []
        for ip, hits in scanner_hits.items():
            tools = set()
            for h in hits:
                for p in SCANNER_UA_PATTERNS:
                    if p.search(h.get("user_agent", "")):
                        tools.add(p.pattern)
            alerts.append(Alert(
                title=f"Scanner Tool Detected from {ip}",
                severity="HIGH",
                description=(
                    f"Known scanning tool detected from {ip}. "
                    f"{len(hits)} requests. Tools: {', '.join(tools)}"
                ),
                source_ips=[ip],
                indicators=list(tools),
                mitre_technique="Active Scanning",
                mitre_id="T1595",
                timestamp_start=hits[0].get("timestamp"),
                timestamp_end=hits[-1].get("timestamp"),
                event_count=len(hits),
                raw_samples=[h["raw"] for h in hits[:5]],
            ))
        return alerts

    def _detect_path_enumeration(self, events: list[dict]) -> list[Alert]:
        """Detect directory/path enumeration from a single IP."""
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for event in events:
            by_ip[event["src_ip"]].append(event)

        alerts = []
        for ip, ip_events in by_ip.items():
            unique_paths = {e["uri"] for e in ip_events}
            sensitive_hits = [p for p in unique_paths if p in SCAN_PATHS]

            if len(unique_paths) >= UNIQUE_PATH_THRESHOLD or len(sensitive_hits) >= 3:
                severity = "CRITICAL" if len(sensitive_hits) >= 5 else "HIGH"
                alerts.append(Alert(
                    title=f"Path Enumeration from {ip}",
                    severity=severity,
                    description=(
                        f"{ip} requested {len(unique_paths)} unique paths. "
                        f"Sensitive paths hit: {', '.join(sensitive_hits) or 'none'}"
                    ),
                    source_ips=[ip],
                    indicators=sensitive_hits,
                    mitre_technique="Active Scanning",
                    mitre_id="T1595",
                    event_count=len(ip_events),
                    raw_samples=[e["raw"] for e in ip_events[:5]],
                ))
        return alerts
