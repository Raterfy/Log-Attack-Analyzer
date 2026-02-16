"""Detect SQL Injection attempts in web access logs."""

import re
from collections import defaultdict
from urllib.parse import unquote

from .base_detector import Alert, BaseDetector

# Common SQLi payloads in URI parameters
SQLI_PATTERNS = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))", re.IGNORECASE),
    re.compile(r"\w*((\%27)|(\'))\s*((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
    re.compile(r"union\s+(all\s+)?select", re.IGNORECASE),
    re.compile(r"select\s+.*\s+from\s+", re.IGNORECASE),
    re.compile(r"insert\s+into\s+", re.IGNORECASE),
    re.compile(r"drop\s+(table|database)", re.IGNORECASE),
    re.compile(r"update\s+\w+\s+set\s+", re.IGNORECASE),
    re.compile(r"exec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"SLEEP\(\d+\)", re.IGNORECASE),
    re.compile(r"BENCHMARK\(\d+", re.IGNORECASE),
    re.compile(r"(AND|OR)\s+\d+=\d+", re.IGNORECASE),
    re.compile(r"1\s*=\s*1", re.IGNORECASE),
    re.compile(r"CONCAT\(", re.IGNORECASE),
    re.compile(r"GROUP\s+BY.+HAVING", re.IGNORECASE),
    re.compile(r"LOAD_FILE\(", re.IGNORECASE),
]


class SQLInjectionDetector(BaseDetector):
    """Detects SQL injection attempts in HTTP request URIs.

    Scans decoded URIs against known SQLi patterns and groups
    findings by source IP.
    """

    def detect(self, events: list[dict]) -> list[Alert]:
        web_events = [e for e in events if e.get("source") == "apache"]

        sqli_by_ip: dict[str, list[dict]] = defaultdict(list)

        for event in web_events:
            uri = unquote(event.get("uri", ""))
            for pattern in SQLI_PATTERNS:
                if pattern.search(uri):
                    sqli_by_ip[event["src_ip"]].append(event)
                    break

        alerts = []
        for ip, hits in sqli_by_ip.items():
            payloads = list({unquote(h["uri"]) for h in hits})
            count = len(hits)

            severity = "CRITICAL" if count >= 10 else "HIGH"

            alerts.append(Alert(
                title=f"SQL Injection Attempts from {ip}",
                severity=severity,
                description=(
                    f"{count} requests containing SQL injection payloads "
                    f"detected from {ip}."
                ),
                source_ips=[ip],
                indicators=payloads[:10],
                mitre_technique="Exploit Public-Facing Application",
                mitre_id="T1190",
                timestamp_start=hits[0].get("timestamp"),
                timestamp_end=hits[-1].get("timestamp"),
                event_count=count,
                raw_samples=[h["raw"] for h in hits[:5]],
            ))

        return alerts
