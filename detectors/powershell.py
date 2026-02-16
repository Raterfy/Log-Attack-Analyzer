"""Detect suspicious PowerShell commands in Windows event logs."""

import re

from .base_detector import Alert, BaseDetector

# Suspicious PowerShell patterns (common in malware/post-exploitation)
SUSPICIOUS_PS_PATTERNS = [
    (re.compile(r"Invoke-Expression", re.IGNORECASE), "Invoke-Expression (IEX)"),
    (re.compile(r"\bIEX\b", re.IGNORECASE), "IEX shorthand"),
    (re.compile(r"Invoke-WebRequest", re.IGNORECASE), "Web download"),
    (re.compile(r"Net\.WebClient", re.IGNORECASE), "WebClient download"),
    (re.compile(r"DownloadString", re.IGNORECASE), "DownloadString"),
    (re.compile(r"DownloadFile", re.IGNORECASE), "DownloadFile"),
    (re.compile(r"-enc\s", re.IGNORECASE), "Encoded command"),
    (re.compile(r"-EncodedCommand", re.IGNORECASE), "Encoded command"),
    (re.compile(r"FromBase64String", re.IGNORECASE), "Base64 decode"),
    (re.compile(r"Start-Process", re.IGNORECASE), "Process execution"),
    (re.compile(r"Invoke-Mimikatz", re.IGNORECASE), "Mimikatz"),
    (re.compile(r"Invoke-Shellcode", re.IGNORECASE), "Shellcode injection"),
    (re.compile(r"Set-MpPreference.*-DisableRealtimeMonitoring", re.IGNORECASE), "Disable AV"),
    (re.compile(r"Add-MpPreference.*-ExclusionPath", re.IGNORECASE), "AV exclusion"),
    (re.compile(r"New-Object\s+System\.Net", re.IGNORECASE), "Network object"),
    (re.compile(r"System\.Reflection\.Assembly", re.IGNORECASE), "Reflective loading"),
    (re.compile(r"bypass", re.IGNORECASE), "Execution policy bypass"),
    (re.compile(r"hidden\s*window", re.IGNORECASE), "Hidden window"),
    (re.compile(r"AMSI.*bypass", re.IGNORECASE), "AMSI bypass"),
]


class PowerShellDetector(BaseDetector):
    """Detects suspicious PowerShell activity in Windows event logs.

    Focuses on Event ID 4688 (process creation) and message content
    matching known offensive PowerShell patterns.
    """

    def detect(self, events: list[dict]) -> list[Alert]:
        windows_events = [
            e for e in events
            if e.get("source") == "windows"
        ]

        alerts = []
        for event in windows_events:
            message = event.get("message", "") + " " + event.get("raw", "")
            matched_techniques = []

            for pattern, label in SUSPICIOUS_PS_PATTERNS:
                if pattern.search(message):
                    matched_techniques.append(label)

            if not matched_techniques:
                continue

            severity = self._compute_severity(matched_techniques)

            alerts.append(Alert(
                title=f"Suspicious PowerShell on {event.get('computer', 'unknown')}",
                severity=severity,
                description=(
                    f"Suspicious PowerShell detected: "
                    f"{', '.join(matched_techniques)}. "
                    f"User: {event.get('user', 'unknown')}"
                ),
                source_ips=[event.get("src_ip", "local")],
                indicators=matched_techniques,
                mitre_technique="Command and Scripting Interpreter: PowerShell",
                mitre_id="T1059.001",
                timestamp_start=event.get("timestamp"),
                event_count=1,
                raw_samples=[event["raw"]],
            ))

        return alerts

    @staticmethod
    def _compute_severity(techniques: list[str]) -> str:
        critical_keywords = {"Mimikatz", "Shellcode injection", "AMSI bypass", "Disable AV"}
        if critical_keywords & set(techniques):
            return "CRITICAL"
        high_keywords = {"Encoded command", "Base64 decode", "Reflective loading", "DownloadString"}
        if high_keywords & set(techniques):
            return "HIGH"
        if len(techniques) >= 3:
            return "HIGH"
        return "MEDIUM"
