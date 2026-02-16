"""Parser for Windows Event Logs exported as text/CSV.

Handles a simplified text format commonly used for exported Security logs:
    EventID|TimeCreated|Computer|Message
    4625|2026-02-10T14:23:01|DC01|An account failed to log on. ... Source: 192.168.1.50
"""

import re
from datetime import datetime

from .base_parser import BaseParser

IP_PATTERN = re.compile(r"(?:Source Network Address|Source:\s*)(\d+\.\d+\.\d+\.\d+)")
USER_PATTERN = re.compile(r"Account Name:\s*(\S+)")

# Event IDs relevant to security monitoring
SECURITY_EVENT_IDS = {
    "4624": "successful_login",
    "4625": "failed_login",
    "4648": "explicit_credentials",
    "4672": "special_privileges",
    "4688": "process_creation",
    "4720": "account_created",
    "4732": "member_added_to_group",
    "7045": "service_installed",
}


class WindowsEventParser(BaseParser):
    """Parses Windows Event Logs in pipe-delimited text export format."""

    def parse_file(self, filepath: str) -> list[dict]:
        events = []
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("EventID"):
                    continue

                parts = line.split("|", 3)
                if len(parts) < 4:
                    continue

                event_id, time_str, computer, message = parts

                event_type = SECURITY_EVENT_IDS.get(event_id.strip())
                if not event_type:
                    continue

                try:
                    timestamp = datetime.fromisoformat(time_str.strip())
                except ValueError:
                    timestamp = None

                ip_match = IP_PATTERN.search(message)
                user_match = USER_PATTERN.search(message)

                events.append({
                    "timestamp": timestamp,
                    "source": "windows",
                    "event_id": event_id.strip(),
                    "event_type": event_type,
                    "computer": computer.strip(),
                    "src_ip": ip_match.group(1) if ip_match else None,
                    "user": user_match.group(1) if user_match else None,
                    "message": message.strip(),
                    "raw": line,
                })

        return events
