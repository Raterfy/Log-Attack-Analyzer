"""Parser for Apache/Nginx access.log (Combined Log Format)."""

import re

from .base_parser import BaseParser

# Combined Log Format:
# 192.168.1.50 - - [10/Feb/2026:14:23:01 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
ACCESS_LOG_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<uri>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


class ApacheLogParser(BaseParser):
    """Parses Apache/Nginx access logs in Combined Log Format."""

    def parse_file(self, filepath: str) -> list[dict]:
        events = []
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                match = ACCESS_LOG_PATTERN.match(line.strip())
                if not match:
                    continue

                timestamp = self.safe_parse_date(
                    match.group("timestamp").split()[0],
                    "%d/%b/%Y:%H:%M:%S",
                )

                events.append({
                    "timestamp": timestamp,
                    "source": "apache",
                    "src_ip": match.group("ip"),
                    "method": match.group("method"),
                    "uri": match.group("uri"),
                    "status": int(match.group("status")),
                    "user_agent": match.group("user_agent") or "",
                    "raw": line.strip(),
                })

        return events
