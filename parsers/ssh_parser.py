"""Parser for Linux auth.log (SSH authentication events)."""

import re

from .base_parser import BaseParser

# Matches standard syslog lines from sshd:
# Feb 10 14:23:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
AUTH_LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.+)$"
)

FAILED_PASSWORD_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

ACCEPTED_PASSWORD_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

INVALID_USER_PATTERN = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)


class SSHLogParser(BaseParser):
    """Parses /var/log/auth.log for SSH-related events."""

    def parse_file(self, filepath: str) -> list[dict]:
        events = []
        with open(filepath, "r", errors="ignore") as f:
            for line in f:
                match = AUTH_LOG_PATTERN.match(line.strip())
                if not match:
                    continue

                timestamp = self.safe_parse_date(
                    match.group("timestamp"), "%b %d %H:%M:%S"
                )
                message = match.group("message")

                event = {
                    "timestamp": timestamp,
                    "hostname": match.group("hostname"),
                    "source": "ssh",
                    "raw": line.strip(),
                    "event_type": None,
                    "user": None,
                    "src_ip": None,
                }

                # Classify the event
                failed = FAILED_PASSWORD_PATTERN.search(message)
                if failed:
                    event["event_type"] = "failed_login"
                    event["user"] = failed.group("user")
                    event["src_ip"] = failed.group("ip")

                accepted = ACCEPTED_PASSWORD_PATTERN.search(message)
                if accepted:
                    event["event_type"] = "successful_login"
                    event["user"] = accepted.group("user")
                    event["src_ip"] = accepted.group("ip")

                invalid = INVALID_USER_PATTERN.search(message)
                if invalid:
                    event["event_type"] = "invalid_user"
                    event["user"] = invalid.group("user")
                    event["src_ip"] = invalid.group("ip")

                if event["event_type"]:
                    events.append(event)

        return events
