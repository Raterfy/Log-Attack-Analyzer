"""Detect brute-force login attempts (SSH and RDP)."""

from collections import defaultdict

from .base_detector import Alert, BaseDetector

# Thresholds
FAILED_LOGIN_THRESHOLD = 5  # failures from one IP to trigger alert
TIME_WINDOW_SECONDS = 300   # 5-minute sliding window


class BruteforceDetector(BaseDetector):
    """Detects brute-force attacks by counting failed logins per source IP.

    Logic:
      1. Group failed login events by source IP.
      2. For each IP, sort events by timestamp.
      3. Use a sliding window: if >= THRESHOLD failures occur within
         TIME_WINDOW seconds, raise an alert.
      4. Severity scales with attempt count.
    """

    def detect(self, events: list[dict]) -> list[Alert]:
        # Filter failed logins from SSH and Windows sources
        failed = [
            e for e in events
            if e.get("event_type") == "failed_login" and e.get("src_ip")
        ]

        # Group by source IP
        by_ip: dict[str, list[dict]] = defaultdict(list)
        for event in failed:
            by_ip[event["src_ip"]].append(event)

        alerts = []
        for ip, ip_events in by_ip.items():
            # Sort chronologically
            ip_events.sort(key=lambda e: e["timestamp"] or 0)

            # Sliding window check
            for i, event in enumerate(ip_events):
                window_events = [
                    e for e in ip_events[i:]
                    if e["timestamp"] and event["timestamp"]
                    and (e["timestamp"] - event["timestamp"]).total_seconds()
                    <= TIME_WINDOW_SECONDS
                ]

                if len(window_events) >= FAILED_LOGIN_THRESHOLD:
                    count = len(window_events)
                    targeted_users = list({
                        e["user"] for e in window_events if e.get("user")
                    })

                    severity = self._compute_severity(count)

                    alerts.append(Alert(
                        title=f"Brute-Force Attack from {ip}",
                        severity=severity,
                        description=(
                            f"{count} failed login attempts from {ip} "
                            f"within {TIME_WINDOW_SECONDS}s. "
                            f"Targeted users: {', '.join(targeted_users)}"
                        ),
                        source_ips=[ip],
                        indicators=targeted_users,
                        mitre_technique="Brute Force",
                        mitre_id="T1110",
                        timestamp_start=window_events[0]["timestamp"],
                        timestamp_end=window_events[-1]["timestamp"],
                        event_count=count,
                        raw_samples=[e["raw"] for e in window_events[:5]],
                    ))
                    break  # one alert per IP is enough

        return alerts

    @staticmethod
    def _compute_severity(count: int) -> str:
        if count >= 50:
            return "CRITICAL"
        if count >= 20:
            return "HIGH"
        if count >= 10:
            return "MEDIUM"
        return "LOW"
