"""Generate an HTML security analysis report from detection alerts."""

from datetime import datetime

from detectors.base_detector import Alert

SEVERITY_COLORS = {
    "CRITICAL": "#dc3545",
    "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107",
    "LOW": "#28a745",
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def generate_report(alerts: list[Alert], log_files: list[str]) -> str:
    """Build a complete HTML report from a list of alerts."""
    alerts_sorted = sorted(alerts, key=lambda a: SEVERITY_ORDER.get(a.severity, 99))

    severity_counts = {}
    for a in alerts:
        severity_counts[a.severity] = severity_counts.get(a.severity, 0) + 1

    all_ips = sorted({ip for a in alerts for ip in a.source_ips if ip and ip != "local"})
    total_events = sum(a.event_count for a in alerts)
    mitre_techniques = sorted({
        f"{a.mitre_id} - {a.mitre_technique}"
        for a in alerts if a.mitre_id
    })

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Log Analysis Report</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, sans-serif; background: #0a0a1a; color: #e0e0e0; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; border-radius: 10px;
              margin-bottom: 20px; border-left: 4px solid #00d4ff; }}
    header h1 {{ color: #00d4ff; font-size: 1.8em; }}
    header p {{ color: #888; margin-top: 5px; }}
    .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;
              margin-bottom: 25px; }}
    .stat-card {{ background: #1a1a2e; padding: 20px; border-radius: 8px; text-align: center; }}
    .stat-card .number {{ font-size: 2em; font-weight: bold; }}
    .stat-card .label {{ color: #888; font-size: 0.9em; margin-top: 5px; }}
    .section {{ background: #1a1a2e; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
    .section h2 {{ color: #00d4ff; margin-bottom: 15px; font-size: 1.3em;
                   border-bottom: 1px solid #333; padding-bottom: 8px; }}
    .alert-card {{ background: #0f0f23; border-radius: 6px; padding: 15px; margin-bottom: 12px;
                   border-left: 4px solid; }}
    .alert-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }}
    .alert-title {{ font-weight: bold; font-size: 1.1em; }}
    .severity-badge {{ padding: 3px 10px; border-radius: 12px; font-size: 0.8em; font-weight: bold;
                       color: #fff; }}
    .alert-details {{ color: #aaa; font-size: 0.95em; line-height: 1.6; }}
    .alert-meta {{ display: flex; gap: 20px; margin-top: 8px; flex-wrap: wrap; }}
    .alert-meta span {{ background: #1a1a2e; padding: 2px 8px; border-radius: 4px; font-size: 0.85em; }}
    .ioc-list {{ list-style: none; }}
    .ioc-list li {{ padding: 6px 10px; border-bottom: 1px solid #222; font-family: monospace; font-size: 0.9em; }}
    .ioc-list li:hover {{ background: #1a1a3e; }}
    .mitre-tag {{ display: inline-block; background: #16213e; color: #00d4ff; padding: 4px 10px;
                  border-radius: 4px; margin: 3px; font-size: 0.85em; }}
    pre {{ background: #0f0f23; padding: 10px; border-radius: 4px; overflow-x: auto;
           font-size: 0.8em; color: #aaa; margin-top: 8px; max-height: 200px; }}
    .timeline {{ position: relative; padding-left: 30px; }}
    .timeline-event {{ position: relative; padding: 10px 0; border-left: 2px solid #333; padding-left: 20px; }}
    .timeline-event::before {{ content: ''; position: absolute; left: -6px; top: 14px; width: 10px;
                               height: 10px; border-radius: 50%; }}
    .timeline-dot-CRITICAL::before {{ background: #dc3545; }}
    .timeline-dot-HIGH::before {{ background: #fd7e14; }}
    .timeline-dot-MEDIUM::before {{ background: #ffc107; }}
    .timeline-dot-LOW::before {{ background: #28a745; }}
    footer {{ text-align: center; color: #555; padding: 20px; font-size: 0.85em; }}
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>Security Log Analysis Report</h1>
        <p>Generated: {now} | Files analyzed: {', '.join(log_files)}</p>
    </header>

    <!-- Summary Stats -->
    <div class="stats">
        <div class="stat-card">
            <div class="number" style="color: #dc3545;">{len(alerts)}</div>
            <div class="label">Total Alerts</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: #dc3545;">{severity_counts.get('CRITICAL', 0)}</div>
            <div class="label">Critical</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: #fd7e14;">{severity_counts.get('HIGH', 0)}</div>
            <div class="label">High</div>
        </div>
        <div class="stat-card">
            <div class="number" style="color: #ffc107;">{severity_counts.get('MEDIUM', 0)}</div>
            <div class="label">Medium</div>
        </div>
        <div class="stat-card">
            <div class="number">{total_events}</div>
            <div class="label">Events Analyzed</div>
        </div>
        <div class="stat-card">
            <div class="number">{len(all_ips)}</div>
            <div class="label">Unique Source IPs</div>
        </div>
    </div>

    <!-- MITRE ATT&CK Mapping -->
    <div class="section">
        <h2>MITRE ATT&CK Techniques Detected</h2>
        {''.join(f'<span class="mitre-tag">{t}</span>' for t in mitre_techniques) or '<p style="color:#666;">No techniques detected.</p>'}
    </div>

    <!-- Alerts Detail -->
    <div class="section">
        <h2>Alerts</h2>
        {''.join(_render_alert(a) for a in alerts_sorted) or '<p style="color:#666;">No alerts generated.</p>'}
    </div>

    <!-- IOCs -->
    <div class="section">
        <h2>Indicators of Compromise (IOCs)</h2>
        <h3 style="color:#ccc; margin-bottom:10px;">Malicious IPs</h3>
        <ul class="ioc-list">
            {''.join(f'<li>{ip}</li>' for ip in all_ips) or '<li style="color:#666;">None detected</li>'}
        </ul>
    </div>

    <!-- Attack Timeline -->
    <div class="section">
        <h2>Attack Timeline</h2>
        <div class="timeline">
            {''.join(_render_timeline_event(a) for a in alerts_sorted if a.timestamp_start) or '<p style="color:#666;">No timeline data available.</p>'}
        </div>
    </div>

    <footer>
        Log Attack Analyzer &mdash; SOC Automation Tool
    </footer>
</div>
</body>
</html>"""


def _render_alert(alert: Alert) -> str:
    color = SEVERITY_COLORS.get(alert.severity, "#888")
    indicators_html = ""
    if alert.indicators:
        items = "".join(f"<li>{ind}</li>" for ind in alert.indicators[:10])
        indicators_html = f"<ul class='ioc-list'>{items}</ul>"

    samples_html = ""
    if alert.raw_samples:
        samples_html = "<pre>" + "\n".join(alert.raw_samples[:5]) + "</pre>"

    time_range = ""
    if alert.timestamp_start:
        start = alert.timestamp_start.strftime("%H:%M:%S") if hasattr(alert.timestamp_start, "strftime") else str(alert.timestamp_start)
        end = alert.timestamp_end.strftime("%H:%M:%S") if alert.timestamp_end and hasattr(alert.timestamp_end, "strftime") else start
        time_range = f"<span>Time: {start} - {end}</span>"

    return f"""
    <div class="alert-card" style="border-left-color: {color};">
        <div class="alert-header">
            <span class="alert-title">{alert.title}</span>
            <span class="severity-badge" style="background:{color};">{alert.severity}</span>
        </div>
        <div class="alert-details">{alert.description}</div>
        <div class="alert-meta">
            <span>MITRE: {alert.mitre_id} {alert.mitre_technique}</span>
            <span>Events: {alert.event_count}</span>
            {time_range}
        </div>
        {indicators_html}
        {samples_html}
    </div>"""


def _render_timeline_event(alert: Alert) -> str:
    time_str = alert.timestamp_start.strftime("%Y-%m-%d %H:%M:%S") if hasattr(alert.timestamp_start, "strftime") else str(alert.timestamp_start)
    color = SEVERITY_COLORS.get(alert.severity, "#888")
    return f"""
    <div class="timeline-event timeline-dot-{alert.severity}">
        <strong style="color:{color};">[{time_str}]</strong> {alert.title}
        <span class="severity-badge" style="background:{color}; margin-left:10px;">{alert.severity}</span>
        <p style="color:#888; font-size:0.9em;">{alert.description}</p>
    </div>"""
