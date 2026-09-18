"""Every shipped rule gets a true positive (it fires on the attack) and a
true negative (it stays quiet on the innocent look-alike). These run against
the real YAML files in rules/, through the full pipeline."""
from sentinel import simulator as sim

from .conftest import T0, feed, rule_ids


def test_all_rules_load_with_attack_mappings(pipeline):
    assert len(pipeline.rules) == 17
    for rule in pipeline.rules:
        assert rule.technique.startswith("T") and rule.tactic
        assert rule.explain and rule.response, "%s needs an explanation and a playbook" % rule.id


# ---------------------------------------------------------------- SSH
def test_brute_force_fires(pipeline):
    lines = [sim.ssh_fail(T0 + i * 3, "bastion-01", "root", "203.0.113.9") for i in range(10)]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-001"]


def test_slow_failures_stay_quiet(pipeline):
    lines = [sim.ssh_fail(T0 + i * 60, "bastion-01", "root", "203.0.113.9") for i in range(10)]
    assert feed(pipeline, lines) == []


def test_password_spray_fires_without_tripping_brute_force(pipeline):
    users = ["a", "b", "c", "d", "e", "f", "g"]
    lines = [sim.ssh_fail(T0 + i * 35, "bastion-01", u, "192.0.2.77") for i, u in enumerate(users)]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-002"]


def test_success_after_failures_is_critical(pipeline):
    lines = [sim.ssh_fail(T0 + i * 20, "bastion-01", "deploy", "198.51.100.23") for i in range(6)]
    lines.append(sim.ssh_ok(T0 + 200, "bastion-01", "deploy", "198.51.100.23", "password"))
    alerts = feed(pipeline, lines)
    assert rule_ids(alerts) == ["SEN-003"] and alerts[0]["severity"] == "critical"


def test_forgotten_password_stays_quiet(pipeline):
    lines = [sim.ssh_fail(T0 + i * 9, "bastion-01", "akim", "100.64.12.9") for i in range(3)]
    lines.append(sim.ssh_ok(T0 + 40, "bastion-01", "akim", "100.64.12.9", "password"))
    assert feed(pipeline, lines) == []


def test_shadow_file_read_and_new_account(pipeline):
    lines = [sim.sudo(T0, "bastion-01", "deploy", "/usr/bin/cat /etc/shadow"),
             sim.sudo(T0 + 5, "bastion-01", "deploy", "/usr/bin/systemctl restart nginx"),
             sim.useradd(T0 + 90, "bastion-01", "svc_backup")]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-016", "SEN-013"]


# ---------------------------------------------------------------- web
def test_web_attacks_fire_even_when_double_encoded(pipeline):
    ip = "203.0.113.66"
    lines = [sim.web(T0, ip, "/item?id=1%2527%2520OR%2520%25271%2527%253D%25271"),
             sim.web(T0 + 400, ip, "/download?file=..%2F..%2F..%2Fetc%2Fpasswd"),
             sim.web(T0 + 800, ip, "/search?q=%3Cscript%3Ealert(1)%3C/script%3E")]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-004", "SEN-006", "SEN-005"]


def test_innocent_urls_stay_quiet(pipeline):
    urls = ["/blog/how-to-select-a-union-representative", "/products?id=12&sort=price",
            "/docs/scripting-guide", "/search?q=drop+shipping+table+lamps", "/a/b/../c".replace("../", "")]
    lines = [sim.web(T0 + i, "100.64.1.1", u) for i, u in enumerate(urls)]
    assert feed(pipeline, lines) == []


def test_scanner_user_agent_and_enumeration(pipeline):
    lines = [sim.web(T0 + i, "203.0.113.66", "/guess-%d" % i, 404, 100, "Nikto/2.5.0")
             for i in range(30)]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-007", "SEN-008"]


def test_a_few_404s_stay_quiet(pipeline):
    lines = [sim.web(T0 + i * 4, "100.64.80.14", "/old-%d" % i, 404) for i in range(10)]
    assert feed(pipeline, lines) == []


# ------------------------------------------------------------ network
def test_port_scan_counts_distinct_ports(pipeline):
    lines = [sim.ufw(T0 + i, "198.51.100.23", "10.0.1.5", 1000 + i) for i in range(20)]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-009"]


def test_hammering_one_port_is_not_a_scan(pipeline):
    lines = [sim.ufw(T0 + i, "198.51.100.23", "10.0.1.5", 3389) for i in range(60)]
    assert feed(pipeline, lines) == []


def test_exfiltration_only_counts_outbound(pipeline):
    big = 1_288_490_188
    lines = [sim.zeek(T0, "10.0.5.22", "10.0.2.30", 445, big, 100),          # internal backup
             sim.zeek(T0 + 5, "10.0.5.14", "100.70.1.1", 443, 40_000_000, 100),  # small upload
             sim.zeek(T0 + 9, "10.0.5.14", "198.51.100.151", 443, big, 100)]     # the real one
    alerts = feed(pipeline, lines)
    assert rule_ids(alerts) == ["SEN-010"]
    assert alerts[0]["entity"] == "WS-014", "internal IP should resolve to its asset name"


def test_c2_connection_uses_threat_intel(pipeline):
    lines = [sim.zeek(T0, "10.0.5.14", "203.0.113.200", 443, 400, 3000),
             sim.zeek(T0 + 1, "10.0.5.14", "100.70.9.9", 443, 400, 3000)]
    alerts = feed(pipeline, lines)
    assert rule_ids(alerts) == ["SEN-011"]
    assert alerts[0]["context"]["threat_intel"][0]["category"] == "command-and-control"


# ------------------------------------------------------------ endpoint
def _proc(ts, parent, child, cmd, host="WS-014"):
    return sim.win(ts, host, 4688, {"SubjectUserName": "mlopez", "NewProcessName": child,
                                    "ParentProcessName": parent, "CommandLine": cmd})


def test_macro_launching_encoded_powershell(pipeline):
    lines = [_proc(T0, "C:\\Office16\\WINWORD.EXE", "C:\\Windows\\System32\\powershell.exe",
                   sim.encoded_powershell())]
    alerts = feed(pipeline, lines)
    assert sorted(rule_ids(alerts)) == ["SEN-012", "SEN-017"]
    decoded = [a for a in alerts if a["rule_id"] == "SEN-012"][0]["summary"]
    assert "DownloadString" in decoded, "the alert should show the decoded command"


def test_ordinary_it_powershell_stays_quiet(pipeline):
    lines = [_proc(T0, "C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\powershell.exe",
                   "powershell.exe -ExecutionPolicy Bypass -File C:\\IT\\inventory.ps1"),
             _proc(T0 + 1, "C:\\Windows\\explorer.exe", "C:\\Office16\\WINWORD.EXE", "")]
    assert feed(pipeline, lines) == []


def test_account_made_admin_then_logs_cleared(pipeline):
    lines = [sim.win(T0, "WS-014", 4720, {"TargetUserName": "helpdesk_svc", "SubjectUserName": "mlopez"}),
             sim.win(T0 + 40, "WS-014", 4732, {"TargetUserName": "Administrators",
                                               "MemberName": "WS-014\\helpdesk_svc",
                                               "SubjectUserName": "mlopez"}),
             sim.win(T0 + 50, "WS-014", 4732, {"TargetUserName": "Remote Desktop Users",
                                               "MemberName": "WS-014\\akim",
                                               "SubjectUserName": "it-admin"}),
             sim.win(T0 + 90, "WS-014", 1102, {"SubjectUserName": "helpdesk_svc"})]
    assert rule_ids(feed(pipeline, lines)) == ["SEN-013", "SEN-014", "SEN-015"]
