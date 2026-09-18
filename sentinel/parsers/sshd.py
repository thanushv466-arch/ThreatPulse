"""Linux auth.log: sshd logins, sudo commands, account creation."""
from __future__ import annotations

import re
from typing import Optional

from ..schema import Event
from ._syslog import split

FAILED = re.compile(
    r"^Failed (?P<method>\S+) for (?P<invalid>invalid user )?(?P<user>\S+) "
    r"from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED = re.compile(
    r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
SUDO = re.compile(r"^\s*(?P<user>\S+) : .*?USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$")
USERADD = re.compile(r"^new user: name=(?P<name>[^,]+),")


def parse(line: str) -> Optional[Event]:
    parts = split(line)
    if not parts:
        return None
    ts, host, proc, msg = parts

    if proc == "sshd":
        m = FAILED.match(msg)
        if m:
            return Event(ts=ts, source="sshd", host=host, action="ssh_login",
                         outcome="failure", src_ip=m.group("ip"), user=m.group("user"),
                         dst_port=22, raw=line,
                         extra={"auth_method": m.group("method"),
                                "invalid_user": bool(m.group("invalid"))})
        m = ACCEPTED.match(msg)
        if m:
            return Event(ts=ts, source="sshd", host=host, action="ssh_login",
                         outcome="success", src_ip=m.group("ip"), user=m.group("user"),
                         dst_port=22, raw=line,
                         extra={"auth_method": m.group("method")})
        return None

    if proc == "sudo":
        m = SUDO.match(msg)
        if m:
            return Event(ts=ts, source="sshd", host=host, action="sudo_command",
                         outcome="success", user=m.group("user"), raw=line,
                         extra={"command_line": m.group("cmd"),
                                "target_user": m.group("target")})
        return None

    if proc == "useradd":
        m = USERADD.match(msg)
        if m:
            return Event(ts=ts, source="sshd", host=host, action="user_created",
                         outcome="success", user=m.group("name"), raw=line)
    return None
