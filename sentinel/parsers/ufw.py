"""UFW / iptables firewall log (kernel messages)."""
from __future__ import annotations

import re
from typing import Optional

from ..schema import Event
from ._syslog import split

VERDICT = re.compile(r"\[UFW (?P<verdict>BLOCK|ALLOW|AUDIT)\]")
PAIR = re.compile(r"(?P<key>[A-Z]+)=(?P<value>\S*)")


def parse(line: str) -> Optional[Event]:
    parts = split(line)
    if not parts:
        return None
    ts, host, _proc, msg = parts
    v = VERDICT.search(msg)
    if not v:
        return None
    kv = {m.group("key"): m.group("value") for m in PAIR.finditer(msg)}
    if "SRC" not in kv or "DST" not in kv:
        return None
    blocked = v.group("verdict") == "BLOCK"
    port = kv.get("DPT")
    return Event(
        ts=ts, source="ufw", host=host,
        action="fw_block" if blocked else "fw_allow",
        outcome="failure" if blocked else "success",
        src_ip=kv["SRC"], dst_ip=kv["DST"],
        dst_port=int(port) if port and port.isdigit() else None,
        raw=line, extra={"proto": kv.get("PROTO", "").lower()},
    )
