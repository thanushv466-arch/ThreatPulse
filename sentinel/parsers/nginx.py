"""nginx / Apache "combined" access log."""
from __future__ import annotations

import re
from datetime import datetime
from typing import Optional
from urllib.parse import unquote_plus

from ..schema import Event

LINE = re.compile(
    r'^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url>\S+) (?P<proto>[^"]*)" '
    r'(?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<referer>[^"]*)" "(?P<agent>[^"]*)"'
    r'(?: host=(?P<host>\S+))?$'
)


def _decode(url: str) -> str:
    """Attackers hide payloads with URL encoding, sometimes twice
    (%2527 -> %27 -> '). Decode until the string stops changing, capped
    so a crafted input cannot keep us looping."""
    for _ in range(3):
        decoded = unquote_plus(url)
        if decoded == url:
            break
        url = decoded
    return url


def parse(line: str) -> Optional[Event]:
    m = LINE.match(line)
    if not m:
        return None
    ts = datetime.strptime(m.group("time"), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    status = int(m.group("status"))
    size = 0 if m.group("bytes") == "-" else int(m.group("bytes"))
    user = None if m.group("user") == "-" else m.group("user")
    return Event(
        ts=ts, source="nginx", host=m.group("host") or "web-01",
        action="http_request", outcome="failure" if status >= 400 else "success",
        src_ip=m.group("ip"), user=user, dst_port=443, raw=line,
        extra={
            "method": m.group("method"),
            "url": m.group("url"),
            "url_decoded": _decode(m.group("url")),
            "status": status,
            "bytes": size,
            "user_agent": m.group("agent"),
        },
    )
