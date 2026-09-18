"""Log parsers. Each one turns a raw line into a normalized Event (or None)."""
from __future__ import annotations

from typing import Callable, Dict, Optional

from ..schema import Event
from . import nginx, sshd, ufw, windows, zeek

Parser = Callable[[str], Optional[Event]]

PARSERS: Dict[str, Parser] = {
    "sshd": sshd.parse,
    "nginx": nginx.parse,
    "ufw": ufw.parse,
    "zeek": zeek.parse,
    "windows": windows.parse,
}

# Which parser to use for a given sample file name.
FILE_HINTS = {
    "auth.log": "sshd",
    "access.log": "nginx",
    "ufw.log": "ufw",
    "conn.log": "zeek",
    "winevent.jsonl": "windows",
}


def parser_for_file(filename: str) -> Optional[str]:
    for hint, name in FILE_HINTS.items():
        if filename.endswith(hint):
            return name
    return None


def parse_line(source: str, line: str) -> Optional[Event]:
    """Parse one line. Malformed input returns None and never raises:
    a SOC pipeline that crashes on a weird log line is a pipeline an
    attacker can switch off."""
    line = line.rstrip("\n")
    if not line.strip():
        return None
    try:
        return PARSERS[source](line)
    except Exception:  # noqa: BLE001 - deliberate: never die on bad input
        return None
