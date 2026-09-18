"""Shared helper for classic syslog timestamps ("Sep 18 14:02:11")."""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional, Tuple

HEADER = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<proc>[^\s:\[]+)(?:\[\d+\])?:\s(?P<msg>.*)$"
)
MONTHS = {m: i for i, m in enumerate(
    "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split(), start=1)}

# Classic syslog lines carry no year. We assume the current year, and roll
# back one year if that would put the event in the future (a log written
# on Dec 31 and read on Jan 1).
_REFERENCE_YEAR: Optional[int] = None


def set_reference_year(year: Optional[int]) -> None:
    global _REFERENCE_YEAR
    _REFERENCE_YEAR = year


def split(line: str) -> Optional[Tuple[float, str, str, str]]:
    """Return (epoch, host, process, message) or None."""
    m = HEADER.match(line)
    if not m or m.group("mon") not in MONTHS:
        return None
    now = datetime.now(timezone.utc)
    year = _REFERENCE_YEAR or now.year
    h, mi, s = (int(x) for x in m.group("time").split(":"))
    stamp = datetime(year, MONTHS[m.group("mon")], int(m.group("day")), h, mi, s,
                     tzinfo=timezone.utc)
    if _REFERENCE_YEAR is None and stamp.timestamp() > now.timestamp() + 86400:
        stamp = stamp.replace(year=year - 1)
    return stamp.timestamp(), m.group("host"), m.group("proc"), m.group("msg")
