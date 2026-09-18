"""The common event schema.

Every log source (SSH, web server, firewall, Zeek, Windows) has its own
format. Parsers translate each of them into this one shape so that the
detection engine only ever has to understand a single vocabulary.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

# Fields a detection rule is allowed to reference.
CORE_FIELDS = (
    "ts", "source", "host", "action", "outcome", "src_ip", "dst_ip",
    "dst_port", "user", "raw",
)


@dataclass
class Event:
    ts: float                       # epoch seconds, UTC
    source: str                     # which parser produced it: sshd, nginx, ufw, zeek, windows
    host: str                       # the machine that wrote the log line
    action: str                     # normalized verb, e.g. ssh_login, http_request
    raw: str                        # the original, untouched log line (evidence)
    outcome: Optional[str] = None   # success | failure
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    user: Optional[str] = None
    extra: Dict[str, Any] = field(default_factory=dict)
    id: Optional[int] = None        # set once the event is stored

    def get(self, name: str) -> Any:
        """Look a field up by name, checking core fields first, then extras."""
        if name in CORE_FIELDS:
            return getattr(self, name)
        return self.extra.get(name)

    @property
    def timestamp(self) -> str:
        return iso(self.ts)

    def to_dict(self) -> Dict[str, Any]:
        data = {name: getattr(self, name) for name in CORE_FIELDS}
        data["timestamp"] = self.timestamp
        data["id"] = self.id
        data.update(self.extra)
        return data


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
