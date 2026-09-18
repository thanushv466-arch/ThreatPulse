"""Windows Security events, in the JSON shape Winlogbeat ships them."""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Optional

from ..schema import Event

# Event ID -> (normalized action, outcome)
EVENT_IDS = {
    4624: ("win_logon", "success"),
    4625: ("win_logon", "failure"),
    4688: ("process_start", "success"),
    4720: ("user_created", "success"),
    4732: ("group_member_added", "success"),
    1102: ("audit_log_cleared", "success"),
}


def _epoch(stamp: str) -> float:
    # datetime.fromisoformat() only accepts a trailing "Z" from Python 3.11,
    # so normalize it by hand to stay compatible with 3.9.
    stamp = stamp.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(stamp)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


ENCODED = re.compile(r"(?i)\s-e[a-z]*\s+([A-Za-z0-9+/=]{20,})")


def _decode_powershell(command_line: Optional[str]) -> Optional[str]:
    """PowerShell's -EncodedCommand is Base64 over UTF-16LE text. Decode it so
    the analyst sees what actually ran instead of a wall of letters."""
    match = ENCODED.search(command_line or "")
    if not match:
        return None
    try:
        return base64.b64decode(match.group(1), validate=True).decode("utf-16-le")[:400]
    except (ValueError, UnicodeDecodeError):
        return None


def _basename(path: Optional[str]) -> Optional[str]:
    return path.replace("/", "\\").rsplit("\\", 1)[-1].lower() if path else None


def parse(line: str) -> Optional[Event]:
    rec = json.loads(line)
    winlog = rec.get("winlog", {})
    event_id = int(winlog.get("event_id", 0))
    if event_id not in EVENT_IDS:
        return None
    action, outcome = EVENT_IDS[event_id]
    data = winlog.get("event_data", {})
    ip = data.get("IpAddress")
    if ip in ("-", "", "::1", "127.0.0.1"):
        ip = None
    user = data.get("TargetUserName") or data.get("SubjectUserName")
    group = None
    if action == "process_start":
        user = data.get("SubjectUserName")
    elif action == "group_member_added":
        # In event 4732 "TargetUserName" is the GROUP; the account that was
        # added lives in MemberName.
        group = data.get("TargetUserName")
        user = (data.get("MemberName") or "").rsplit("\\", 1)[-1] or None
    return Event(
        ts=_epoch(rec["@timestamp"]), source="windows",
        host=winlog.get("computer_name", "unknown"), action=action,
        outcome=outcome, src_ip=ip, user=user, raw=line,
        extra={
            "event_id": event_id,
            "process_name": _basename(data.get("NewProcessName")),
            "parent_process": _basename(data.get("ParentProcessName")),
            "command_line": data.get("CommandLine"),
            "decoded_command": _decode_powershell(data.get("CommandLine")),
            "group_name": group,
            "actor": data.get("SubjectUserName"),
        },
    )
