"""Zeek conn.log in JSON format: one record per network connection."""
from __future__ import annotations

import json
from typing import Optional

from ..schema import Event


def parse(line: str) -> Optional[Event]:
    rec = json.loads(line)
    if "id.orig_h" not in rec or "id.resp_h" not in rec:
        return None
    return Event(
        ts=float(rec["ts"]), source="zeek", host=rec.get("sensor", "zeek-01"),
        action="network_flow", outcome="success",
        src_ip=rec["id.orig_h"], dst_ip=rec["id.resp_h"],
        dst_port=int(rec.get("id.resp_p", 0)) or None, raw=line,
        extra={
            "proto": rec.get("proto"),
            "service": rec.get("service"),
            "duration": float(rec.get("duration") or 0),
            "bytes_out": int(rec.get("orig_bytes") or 0),
            "bytes_in": int(rec.get("resp_bytes") or 0),
            "mb_out": round(int(rec.get("orig_bytes") or 0) / 1_000_000, 1),
        },
    )
