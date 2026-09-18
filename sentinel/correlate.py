"""Correlation: fold related alerts into one incident and score its risk.

Ten alerts about the same attacker are one story, not ten tickets. Alerts
that share an entity (normally the source IP) and arrive within `gap`
seconds of each other join the same incident.
"""
from __future__ import annotations

import math
from typing import Any, Dict, List

SEVERITY_POINTS = {"low": 5, "medium": 12, "high": 25, "critical": 45}
SEVERITY_ORDER = ["low", "medium", "high", "critical"]
INCIDENT_GAP = 3600


def risk_score(alerts: List[Dict[str, Any]]) -> int:
    """0-100. Severity adds points; spanning several ATT&CK tactics multiplies
    them (an attacker progressing through the kill chain is worse than one
    noisy stage); threat-intel hits and critical assets add a bonus. The
    total goes through a saturating curve, so the score approaches 100 but
    never passes it and the first few findings move it the most."""
    if not alerts:
        return 0
    # Count each rule once so a repeating alert cannot inflate the score.
    per_rule = {}
    for a in alerts:
        per_rule[a["rule_id"]] = max(per_rule.get(a["rule_id"], 0),
                                     SEVERITY_POINTS[a["severity"]])
    points = float(sum(per_rule.values()))
    tactics = {a["tactic"] for a in alerts}
    points *= 1 + 0.10 * (len(tactics) - 1)
    if any(a["context"].get("threat_intel") for a in alerts):
        points += 15
    if any((a["context"].get("asset") or {}).get("criticality") == "critical"
           for a in alerts):
        points += 10
    return int(round(100 * (1 - math.exp(-points / 70.0))))


def worst_severity(alerts: List[Dict[str, Any]]) -> str:
    return max((a["severity"] for a in alerts), key=SEVERITY_ORDER.index)
