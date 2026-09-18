"""Score the pipeline against the simulator's ground truth."""
from __future__ import annotations

from typing import Any, Dict, List


def score(truth: List[Dict[str, Any]], alerts: List[Dict[str, Any]],
          slack: int = 180) -> Dict[str, Any]:
    matched_alerts = set()
    rows = []
    for item in truth:
        hit = None
        for alert in alerts:
            if (alert["rule_id"] == item["rule_id"] and alert["entity"] == item["entity"]
                    and item["start"] - slack <= alert["ts"] <= item["end"] + slack):
                hit = alert
                matched_alerts.add(alert["id"])
        if hit is None:
            rows.append(dict(item, detected=False, delay=None))
        else:
            first = min(a["ts"] for a in alerts if a["rule_id"] == item["rule_id"]
                        and a["entity"] == item["entity"])
            rows.append(dict(item, detected=True, delay=round(max(first - item["start"], 0))))
    unexpected = [a for a in alerts if a["id"] not in matched_alerts]
    detected = sum(1 for r in rows if r["detected"])
    tp, fp, fn = detected, len(unexpected), len(rows) - detected
    return {
        "expected": len(rows), "detected": tp, "missed": fn, "unexpected_alerts": fp,
        "recall": round(tp / (tp + fn), 3) if rows else None,
        "precision": round(tp / (tp + fp), 3) if (tp + fp) else None,
        "rows": rows,
        "unexpected": [{"rule_id": a["rule_id"], "entity": a["entity"],
                        "summary": a["summary"]} for a in unexpected],
    }
