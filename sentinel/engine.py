"""The detection engine.

Rules live in YAML files (see rules/). Three rule types are supported:

  match      one event is enough            e.g. a SQL injection string in a URL
  threshold  N events (or N distinct values) from the same source inside a
             time window                    e.g. 8 failed logins in 2 minutes
  sequence   A happened several times, THEN B happened, same source, inside
             a time window                  e.g. many failures, then a success

Events must be fed in time order. State is held in memory per
(rule, group key) and trimmed as the window slides, so memory stays bounded.
"""
from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

import yaml

from .schema import Event

SEVERITIES = ("low", "medium", "high", "critical")
MAX_EVIDENCE = 25


class RuleError(ValueError):
    """Raised when a rule file is invalid. Fail loudly at startup, not at 3am."""


# --------------------------------------------------------------------------
# Field conditions:   field|operator: value      (operator defaults to "eq")
# --------------------------------------------------------------------------
@dataclass
class Condition:
    field_name: str
    op: str
    value: Any

    OPS = ("eq", "ne", "in", "re", "contains", "contains_any", "gte", "lte", "exists")

    def __post_init__(self) -> None:
        if self.op not in self.OPS:
            raise RuleError("unknown operator '%s' on field '%s'" % (self.op, self.field_name))
        if self.op == "re":
            try:
                self.value = re.compile(self.value)
            except re.error as exc:
                raise RuleError("bad regex for '%s': %s" % (self.field_name, exc)) from exc
        if self.op == "contains_any":
            self.value = [str(v).lower() for v in self.value]
        if self.op == "contains":
            self.value = str(self.value).lower()

    def test(self, event: Event) -> bool:
        actual = event.get(self.field_name)
        if self.op == "exists":
            return (actual is not None) == bool(self.value)
        if actual is None:
            return False
        if self.op == "eq":
            return actual == self.value
        if self.op == "ne":
            return actual != self.value
        if self.op == "in":
            return actual in self.value
        if self.op == "re":
            return bool(self.value.search(str(actual)))
        if self.op == "contains":
            return self.value in str(actual).lower()
        if self.op == "contains_any":
            text = str(actual).lower()
            return any(v in text for v in self.value)
        try:
            if self.op == "gte":
                return float(actual) >= float(self.value)
            return float(actual) <= float(self.value)
        except (TypeError, ValueError):
            return False


def compile_match(block: Dict[str, Any]) -> List[Condition]:
    if not isinstance(block, dict) or not block:
        raise RuleError("'match' must be a non-empty mapping")
    conditions = []
    for key, value in block.items():
        name, _, op = key.partition("|")
        conditions.append(Condition(name, op or "eq", value))
    return conditions


def matches(conditions: List[Condition], event: Event) -> bool:
    return all(c.test(event) for c in conditions)


# --------------------------------------------------------------------------
# Rules and alerts
# --------------------------------------------------------------------------
@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    type: str
    tactic: str
    technique: str
    technique_name: str
    conditions: List[Condition]
    group_by: Optional[str] = None
    window: int = 0
    count: int = 1
    distinct: Optional[str] = None
    then: List[Condition] = field(default_factory=list)
    suppress: int = 0
    false_positives: List[str] = field(default_factory=list)
    response: List[str] = field(default_factory=list)
    explain: str = ""
    summary: str = ""          # optional template, e.g. "{user} ran: {command_line}"
    source_file: str = ""

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.id, "title": self.title, "description": self.description,
            "severity": self.severity, "type": self.type, "tactic": self.tactic,
            "technique": self.technique, "technique_name": self.technique_name,
            "group_by": self.group_by, "window": self.window, "count": self.count,
            "distinct": self.distinct, "false_positives": self.false_positives,
            "response": self.response, "explain": self.explain,
        }


@dataclass
class Alert:
    rule: Rule
    ts: float
    entity: str                 # what the alert is "about" (usually the source IP)
    summary: str
    evidence: List[Event]
    src_ip: Optional[str] = None
    host: Optional[str] = None
    user: Optional[str] = None


def load_rule(doc: Dict[str, Any], source_file: str = "") -> Rule:
    required = ("id", "title", "severity", "type", "match", "mitre")
    missing = [k for k in required if k not in doc]
    if missing:
        raise RuleError("%s: missing keys %s" % (source_file or doc.get("id"), missing))
    if doc["severity"] not in SEVERITIES:
        raise RuleError("%s: severity must be one of %s" % (doc["id"], SEVERITIES))
    if doc["type"] not in ("match", "threshold", "sequence"):
        raise RuleError("%s: unknown rule type '%s'" % (doc["id"], doc["type"]))
    if doc["type"] != "match":
        for key in ("group_by", "window", "count"):
            if key not in doc:
                raise RuleError("%s: %s rules need '%s'" % (doc["id"], doc["type"], key))
    if doc["type"] == "sequence" and "then" not in doc:
        raise RuleError("%s: sequence rules need a 'then' block" % doc["id"])
    mitre = doc["mitre"]
    window = int(doc.get("window", 0))
    return Rule(
        id=doc["id"], title=doc["title"], description=doc.get("description", "").strip(),
        severity=doc["severity"], type=doc["type"], tactic=mitre["tactic"],
        technique=mitre["technique"], technique_name=mitre.get("name", ""),
        conditions=compile_match(doc["match"]), group_by=doc.get("group_by"),
        window=window, count=int(doc.get("count", 1)), distinct=doc.get("distinct"),
        then=compile_match(doc["then"]) if "then" in doc else [],
        suppress=int(doc.get("suppress", window or 300)),
        false_positives=list(doc.get("false_positives", [])),
        response=list(doc.get("response", [])), explain=doc.get("explain", "").strip(),
        summary=doc.get("summary", ""),
        source_file=source_file,
    )


def load_rules(directory: Path) -> List[Rule]:
    rules, seen = [], set()
    for path in sorted(Path(directory).glob("*.yml")):
        with open(path, encoding="utf-8") as handle:
            # safe_load: never let a rule file execute code.
            doc = yaml.safe_load(handle)
        rule = load_rule(doc, path.name)
        if rule.id in seen:
            raise RuleError("duplicate rule id %s" % rule.id)
        seen.add(rule.id)
        rules.append(rule)
    if not rules:
        raise RuleError("no rules found in %s" % directory)
    return rules


class DetectionEngine:
    def __init__(self, rules: List[Rule]):
        self.rules = rules
        # (rule id, group key) -> recent matching events
        self._windows: Dict[Tuple[str, str], Deque[Event]] = defaultdict(deque)
        # (rule id, group key) -> time of the last alert, for de-duplication
        self._last_fired: Dict[Tuple[str, str], float] = {}

    def process(self, event: Event) -> List[Alert]:
        alerts = []
        for rule in self.rules:
            alert = self._evaluate(rule, event)
            if alert:
                alerts.append(alert)
        return alerts

    # ------------------------------------------------------------------
    def _evaluate(self, rule: Rule, event: Event) -> Optional[Alert]:
        if rule.type == "match":
            if not matches(rule.conditions, event):
                return None
            key = str(event.get(rule.group_by)) if rule.group_by else (
                event.src_ip or event.host)
            return self._fire(rule, key, event, [event])

        key_value = event.get(rule.group_by)
        if key_value is None:
            return None
        state_key = (rule.id, str(key_value))

        if rule.type == "threshold":
            if not matches(rule.conditions, event):
                return None
            window = self._slide(state_key, event, rule.window)
            if rule.distinct:
                size = len({e.get(rule.distinct) for e in window} - {None})
            else:
                size = len(window)
            if size >= rule.count:
                return self._fire(rule, str(key_value), event, list(window), size)
            return None

        # sequence: count the "first" events, fire when the "then" event arrives
        if matches(rule.conditions, event):
            self._slide(state_key, event, rule.window)
            return None
        if matches(rule.then, event):
            window = self._windows.get(state_key)
            if not window:
                return None
            self._trim(window, event.ts, rule.window)
            if len(window) >= rule.count:
                evidence = list(window) + [event]
                window.clear()
                return self._fire(rule, str(key_value), event, evidence, len(evidence) - 1)
        return None

    def _slide(self, state_key: Tuple[str, str], event: Event, seconds: int) -> Deque[Event]:
        window = self._windows[state_key]
        window.append(event)
        self._trim(window, event.ts, seconds)
        return window

    @staticmethod
    def _trim(window: Deque[Event], now: float, seconds: int) -> None:
        while window and now - window[0].ts > seconds:
            window.popleft()

    def _fire(self, rule: Rule, key: str, event: Event, evidence: List[Event],
              size: Optional[int] = None) -> Optional[Alert]:
        # De-duplicate: one alert per rule per entity per suppression period,
        # otherwise a 5,000-attempt brute force becomes 5,000 alerts.
        fired_key = (rule.id, key)
        last = self._last_fired.get(fired_key)
        if last is not None and event.ts - last < rule.suppress:
            return None
        self._last_fired[fired_key] = event.ts
        if rule.type == "sequence":
            summary = "%d failures, then a success, within %ds from %s" % (
                size, rule.window, key)
        elif rule.type == "threshold":
            what = "different %s values" % rule.distinct if rule.distinct else "events"
            summary = "%d %s within %ds from %s" % (size, what, rule.window, key)
        elif rule.summary:
            # Fill {field} placeholders from the event. Plain substitution only:
            # str.format() on attacker-influenced text would be an injection risk.
            summary = re.sub(r"\{(\w+)\}", lambda m: str(event.get(m.group(1)) or "?"),
                             rule.summary)[:220]
        else:
            summary = rule.title
        first = evidence[0]
        return Alert(
            rule=rule, ts=event.ts, entity=key, summary=summary,
            evidence=evidence[-MAX_EVIDENCE:],
            src_ip=event.src_ip or first.src_ip, host=event.host, user=event.user,
        )
