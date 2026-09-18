import pytest

from sentinel.engine import Condition, DetectionEngine, RuleError, load_rule
from sentinel.schema import Event

from .conftest import T0


def ev(ts, **kw):
    core = {k: kw.pop(k) for k in list(kw) if k in ("src_ip", "user", "outcome", "dst_port", "host")}
    return Event(ts=ts, source="test", host=core.pop("host", "h"), action=kw.pop("action", "login"),
                 raw="raw", extra=kw, **core)


def rule(**overrides):
    doc = {"id": "T-1", "title": "test", "severity": "high", "type": "threshold",
           "match": {"action": "login", "outcome": "failure"}, "group_by": "src_ip",
           "window": 60, "count": 3, "mitre": {"tactic": "X", "technique": "T0"}}
    doc.update(overrides)
    return load_rule(doc)


@pytest.mark.parametrize("op,value,actual,expected", [
    ("eq", "a", "a", True), ("eq", "a", "b", False), ("ne", "a", "b", True),
    ("in", ["a", "b"], "b", True), ("in", ["a"], "z", False),
    ("re", r"(?i)union\s+select", "x UNION  SELECT y", True),
    ("re", r"(?i)union\s+select", "select-a-union", False),
    ("contains", "MAP", "sqlmap/1.8", True),
    ("contains_any", ["nikto", "sqlmap"], "Mozilla (Nikto/2.5)", True),
    ("gte", 500, 500, True), ("gte", 500, 499, False), ("lte", 5, 9, False),
    ("gte", 500, "not a number", False), ("exists", True, "x", True),
])
def test_condition_operators(op, value, actual, expected):
    assert Condition("f", op, value).test(ev(T0, f=actual)) is expected


def test_missing_field_never_matches():
    assert Condition("nope", "eq", "x").test(ev(T0)) is False
    assert Condition("nope", "exists", False).test(ev(T0)) is True


def test_threshold_fires_at_count_not_before():
    engine = DetectionEngine([rule()])
    hits = [engine.process(ev(T0 + i, src_ip="1.1.1.1", outcome="failure")) for i in range(3)]
    assert [len(h) for h in hits] == [0, 0, 1]
    assert len(hits[2][0].evidence) == 3


def test_threshold_window_expires_old_events():
    engine = DetectionEngine([rule()])
    for t in (0, 50, 120):   # third event is outside the 60s window of the first two
        alerts = engine.process(ev(T0 + t, src_ip="1.1.1.1", outcome="failure"))
    assert alerts == []


def test_threshold_is_per_source():
    engine = DetectionEngine([rule()])
    alerts = []
    for i in range(6):
        alerts += engine.process(ev(T0 + i, src_ip="1.1.1.%d" % (i % 3), outcome="failure"))
    assert alerts == []      # 2 each from 3 sources: nobody reaches 3


def test_suppression_stops_alert_storms():
    engine = DetectionEngine([rule(suppress=300)])
    alerts = []
    for i in range(200):
        alerts += engine.process(ev(T0 + i, src_ip="1.1.1.1", outcome="failure"))
    assert len(alerts) == 1
    alerts += engine.process(ev(T0 + 600, src_ip="1.1.1.1", outcome="failure"))
    alerts += engine.process(ev(T0 + 601, src_ip="1.1.1.1", outcome="failure"))
    alerts += engine.process(ev(T0 + 602, src_ip="1.1.1.1", outcome="failure"))
    assert len(alerts) == 2  # fires again once the suppression period has passed


def test_distinct_counts_unique_values_only():
    engine = DetectionEngine([rule(distinct="user", count=3)])
    alerts = []
    for i, user in enumerate(["root", "root", "root", "root", "amy"]):
        alerts += engine.process(ev(T0 + i, src_ip="1.1.1.1", outcome="failure", user=user))
    assert alerts == []
    alerts += engine.process(ev(T0 + 9, src_ip="1.1.1.1", outcome="failure", user="bob"))
    assert len(alerts) == 1


def test_sequence_needs_failures_before_the_success():
    seq = rule(type="sequence", then={"action": "login", "outcome": "success"})
    engine = DetectionEngine([seq])
    assert engine.process(ev(T0, src_ip="9.9.9.9", outcome="success")) == []
    for i in range(3):
        engine.process(ev(T0 + 1 + i, src_ip="9.9.9.9", outcome="failure"))
    assert engine.process(ev(T0 + 5, src_ip="8.8.8.8", outcome="success")) == []  # other source
    fired = engine.process(ev(T0 + 6, src_ip="9.9.9.9", outcome="success"))
    assert len(fired) == 1 and "3 failures, then a success" in fired[0].summary


def test_summary_template_cannot_be_abused_by_log_content():
    r = rule(type="match", match={"action": "login"}, summary="{user} did {nope} {user.__class__}")
    alert = DetectionEngine([r]).process(ev(T0, src_ip="1.1.1.1", user="{raw}"))[0]
    assert alert.summary == "{raw} did ? {user.__class__}"


@pytest.mark.parametrize("broken", [
    {"severity": "catastrophic"}, {"type": "magic"}, {"match": {}},
    {"match": {"url|re": "("}}, {"match": {"a|nope": 1}}, {"window": None, "type": "threshold"},
])
def test_bad_rules_are_rejected_at_load_time(broken):
    doc = {"id": "T-1", "title": "t", "severity": "high", "type": "threshold",
           "match": {"a": 1}, "group_by": "src_ip", "window": 60, "count": 3,
           "mitre": {"tactic": "X", "technique": "T0"}}
    doc.update(broken)
    if broken.get("window", 1) is None:
        del doc["window"]
    with pytest.raises(RuleError):
        load_rule(doc)
