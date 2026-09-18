from sentinel import simulator as sim
from sentinel.correlate import risk_score
from sentinel.respond import contain_ip

from .conftest import T0, feed


def alert(rule_id, severity, tactic, intel=False, critical_asset=False):
    return {"rule_id": rule_id, "severity": severity, "tactic": tactic, "context": {
        "threat_intel": [{"x": 1}] if intel else [],
        "asset": {"criticality": "critical"} if critical_asset else None}}


def test_risk_rises_with_severity_breadth_and_context():
    one = risk_score([alert("A", "medium", "Recon")])
    two = risk_score([alert("A", "medium", "Recon"), alert("B", "critical", "Initial Access")])
    ctx = risk_score([alert("A", "medium", "Recon", intel=True, critical_asset=True)])
    assert 0 < one < ctx < two <= 100


def test_repeating_the_same_alert_does_not_inflate_risk():
    assert risk_score([alert("A", "high", "X")] * 50) == risk_score([alert("A", "high", "X")])


def test_risk_never_exceeds_100():
    many = [alert("R%d" % i, "critical", "T%d" % i, True, True) for i in range(40)]
    assert risk_score(many) == 100


def test_intruder_and_what_they_did_on_the_host_become_one_incident(pipeline):
    lines, _ = sim.Scenarios(__import__("random").Random(1)).ssh_intrusion(T0)
    alerts = feed(pipeline, lines)
    assert len(alerts) == 5
    assert len({a["incident_id"] for a in alerts}) == 1
    incident = pipeline.storage.incidents()[0]
    assert incident["entity"] == "198.51.100.23" and incident["severity"] == "critical"
    assert incident["alert_count"] == 5 and incident["risk"] > 80


def test_two_attackers_are_two_incidents(pipeline):
    lines = [sim.ssh_fail(T0 + i, "bastion-01", "root", "203.0.113.9") for i in range(10)]
    lines += [sim.ssh_fail(T0 + i, "bastion-01", "root", "203.0.113.10") for i in range(10)]
    alerts = feed(pipeline, lines)
    assert len({a["incident_id"] for a in alerts}) == 2


def test_closing_every_alert_resolves_the_incident(pipeline):
    lines = [sim.ssh_fail(T0 + i, "bastion-01", "root", "203.0.113.9") for i in range(10)]
    (alert_row,) = feed(pipeline, lines)
    pipeline.storage.set_alert_status(alert_row["id"], "closed", "blocked at edge", "analyst")
    assert pipeline.storage.incidents()[0]["status"] == "resolved"
    assert pipeline.storage.audit_log()[0]["action"] == "alert_closed"


def test_containment_guardrails(pipeline):
    s, e = pipeline.storage, pipeline.enricher
    assert contain_ip(s, e, "203.0.113.66", "web attack")[0] is True
    for refused in ("10.0.2.2", "192.168.1.1", "127.0.0.1", "0.0.0.0", "not-an-ip",  # noqa: S104
                    "203.0.113.66; rm -rf /"):
        ok, _ = contain_ip(s, e, refused, "test")
        assert ok is False, "%s must be refused" % refused
    assert [b["ip"] for b in s.blocklist()] == ["203.0.113.66"]


def test_documentation_ranges_are_not_treated_as_internal(pipeline):
    # ipaddress.is_private is True for 203.0.113.0/24; our own check must not be.
    assert pipeline.enricher.is_internal("203.0.113.66") is False
    assert pipeline.enricher.is_internal("10.0.5.14") is True
