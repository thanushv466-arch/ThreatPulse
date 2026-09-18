import pytest

from sentinel import simulator as sim
from sentinel.web.app import create_app

from .conftest import T0, feed

XSS = "/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E"


@pytest.fixture
def client(pipeline):
    feed(pipeline, [sim.web(T0, "203.0.113.66", XSS)] +
         [sim.ssh_fail(T0 + 5 + i, "bastion-01", "root", "203.0.113.9") for i in range(10)])
    return create_app(pipeline).test_client()


def post(client, url, payload, **headers):
    return client.post(url, json=payload, headers=headers)


def test_summary_and_alert_list(client):
    data = client.get("/api/summary").get_json()
    assert data["events"] == 11 and data["open_alerts"] == 2 and len(data["tactics"]) == 11
    alerts = client.get("/api/alerts?status=open").get_json()["alerts"]
    assert {a["rule_id"] for a in alerts} == {"SEN-005", "SEN-001"}


def test_alert_detail_carries_evidence_and_playbook(client):
    detail = client.get("/api/alerts/2").get_json()
    assert detail["rule"]["response"] and len(detail["events"]) == 8
    assert "Failed password" in detail["events"][0]["raw"]


def test_security_headers_on_every_response(client):
    for path in ("/", "/api/summary", "/api/alerts/999"):
        headers = client.get(path).headers
        assert "script-src 'self'" in headers["Content-Security-Policy"]
        assert "unsafe-inline" not in headers["Content-Security-Policy"]
        assert headers["X-Frame-Options"] == "DENY"
        assert headers["X-Content-Type-Options"] == "nosniff"


def test_logged_xss_payload_is_only_ever_served_as_json(client):
    response = client.get("/api/alerts/1")
    assert response.mimetype == "application/json"
    assert "<script>" in response.get_json()["summary"]      # stored faithfully as evidence
    assert b"<script>alert" not in client.get("/").data      # never templated into the page


def test_dashboard_script_never_uses_innerhtml():
    import pathlib
    js = (pathlib.Path(__file__).parent.parent / "sentinel/web/static/app.js").read_text()
    code = "\n".join(line for line in js.splitlines() if not line.strip().startswith(("*", "/*", "//")))
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval("):
        assert banned not in code


def test_triage_workflow_and_audit_trail(client):
    assert post(client, "/api/alerts/2/status", {"status": "acknowledged", "note": "looking"}).status_code == 200
    assert post(client, "/api/alerts/2/status", {"status": "deleted"}).status_code == 400
    assert post(client, "/api/alerts/999/status", {"status": "closed"}).status_code == 404
    audit = client.get("/api/response").get_json()["audit"]
    assert audit[0]["action"] == "alert_acknowledged" and audit[0]["detail"] == "looking"


def test_contain_and_release(client):
    assert post(client, "/api/contain", {"ip": "203.0.113.9", "reason": "brute force"}).status_code == 200
    assert post(client, "/api/contain", {"ip": "10.0.2.2"}).status_code == 400   # domain controller
    assert client.get("/api/blocklist.txt").data == b"203.0.113.9\n"
    assert post(client, "/api/release", {"ip": "203.0.113.9"}).status_code == 200
    assert client.get("/api/blocklist.txt").data == b""


def test_csrf_defences(client):
    cross = post(client, "/api/contain", {"ip": "203.0.113.9"}, Origin="https://evil.example")
    assert cross.status_code == 403
    form = client.post("/api/contain", data={"ip": "203.0.113.9"})    # a plain HTML form
    assert form.status_code == 415
    assert client.get("/api/response").get_json()["blocklist"] == []


def test_input_validation(client):
    assert client.get("/api/alerts?severity=banana").status_code == 400
    assert client.get("/api/alerts?status=' OR 1=1--").status_code == 400
    assert client.get("/api/events/search?q=a").status_code == 400
    assert client.get("/api/events/search?q=" + "a" * 101).status_code == 400
    assert post(client, "/api/simulate", {"scenario": "__import__"}).status_code == 400


def test_search_treats_sql_wildcards_as_text(client):
    assert client.get("/api/events/search?q=%25%25").get_json()["events"] == []
    hits = client.get("/api/events/search?q=203.0.113.9").get_json()["events"]
    assert len(hits) == 10


def test_live_scenario_raises_alerts(client):
    result = post(client, "/api/simulate", {"scenario": "ssh_intrusion"}).get_json()
    assert result["ok"] and result["new_alerts"] >= 4
