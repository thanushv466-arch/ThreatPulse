"""Flask API and dashboard.

Security notes (a security tool should hold itself to the standard it checks):
  * Log data is attacker controlled. The front end renders it with
    textContent only, never innerHTML, and a strict Content-Security-Policy
    forbids inline scripts, so a <script> tag inside a logged URL is inert.
  * All SQL is parameterized (see storage.py).
  * State-changing requests must be JSON and same-origin (CSRF defence).
  * The server binds to 127.0.0.1 and never runs in debug mode.
  * There is no login. That is acceptable for a localhost lab and is the
    first thing to add before exposing this anywhere (see README roadmap).
"""
from __future__ import annotations

import logging
import random
import threading
import time
from typing import Any, Dict
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, render_template, request

from .. import __version__, simulator
from ..mitre import TACTICS
from ..pipeline import Pipeline
from ..respond import contain_ip
from ..storage import ALERT_STATUSES

SEVERITIES = ("low", "medium", "high", "critical")
LIVE = {"running": False}
log = logging.getLogger("sentinel")


def create_app(pipeline: Pipeline) -> Flask:
    app = Flask(__name__)
    app.config["JSON_SORT_KEYS"] = False
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024
    storage = pipeline.storage
    rules_by_id = {r["id"]: r for r in pipeline.rule_catalog()}

    @app.after_request
    def security_headers(response: Response) -> Response:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.before_request
    def guard_writes():
        if request.method != "POST":
            return None
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc != request.host:
            return jsonify(error="Cross-origin requests are not allowed."), 403
        if not request.is_json:
            return jsonify(error="Send JSON."), 415
        return None

    def body() -> Dict[str, Any]:
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else {}

    # ------------------------------------------------------------------ pages
    @app.get("/")
    def index():
        return render_template("index.html", version=__version__)

    @app.get("/healthz")
    def health():
        return jsonify(status="ok", version=__version__)

    # -------------------------------------------------------------------- api
    @app.get("/api/summary")
    def summary():
        data = storage.summary()
        data["tactics"] = [{"name": n, "id": i} for n, i in TACTICS]
        data["pipeline"] = dict(pipeline.stats, rules=len(rules_by_id))
        data["live"] = LIVE["running"]
        data["scenarios"] = list(simulator.LIVE_SCENARIOS)
        return jsonify(data)

    @app.get("/api/alerts")
    def alerts():
        status = request.args.get("status")
        severity = request.args.get("severity")
        if status and status not in ALERT_STATUSES + ("open",):
            return jsonify(error="Unknown status."), 400
        if severity and severity not in SEVERITIES:
            return jsonify(error="Unknown severity."), 400
        limit = min(max(request.args.get("limit", 150, type=int), 1), 500)
        if status == "open":
            rows = [a for a in storage.alerts(severity=severity, limit=500)
                    if a["status"] in ("new", "acknowledged")][:limit]
        else:
            rows = storage.alerts(status=status, severity=severity, limit=limit)
        for row in rows:
            row.pop("evidence", None)
        return jsonify(alerts=rows)

    @app.get("/api/alerts/<int:alert_id>")
    def alert_detail(alert_id: int):
        alert = storage.alert(alert_id)
        if not alert:
            return jsonify(error="No such alert."), 404
        alert["events"] = storage.events_by_ids(alert.pop("evidence"))
        alert["rule"] = rules_by_id.get(alert["rule_id"])
        alert["contained"] = any(b["ip"] == alert["src_ip"] for b in storage.blocklist())
        return jsonify(alert)

    @app.post("/api/alerts/<int:alert_id>/status")
    def alert_status(alert_id: int):
        data = body()
        status = data.get("status")
        if status not in ALERT_STATUSES:
            return jsonify(error="Status must be one of %s." % ", ".join(ALERT_STATUSES)), 400
        note = str(data.get("note", ""))[:500]
        if not storage.set_alert_status(alert_id, status, note, "analyst"):
            return jsonify(error="No such alert."), 404
        return jsonify(ok=True)

    @app.get("/api/incidents")
    def incidents():
        items = storage.incidents()
        for item in items:
            members = storage.alerts(incident_id=item["id"], limit=100)
            item["alerts"] = [{k: a[k] for k in ("id", "timestamp", "title", "severity",
                                                 "tactic", "technique", "status")}
                              for a in reversed(members)]
        return jsonify(incidents=items)

    @app.get("/api/events/search")
    def search():
        query = request.args.get("q", "").strip()
        if not 2 <= len(query) <= 100:
            return jsonify(error="Search for 2 to 100 characters."), 400
        return jsonify(events=storage.search_events(query))

    @app.get("/api/rules")
    def rules():
        return jsonify(rules=list(rules_by_id.values()))

    @app.get("/api/response")
    def response_state():
        return jsonify(blocklist=storage.blocklist(), audit=storage.audit_log())

    @app.get("/api/blocklist.txt")
    def blocklist_export():
        text = "".join(b["ip"] + "\n" for b in storage.blocklist())
        return Response(text, mimetype="text/plain")

    @app.post("/api/contain")
    def contain():
        data = body()
        ok, message = contain_ip(storage, pipeline.enricher, str(data.get("ip", "")),
                                 str(data.get("reason", "Contained from dashboard")))
        return jsonify(ok=ok, message=message), (200 if ok else 400)

    @app.post("/api/release")
    def release():
        ok = storage.unblock_ip(str(body().get("ip", "")), "analyst")
        return jsonify(ok=ok), (200 if ok else 404)

    @app.post("/api/simulate")
    def simulate():
        name = body().get("scenario")
        if name not in simulator.LIVE_SCENARIOS:
            return jsonify(error="Unknown scenario."), 400
        new_alerts = run_live_scenario(pipeline, name)
        return jsonify(ok=True, new_alerts=len(new_alerts))

    return app


# ---------------------------------------------------------------- live feed
def run_live_scenario(pipeline: Pipeline, name: str):
    """Play an attack so that it ends "now", squeezed into about 20 seconds."""
    rng = random.Random()
    scenarios = simulator.Scenarios(rng)
    build = getattr(scenarios, name)
    kwargs: Dict[str, Any] = {"pace": 0.02}
    if name != "endpoint_compromise":
        kwargs["ip"] = "%s.%d" % (rng.choice(["203.0.113", "198.51.100", "192.0.2"]),
                                  rng.randint(2, 250))
    now = time.time()
    probe, _ = build(now, **kwargs)
    duration = probe[-1][0] - now
    lines, _ = build(now - duration, **kwargs)
    return pipeline.ingest_lines((src, line) for _, src, line in lines)


def start_live_feed(pipeline: Pipeline, interval: float = 2.0) -> threading.Thread:
    """Trickle ordinary traffic into the pipeline so the dashboard moves."""
    rng = random.Random()

    def loop() -> None:
        LIVE["running"] = True
        while LIVE["running"]:
            now = time.time()
            batch = []
            for _ in range(rng.randint(1, 3)):
                batch.append(simulator.web(
                    now, "100.64.%d.%d" % (rng.randint(0, 120), rng.randint(2, 250)),
                    rng.choice(simulator.PAGES), 200, rng.randint(300, 48000),
                    rng.choice(simulator.BROWSERS)))
            if rng.random() < 0.3:
                batch.append(simulator.ufw(now, "100.%d.%d.%d" % (
                    rng.randint(64, 127), rng.randint(0, 255), rng.randint(1, 254)),
                    "10.0.1.10", rng.choice([23, 445, 3389])))
            if rng.random() < 0.4:
                batch.append(simulator.zeek(now, "10.0.5.%d" % rng.randint(10, 40),
                                            "100.%d.%d.%d" % (rng.randint(64, 127),
                                                              rng.randint(0, 255),
                                                              rng.randint(1, 254)),
                                            443, rng.randint(800, 90000),
                                            rng.randint(2000, 900000)))
            try:
                pipeline.ingest_lines((src, line) for _, src, line in batch)
            except Exception:  # noqa: BLE001 - the feed must never kill the app
                log.exception("live feed batch failed")
            time.sleep(interval)

    thread = threading.Thread(target=loop, name="sentinel-live-feed", daemon=True)
    thread.start()
    return thread
