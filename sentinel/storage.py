"""SQLite storage. Every query is parameterized: log data is attacker
controlled, so it must never be glued into a SQL string."""
from __future__ import annotations

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

from .schema import Event, iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, source TEXT, host TEXT,
    action TEXT, outcome TEXT, src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
    user TEXT, raw TEXT, extra TEXT);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY, ts REAL NOT NULL, rule_id TEXT, title TEXT,
    summary TEXT, severity TEXT, tactic TEXT, technique TEXT,
    technique_name TEXT, entity TEXT, src_ip TEXT, host TEXT, user TEXT,
    status TEXT NOT NULL DEFAULT 'new', incident_id INTEGER,
    evidence TEXT, context TEXT, note TEXT, updated REAL);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY, entity TEXT, first_seen REAL, last_seen REAL,
    status TEXT NOT NULL DEFAULT 'open', risk INTEGER DEFAULT 0,
    alert_count INTEGER DEFAULT 0, tactics TEXT, severity TEXT);

CREATE TABLE IF NOT EXISTS blocklist (
    ip TEXT PRIMARY KEY, reason TEXT, ts REAL, actor TEXT);

CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY, ts REAL, actor TEXT, action TEXT,
    target TEXT, detail TEXT);
"""

ALERT_STATUSES = ("new", "acknowledged", "closed", "false_positive")


class Storage:
    def __init__(self, path: Path):
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        # One shared connection for in-memory databases (used by tests),
        # otherwise a fresh connection per operation (thread safe).
        self._shared = sqlite3.connect(":memory:", check_same_thread=False) \
            if self.path == ":memory:" else None
        with self.connect() as db:
            db.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        db = self._shared or sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        if not self._shared:
            db.execute("PRAGMA journal_mode=WAL")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            if not self._shared:
                db.close()

    def reset(self) -> None:
        with self.connect() as db:
            for table in ("events", "alerts", "incidents", "blocklist", "audit"):
                db.execute("DELETE FROM %s" % table)  # table names are constants above

    # ---------------------------------------------------------------- events
    def add_events(self, events: Iterable[Event]) -> None:
        with self.connect() as db:
            for e in events:
                cur = db.execute(
                    "INSERT INTO events (ts, source, host, action, outcome, src_ip,"
                    " dst_ip, dst_port, user, raw, extra) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                    (e.ts, e.source, e.host, e.action, e.outcome, e.src_ip, e.dst_ip,
                     e.dst_port, e.user, e.raw, json.dumps(e.extra)))
                e.id = cur.lastrowid

    def search_events(self, query: str, limit: int = 200) -> List[Dict[str, Any]]:
        like = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events WHERE src_ip = ? OR dst_ip = ? OR user = ?"
                " OR host = ? OR raw LIKE ? ESCAPE '\\' ORDER BY ts DESC LIMIT ?",
                (query, query, query, query, like, limit)).fetchall()
        return [_event_row(r) for r in rows]

    def events_by_ids(self, ids: List[int]) -> List[Dict[str, Any]]:
        if not ids:
            return []
        marks = ",".join("?" for _ in ids)
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM events WHERE id IN (%s) ORDER BY ts" % marks, ids).fetchall()
        return [_event_row(r) for r in rows]

    # ---------------------------------------------------------------- alerts
    def add_alert(self, record: Dict[str, Any]) -> int:
        with self.connect() as db:
            cur = db.execute(
                "INSERT INTO alerts (ts, rule_id, title, summary, severity, tactic,"
                " technique, technique_name, entity, src_ip, host, user, incident_id,"
                " evidence, context, updated) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record["ts"], record["rule_id"], record["title"], record["summary"],
                 record["severity"], record["tactic"], record["technique"],
                 record["technique_name"], record["entity"], record["src_ip"],
                 record["host"], record["user"], record["incident_id"],
                 json.dumps(record["evidence"]), json.dumps(record["context"]),
                 record["ts"]))
            return int(cur.lastrowid)

    def alerts(self, status: Optional[str] = None, severity: Optional[str] = None,
               incident_id: Optional[int] = None, limit: int = 200) -> List[Dict[str, Any]]:
        clauses, params = [], []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if incident_id:
            clauses.append("incident_id = ?")
            params.append(incident_id)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM alerts %s ORDER BY ts DESC LIMIT ?" % where,
                params + [limit]).fetchall()
        return [_alert_row(r) for r in rows]

    def alert(self, alert_id: int) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        return _alert_row(row) if row else None

    def set_alert_status(self, alert_id: int, status: str, note: str, actor: str) -> bool:
        if status not in ALERT_STATUSES:
            raise ValueError("invalid status")
        now = time.time()
        with self.connect() as db:
            cur = db.execute(
                "UPDATE alerts SET status = ?, note = ?, updated = ? WHERE id = ?",
                (status, note, now, alert_id))
            if cur.rowcount == 0:
                return False
            db.execute(
                "INSERT INTO audit (ts, actor, action, target, detail) VALUES (?,?,?,?,?)",
                (now, actor, "alert_" + status, "alert:%d" % alert_id, note))
            row = db.execute("SELECT incident_id FROM alerts WHERE id = ?",
                             (alert_id,)).fetchone()
            if row and row["incident_id"]:
                open_left = db.execute(
                    "SELECT COUNT(*) FROM alerts WHERE incident_id = ? AND status IN"
                    " ('new','acknowledged')", (row["incident_id"],)).fetchone()[0]
                db.execute("UPDATE incidents SET status = ? WHERE id = ?",
                           ("open" if open_left else "resolved", row["incident_id"]))
        return True

    # ------------------------------------------------------------- incidents
    def open_incident_for(self, entity: str, ts: float, gap: int) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM incidents WHERE entity = ? AND status = 'open'"
                " AND ? - last_seen <= ? ORDER BY last_seen DESC LIMIT 1",
                (entity, ts, gap)).fetchone()
        return dict(row) if row else None

    def open_incident_for_host(self, host: str, ts: float, gap: int) -> Optional[Dict[str, Any]]:
        with self.connect() as db:
            row = db.execute(
                "SELECT i.* FROM alerts a JOIN incidents i ON i.id = a.incident_id"
                " WHERE a.host = ? AND i.status = 'open' AND ? - a.ts <= ?"
                " ORDER BY a.ts DESC LIMIT 1", (host, ts, gap)).fetchone()
        return dict(row) if row else None

    def create_incident(self, entity: str, ts: float) -> int:
        with self.connect() as db:
            cur = db.execute(
                "INSERT INTO incidents (entity, first_seen, last_seen, tactics)"
                " VALUES (?,?,?,?)", (entity, ts, ts, "[]"))
            return int(cur.lastrowid)

    def update_incident(self, incident_id: int, last_seen: float, risk: int,
                        alert_count: int, tactics: List[str], severity: str) -> None:
        with self.connect() as db:
            db.execute(
                "UPDATE incidents SET last_seen = ?, risk = ?, alert_count = ?,"
                " tactics = ?, severity = ? WHERE id = ?",
                (last_seen, risk, alert_count, json.dumps(tactics), severity, incident_id))

    def incidents(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT * FROM incidents ORDER BY (status = 'open') DESC, risk DESC,"
                " last_seen DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            item = dict(r)
            item["tactics"] = json.loads(item["tactics"] or "[]")
            item["first_seen_iso"] = iso(item["first_seen"])
            item["last_seen_iso"] = iso(item["last_seen"])
            out.append(item)
        return out

    # -------------------------------------------------------------- response
    def block_ip(self, ip: str, reason: str, actor: str) -> None:
        now = time.time()
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO blocklist (ip, reason, ts, actor)"
                       " VALUES (?,?,?,?)", (ip, reason, now, actor))
            db.execute("INSERT INTO audit (ts, actor, action, target, detail)"
                       " VALUES (?,?,?,?,?)", (now, actor, "contain_ip", ip, reason))

    def unblock_ip(self, ip: str, actor: str) -> bool:
        now = time.time()
        with self.connect() as db:
            cur = db.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))
            if cur.rowcount:
                db.execute("INSERT INTO audit (ts, actor, action, target, detail)"
                           " VALUES (?,?,?,?,?)", (now, actor, "release_ip", ip, ""))
            return bool(cur.rowcount)

    def blocklist(self) -> List[Dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM blocklist ORDER BY ts DESC").fetchall()
        return [dict(r, when=iso(r["ts"])) for r in rows]

    def audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as db:
            rows = db.execute("SELECT * FROM audit ORDER BY ts DESC, id DESC LIMIT ?",
                              (limit,)).fetchall()
        return [dict(r, when=iso(r["ts"])) for r in rows]

    # ------------------------------------------------------------- summaries
    def summary(self) -> Dict[str, Any]:
        with self.connect() as db:
            one = lambda sql, *p: db.execute(sql, p).fetchone()[0]  # noqa: E731
            bounds = db.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
            data = {
                "events": one("SELECT COUNT(*) FROM events"),
                "alerts": one("SELECT COUNT(*) FROM alerts"),
                "open_alerts": one("SELECT COUNT(*) FROM alerts WHERE status IN"
                                   " ('new','acknowledged')"),
                "open_incidents": one("SELECT COUNT(*) FROM incidents WHERE status='open'"),
                "blocked": one("SELECT COUNT(*) FROM blocklist"),
                "first_event": bounds[0], "last_event": bounds[1],
                "by_severity": {r[0]: r[1] for r in db.execute(
                    "SELECT severity, COUNT(*) FROM alerts WHERE status IN"
                    " ('new','acknowledged') GROUP BY severity")},
                "by_source": {r[0]: r[1] for r in db.execute(
                    "SELECT source, COUNT(*) FROM events GROUP BY source")},
                "techniques": [dict(r) for r in db.execute(
                    "SELECT tactic, technique, technique_name, COUNT(*) AS count,"
                    " MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3"
                    " WHEN 'medium' THEN 2 ELSE 1 END) AS worst FROM alerts"
                    " WHERE status != 'false_positive'"
                    " GROUP BY tactic, technique, technique_name")],
                "top_entities": [dict(r) for r in db.execute(
                    "SELECT entity, COUNT(*) AS alerts, COUNT(DISTINCT tactic) AS tactics"
                    " FROM alerts WHERE status != 'false_positive' GROUP BY entity"
                    " ORDER BY alerts DESC, entity LIMIT 6")],
            }
            data["timeline"] = self._timeline(db, bounds)
        return data

    @staticmethod
    def _timeline(db: sqlite3.Connection, bounds, buckets: int = 48,
                  span: int = 3 * 3600) -> List[Dict[str, Any]]:
        """Event and alert counts for the most recent `span` seconds of data,
        bucketed in SQL so the work stays in the database."""
        if bounds[0] is None:
            return []
        end = max(bounds[1], bounds[0] + 60)
        start = max(bounds[0], end - span)
        width = (end - start) / buckets
        series = {"events": [0] * buckets, "alerts": [0] * buckets}
        for table in series:  # table names are the two constants above
            rows = db.execute(
                "SELECT CAST((ts - ?) / ? AS INTEGER) AS bucket, COUNT(*) FROM %s"
                " WHERE ts >= ? GROUP BY bucket" % table, (start, width, start))
            for bucket, count in rows:
                series[table][min(max(bucket, 0), buckets - 1)] += count
        return [{"t": iso(start + i * width), "events": series["events"][i],
                 "alerts": series["alerts"][i]} for i in range(buckets)]


def _event_row(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["extra"] = json.loads(item.get("extra") or "{}")
    item["timestamp"] = iso(item["ts"])
    return item


def _alert_row(row: sqlite3.Row) -> Dict[str, Any]:
    item = dict(row)
    item["evidence"] = json.loads(item.get("evidence") or "[]")
    item["context"] = json.loads(item.get("context") or "{}")
    item["timestamp"] = iso(item["ts"])
    return item
