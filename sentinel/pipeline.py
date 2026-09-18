"""The pipeline: parse -> enrich -> detect -> correlate -> store."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import config
from .anomaly import VolumeAnomaly, VolumeAnomalyDetector
from .correlate import INCIDENT_GAP, risk_score, worst_severity
from .engine import Alert, DetectionEngine, Rule, load_rules
from .enrich import Enricher
from .parsers import parse_line, parser_for_file
from .schema import Event
from .storage import Storage

ANOMALY_RULE = {
    "id": "SEN-018", "title": "Traffic volume anomaly",
    "severity": "medium", "tactic": "Impact", "technique": "T1498",
    "technique_name": "Network Denial of Service",
}


class Pipeline:
    def __init__(self, storage: Storage, rules_dir: Optional[Path] = None,
                 data_dir: Optional[Path] = None):
        data_dir = data_dir or config.DATA_DIR
        self.storage = storage
        self.rules: List[Rule] = load_rules(rules_dir or config.RULES_DIR)
        self.engine = DetectionEngine(self.rules)
        self.anomaly = VolumeAnomalyDetector()
        self.enricher = Enricher(data_dir / "threat_intel.csv", data_dir / "assets.yml")
        self.stats = {"lines": 0, "parsed": 0, "unparsed": 0, "alerts": 0}
        self._lock = threading.Lock()   # the live feed and the API share one pipeline

    # ------------------------------------------------------------------
    def ingest_lines(self, tagged: Iterable[Tuple[str, str]]) -> List[int]:
        """tagged = (parser name, raw line). Lines must be in time order."""
        return self._ingest(self._parse(tagged))

    def ingest_files(self, paths: List[Path]) -> List[int]:
        """Read several log files and merge them into one time-ordered stream,
        the way a SIEM sees many sources at once."""
        events: List[Event] = []
        for path in paths:
            source = parser_for_file(path.name)
            if not source:
                raise ValueError("Don't know which parser to use for %s" % path.name)
            with open(path, encoding="utf-8", errors="replace") as handle:
                events.extend(self._parse((source, line) for line in handle))
        events.sort(key=lambda e: e.ts)
        ids: List[int] = []
        for start in range(0, len(events), 2000):
            ids.extend(self._ingest(events[start:start + 2000]))
        return ids

    def _parse(self, tagged: Iterable[Tuple[str, str]]) -> List[Event]:
        events = []
        for source, line in tagged:
            if not line.strip():
                continue
            self.stats["lines"] += 1
            event = parse_line(source, line)
            if event is None:
                self.stats["unparsed"] += 1
                continue
            self.stats["parsed"] += 1
            self.enricher.tag_event(event)
            events.append(event)
        return events

    def _ingest(self, events: List[Event]) -> List[int]:
        with self._lock:
            self.storage.add_events(events)
            alert_ids = []
            for event in events:
                for alert in self.engine.process(event):
                    alert_ids.append(self._record(alert))
                anomaly = self.anomaly.process(event)
                if anomaly:
                    alert_ids.append(self._record_anomaly(anomaly))
            self.stats["alerts"] += len(alert_ids)
            return alert_ids

    # ------------------------------------------------------------------
    def _record(self, alert: Alert) -> int:
        rule = alert.rule
        dst_ips = {e.dst_ip for e in alert.evidence if e.dst_ip}
        return self._store({
            "ts": alert.ts, "rule_id": rule.id, "title": rule.title,
            "summary": alert.summary, "severity": rule.severity,
            "tactic": rule.tactic, "technique": rule.technique,
            "technique_name": rule.technique_name,
            "entity": self._resolve_entity(alert.entity),
            "src_ip": alert.src_ip, "host": alert.host, "user": alert.user,
            "evidence": [e.id for e in alert.evidence if e.id],
            "context": self.enricher.context(alert.src_ip, dst_ips, alert.host),
        })

    def _record_anomaly(self, anomaly: VolumeAnomaly) -> int:
        entity = anomaly.top_src_ip or anomaly.source
        record = dict(ANOMALY_RULE)
        record["rule_id"] = record.pop("id")
        record.update({
            "ts": anomaly.ts, "entity": entity, "src_ip": anomaly.top_src_ip,
            "host": anomaly.sample[0].host if anomaly.sample else None, "user": None,
            "summary": "%s volume anomaly: %d events in one minute vs a baseline of %s "
                       "(z-score %s)" % (anomaly.source, anomaly.count,
                                         anomaly.baseline_mean, anomaly.zscore),
            "evidence": [e.id for e in anomaly.sample if e.id],
            "context": self.enricher.context(anomaly.top_src_ip, [], None),
        })
        return self._store(record)

    def _resolve_entity(self, entity: str) -> str:
        """10.0.5.14 and WS-014 are the same machine. Use the asset inventory
        to give both the same name so their alerts land in one incident."""
        asset = self.enricher.asset_for(ip=entity)
        return asset["hostname"] if asset else entity

    def _store(self, record: Dict[str, Any]) -> int:
        incident = self.storage.open_incident_for(record["entity"], record["ts"], INCIDENT_GAP)
        if incident is None and not record["src_ip"] and record["host"]:
            # Host-only alerts (a sudo command, a new account) carry no source
            # address. Attach them to the open incident already touching that
            # host: the intruder who just logged in is the likeliest cause.
            incident = self.storage.open_incident_for_host(
                record["host"], record["ts"], INCIDENT_GAP)
        incident_id = incident["id"] if incident else self.storage.create_incident(
            record["entity"], record["ts"])
        record["incident_id"] = incident_id
        alert_id = self.storage.add_alert(record)
        members = self.storage.alerts(incident_id=incident_id, limit=1000)
        self.storage.update_incident(
            incident_id, last_seen=record["ts"], risk=risk_score(members),
            alert_count=len(members), tactics=sorted({a["tactic"] for a in members}),
            severity=worst_severity(members))
        return alert_id

    def rule_catalog(self) -> List[Dict[str, Any]]:
        catalog = [r.public() for r in self.rules]
        catalog.append(dict(
            ANOMALY_RULE, type="anomaly", group_by="source", window=60, count=None,
            distinct=None,
            description="Flags a minute whose event count is far above the rolling "
                        "30-minute baseline for that log source (z-score of 4 or more).",
            explain="Like a shop owner who knows a normal Tuesday sees 40 customers. "
                    "If 900 walk in within a minute, nobody needs a rulebook to know "
                    "something is off.",
            false_positives=["Marketing campaigns, product launches, load tests"],
            response=["Identify the top talker and check whether it is a customer or a bot",
                      "Rate limit or challenge the source at the edge",
                      "Check whether the flood is cover for a quieter attack"]))
        return catalog
