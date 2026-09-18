import pytest

from sentinel.parsers import _syslog
from sentinel.pipeline import Pipeline
from sentinel.storage import Storage

T0 = 1789000000.0   # 2026-09-10 01:46:40 UTC, a fixed "now" so tests never drift


@pytest.fixture(autouse=True)
def fixed_year():
    _syslog.set_reference_year(2026)
    yield
    _syslog.set_reference_year(None)


@pytest.fixture
def pipeline():
    return Pipeline(Storage(":memory:"))


def feed(pipeline, lines):
    """Ingest simulator-style (ts, source, line) tuples; return the alerts raised."""
    lines = sorted(lines, key=lambda item: item[0])
    pipeline.ingest_lines((src, line) for _, src, line in lines)
    return list(reversed(pipeline.storage.alerts(limit=1000)))


def rule_ids(alerts):
    return [a["rule_id"] for a in alerts]
