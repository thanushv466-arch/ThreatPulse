"""The whole thing: generate three hours of logs with five attacks hidden in
about ten thousand ordinary lines, run the pipeline, and score it."""
import json

from sentinel import simulator
from sentinel.evaluate import score
from sentinel.parsers import _syslog
from sentinel.pipeline import Pipeline
from sentinel.storage import Storage

from .conftest import T0


def test_every_planted_attack_is_found_with_no_false_alarms():
    lines, truth = simulator.generate(seed=7, end=T0)
    pipeline = Pipeline(Storage(":memory:"))
    pipeline.ingest_lines((src, line) for _, src, line in lines)
    result = score(truth, pipeline.storage.alerts(limit=10000))
    assert result["missed"] == 0, [r for r in result["rows"] if not r["detected"]]
    assert result["unexpected_alerts"] == 0, result["unexpected"]
    assert pipeline.stats["unparsed"] == 0
    assert len(pipeline.storage.incidents()) == 5


def test_a_different_random_seed_gives_the_same_verdict():
    lines, truth = simulator.generate(seed=2024, end=T0)
    pipeline = Pipeline(Storage(":memory:"))
    pipeline.ingest_lines((src, line) for _, src, line in lines)
    result = score(truth, pipeline.storage.alerts(limit=10000))
    assert (result["missed"], result["unexpected_alerts"]) == (0, 0)


def test_samples_round_trip_through_files(tmp_path):
    lines, truth = simulator.generate(seed=7, end=T0, minutes=120)
    paths = simulator.write_samples(tmp_path, lines, truth)
    meta = json.loads((tmp_path / "ground_truth.json").read_text())
    _syslog.set_reference_year(meta["reference_year"])
    pipeline = Pipeline(Storage(tmp_path / "test.db"))
    pipeline.ingest_files(paths)
    assert pipeline.stats["parsed"] == len(lines)
    assert pipeline.stats["alerts"] >= 18
