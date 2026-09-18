from sentinel.anomaly import VolumeAnomalyDetector
from sentinel.schema import Event

from .conftest import T0

START = (int(T0) // 60) * 60.0


def minute_of(detector, minute, count, ip="100.64.0.1"):
    found = []
    for i in range(count):
        result = detector.process(Event(ts=START + minute * 60 + i * (59.0 / max(count, 1)),
                                        source="nginx", host="web-01", action="http_request",
                                        raw="", src_ip=ip))
        if result:
            found.append(result)
    return found


def test_flood_is_flagged_and_names_the_top_talker():
    d = VolumeAnomalyDetector()
    found = []
    for m in range(20):
        found += minute_of(d, m, 30 + m % 5)
    assert found == []
    minute_of(d, 20, 900, ip="192.0.2.200")
    found = minute_of(d, 21, 30)          # the flood minute is scored when it closes
    assert len(found) == 1
    assert found[0].top_src_ip == "192.0.2.200" and found[0].zscore >= 4


def test_no_alert_during_warmup():
    d = VolumeAnomalyDetector()
    found = minute_of(d, 0, 30) + minute_of(d, 1, 5000) + minute_of(d, 2, 30)
    assert found == [], "with no baseline yet we cannot call anything abnormal"


def test_busy_but_normal_growth_stays_quiet():
    d = VolumeAnomalyDetector()
    found = []
    for m in range(40):
        found += minute_of(d, m, 100 + m * 2)     # steady organic growth
    assert found == []


def test_flood_does_not_poison_the_baseline():
    d = VolumeAnomalyDetector(suppress=0)
    for m in range(15):
        minute_of(d, m, 30)
    found = []
    for m in range(15, 20):
        found += minute_of(d, m, 900)
    found += minute_of(d, 20, 30)
    assert len(found) == 5, "every flood minute should still look abnormal"
