"""Statistical anomaly detection on event volume.

This is deliberately simple statistics, not machine learning. For each log
source we count events per minute and keep the last `history` minutes as
the baseline. When a minute closes, we ask: how many standard deviations
above normal was it (its z-score)? A minute that is far above baseline AND
above an absolute floor raises an alert.

Signature rules catch what we already know to look for. This catches
"something is suddenly very different", which is how floods and noisy
tooling show up.
"""
from __future__ import annotations

import statistics
from collections import Counter, deque
from dataclasses import dataclass
from typing import Deque, Dict, List, Optional

from .schema import Event


@dataclass
class VolumeAnomaly:
    ts: float
    source: str
    count: int
    baseline_mean: float
    zscore: float
    top_src_ip: Optional[str]
    sample: List[Event]


class VolumeAnomalyDetector:
    def __init__(self, z_threshold: float = 4.0, min_count: int = 150,
                 history: int = 30, warmup: int = 10, suppress: int = 600):
        self.z_threshold = z_threshold
        self.min_count = min_count
        self.warmup = warmup
        self.suppress = suppress
        self._last_alert: Dict[str, float] = {}
        self._history: Dict[str, Deque[int]] = {}
        self._history_len = history
        self._minute: Dict[str, int] = {}
        self._count: Dict[str, int] = {}
        self._ips: Dict[str, Counter] = {}
        self._sample: Dict[str, List[Event]] = {}

    def process(self, event: Event) -> Optional[VolumeAnomaly]:
        src = event.source
        minute = int(event.ts // 60)
        current = self._minute.get(src)
        result = None
        if current is None:
            self._open(src, minute)
        elif minute > current:
            result = self._close(src)
            # Quiet minutes between two events still count as zero traffic.
            gap = min(minute - current - 1, self._history_len)
            for _ in range(gap):
                self._history[src].append(0)
            self._open(src, minute)
        self._count[src] += 1
        if event.src_ip:
            self._ips[src][event.src_ip] += 1
        if len(self._sample[src]) < 10:
            self._sample[src].append(event)
        return result

    def _open(self, src: str, minute: int) -> None:
        self._history.setdefault(src, deque(maxlen=self._history_len))
        self._minute[src] = minute
        self._count[src] = 0
        self._ips[src] = Counter()
        self._sample[src] = []

    def _close(self, src: str) -> Optional[VolumeAnomaly]:
        count = self._count[src]
        history = self._history[src]
        anomaly = None
        if len(history) >= self.warmup and count >= self.min_count:
            mean = statistics.fmean(history)
            # Floor the deviation so a perfectly flat baseline cannot make
            # every tiny bump look infinite.
            stdev = max(statistics.pstdev(history), 1.0, mean * 0.1)
            z = (count - mean) / stdev
            if z >= self.z_threshold:
                top = self._ips[src].most_common(1)
                anomaly = VolumeAnomaly(
                    ts=(self._minute[src] + 1) * 60.0, source=src, count=count,
                    baseline_mean=round(mean, 1), zscore=round(z, 1),
                    top_src_ip=top[0][0] if top else None,
                    sample=list(self._sample[src]))
        # An anomalous minute is NOT added to the baseline, otherwise a
        # patient attacker could teach the detector that floods are normal.
        if anomaly is None:
            history.append(count)
            return None
        # One alert per source per suppression period: a ten-minute flood is
        # one problem, not ten.
        last = self._last_alert.get(src)
        if last is not None and anomaly.ts - last < self.suppress:
            return None
        self._last_alert[src] = anomaly.ts
        return anomaly
