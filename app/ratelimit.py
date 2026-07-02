from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Tuple


@dataclass
class _Window:
    minute_start: float
    minute_count: int
    day_start: float
    day_count: int


class RateLimiter:
    """Fixed-window limiter (per-minute and per-day) keyed by IP or user id.
    In-memory and thread-safe — enough to protect free-tier quotas and deter
    abuse on a single host. Clock is injectable for deterministic tests."""

    def __init__(self, per_min: int, per_day: int,
                 clock: Callable[[], float] = time.time, max_keys: int = 50_000) -> None:
        self.per_min = per_min
        self.per_day = per_day
        self._clock = clock
        self._max_keys = max_keys
        self._state: Dict[str, _Window] = {}
        self._lock = threading.Lock()

    def _evict(self, now: float) -> None:
        # drop windows whose daily bucket has fully expired; if still over cap,
        # drop the oldest ~10% so the dict can never grow without bound.
        for k in [k for k, w in self._state.items() if now - w.day_start >= 86_400]:
            del self._state[k]
        if len(self._state) >= self._max_keys:
            for k in sorted(self._state, key=lambda k: self._state[k].day_start)[: self._max_keys // 10 + 1]:
                del self._state[k]

    def check(self, key: str) -> Tuple[bool, int]:
        """Return (allowed, retry_after_seconds). Counts the request when allowed."""
        now = self._clock()
        with self._lock:
            w = self._state.get(key)
            if w is None:
                if len(self._state) >= self._max_keys:
                    self._evict(now)
                self._state[key] = _Window(now, 1, now, 1)
                return True, 0
            if now - w.minute_start >= 60:
                w.minute_start, w.minute_count = now, 0
            if now - w.day_start >= 86_400:
                w.day_start, w.day_count = now, 0
            if w.minute_count >= self.per_min:
                return False, int(60 - (now - w.minute_start)) + 1
            if w.day_count >= self.per_day:
                return False, int(86_400 - (now - w.day_start)) + 1
            w.minute_count += 1
            w.day_count += 1
            return True, 0
