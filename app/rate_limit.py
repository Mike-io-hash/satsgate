from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque


class RateLimiter:
    """In-memory sliding window with a hard cap on tracked keys.

    Not distributed (a gateway or Redis is still the right production limiter).
    The cap keeps a flood of distinct keys from growing this process without bound.
    When the cap is hit, the least-recently-used key is dropped.
    """

    def __init__(self, *, window_seconds: int, max_requests: int, max_keys: int = 10_000) -> None:
        self.window_seconds = int(window_seconds)
        self.max_requests = int(max_requests)
        self.max_keys = max(1, int(max_keys))
        self._lock = threading.Lock()
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._ops = 0

    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._hits)

    def _evict_expired(self, cutoff: float) -> None:
        stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
        for key in stale:
            del self._hits[key]

    def allow(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        if not key or len(key) > 200:
            return False, self.window_seconds

        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            self._ops += 1
            if self._ops % 64 == 0:
                self._evict_expired(cutoff)

            hits = self._hits.get(key)
            if hits is None:
                while len(self._hits) >= self.max_keys:
                    self._hits.popitem(last=False)
                hits = deque()
                self._hits[key] = hits
            else:
                self._hits.move_to_end(key)

            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= self.max_requests:
                retry_after = int((hits[0] + self.window_seconds) - now) + 1
                return False, max(1, retry_after)

            hits.append(now)
            return True, 0
