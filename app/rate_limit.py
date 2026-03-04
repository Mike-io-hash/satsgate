from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Simple in-memory rate limiter (sliding window).

    - Not distributed (in production, replace with Redis / gateway).
    - Resets on process restart.

    Goal: reduce spam and prevent free resource burn.
    """

    def __init__(self, *, window_seconds: int, max_requests: int) -> None:
        self.window_seconds = int(window_seconds)
        self.max_requests = int(max_requests)
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> tuple[bool, int]:
        """Returns (allowed, retry_after_seconds)."""
        now = time.time()
        cutoff = now - self.window_seconds

        with self._lock:
            q = self._hits.get(key)
            if q is None:
                q = deque()
                self._hits[key] = q

            # Drop old hits
            while q and q[0] <= cutoff:
                q.popleft()

            if len(q) >= self.max_requests:
                # how long until the oldest hit expires from the window
                oldest = q[0]
                retry_after = int((oldest + self.window_seconds) - now) + 1
                return False, max(1, retry_after)

            q.append(now)
            return True, 0
