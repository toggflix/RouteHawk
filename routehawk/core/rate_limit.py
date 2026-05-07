from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class AsyncRateLimiter:
    requests_per_second: float
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    _next_allowed_at: float = 0.0

    async def wait(self) -> None:
        if self.requests_per_second <= 0:
            return

        async with self._lock:
            now = time.monotonic()
            delay = self._next_allowed_at - now
            if delay > 0:
                await asyncio.sleep(delay)
            self._next_allowed_at = time.monotonic() + (1.0 / self.requests_per_second)

