from __future__ import annotations

import asyncio
from typing import Awaitable, Iterable, List, TypeVar


T = TypeVar("T")


async def run_limited(tasks: Iterable[Awaitable[T]], max_concurrency: int) -> List[T]:
    semaphore = asyncio.Semaphore(max_concurrency)

    async def guarded(task: Awaitable[T]) -> T:
        async with semaphore:
            return await task

    return await asyncio.gather(*(guarded(task) for task in tasks))

