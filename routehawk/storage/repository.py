from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from routehawk.core.models import ScanResult


@dataclass
class InMemoryRepository:
    scans: List[ScanResult] = field(default_factory=list)

    def add_scan(self, result: ScanResult) -> None:
        self.scans.append(result)

    def list_scans(self) -> List[ScanResult]:
        return list(self.scans)

