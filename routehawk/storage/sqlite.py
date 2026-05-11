from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from routehawk.core.diff import scope_fingerprint, target_fingerprint


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    run_id TEXT PRIMARY KEY,
    generated_at TEXT NOT NULL,
    target TEXT NOT NULL,
    target_fingerprint TEXT NOT NULL DEFAULT '',
    scope_json TEXT NOT NULL,
    scope_fingerprint TEXT NOT NULL DEFAULT '',
    asset_count INTEGER NOT NULL,
    javascript_file_count INTEGER NOT NULL,
    metadata_count INTEGER NOT NULL,
    endpoint_count INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    high_risk_count INTEGER NOT NULL,
    medium_risk_count INTEGER NOT NULL,
    new_endpoint_count INTEGER NOT NULL,
    removed_endpoint_count INTEGER NOT NULL,
    changed_endpoint_count INTEGER NOT NULL,
    result_json TEXT NOT NULL,
    diff_json TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_scans_generated_at ON scans(generated_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_target_scope_fp ON scans(target_fingerprint, scope_fingerprint, generated_at DESC);
"""


@dataclass(frozen=True)
class ScanRecord:
    run_id: str
    generated_at: str
    target: str
    target_fingerprint: str
    scope: List[str]
    scope_fingerprint: str
    endpoint_count: int
    finding_count: int
    high_risk_count: int
    new_endpoint_count: int
    removed_endpoint_count: int
    changed_endpoint_count: int


def initialize_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(path) as connection:
        connection.executescript(SCHEMA)
        _ensure_scan_columns(connection)


def record_scan(
    path: Path,
    metadata: Dict[str, object],
    result_payload: Dict[str, object],
    diff_payload: Dict[str, object],
) -> None:
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO scans (
                run_id,
                generated_at,
                target,
                target_fingerprint,
                scope_json,
                scope_fingerprint,
                asset_count,
                javascript_file_count,
                metadata_count,
                endpoint_count,
                finding_count,
                high_risk_count,
                medium_risk_count,
                new_endpoint_count,
                removed_endpoint_count,
                changed_endpoint_count,
                result_json,
                diff_json
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                str(metadata.get("run_id", "")),
                str(metadata.get("generated_at", "")),
                str(metadata.get("target", "")),
                str(metadata.get("target_fingerprint", "")),
                json.dumps(metadata.get("scope", [])),
                str(metadata.get("scope_fingerprint", "")),
                _int(metadata.get("assets")),
                _int(metadata.get("javascript_files")),
                _int(metadata.get("metadata")),
                _int(metadata.get("endpoints")),
                _int(metadata.get("findings")),
                _int(metadata.get("high_risk")),
                _int(metadata.get("medium_risk")),
                _int(metadata.get("new_endpoints")),
                _int(metadata.get("removed_endpoints")),
                _int(metadata.get("changed_endpoints")),
                json.dumps(result_payload),
                json.dumps(diff_payload),
            ),
        )


def list_scan_records(path: Path, limit: int = 20) -> List[ScanRecord]:
    if not path.exists():
        return []
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT
                run_id,
                generated_at,
                target,
                target_fingerprint,
                scope_json,
                scope_fingerprint,
                endpoint_count,
                finding_count,
                high_risk_count,
                new_endpoint_count,
                removed_endpoint_count,
                changed_endpoint_count
            FROM scans
            ORDER BY generated_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [_record_from_row(row) for row in rows]


def fetch_scan_payload(path: Path, run_id: str, column: str) -> Optional[Dict[str, object]]:
    if column not in {"result_json", "diff_json"}:
        raise ValueError("Unsupported scan payload column.")
    if not path.exists():
        return None
    initialize_database(path)
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            f"SELECT {column} FROM scans WHERE run_id = ?",
            (run_id,),
        ).fetchone()
    if row is None:
        return None
    try:
        payload = json.loads(row[0])
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _record_from_row(row: tuple) -> ScanRecord:
    try:
        scope = json.loads(row[4])
    except json.JSONDecodeError:
        scope = []
    if not isinstance(scope, list):
        scope = []
    target = str(row[2])
    target_fp = str(row[3] or "")
    scope_fp = str(row[5] or "")
    normalized_scope = [str(item) for item in scope]
    return ScanRecord(
        run_id=str(row[0]),
        generated_at=str(row[1]),
        target=target,
        target_fingerprint=target_fp or target_fingerprint(target),
        scope=normalized_scope,
        scope_fingerprint=scope_fp or scope_fingerprint(normalized_scope),
        endpoint_count=int(row[6]),
        finding_count=int(row[7]),
        high_risk_count=int(row[8]),
        new_endpoint_count=int(row[9]),
        removed_endpoint_count=int(row[10]),
        changed_endpoint_count=int(row[11]),
    )


def _int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _ensure_scan_columns(connection: sqlite3.Connection) -> None:
    columns = {
        str(row[1]).lower()
        for row in connection.execute("PRAGMA table_info(scans)").fetchall()
        if len(row) >= 2
    }
    if "target_fingerprint" not in columns:
        connection.execute(
            "ALTER TABLE scans ADD COLUMN target_fingerprint TEXT NOT NULL DEFAULT ''"
        )
    if "scope_fingerprint" not in columns:
        connection.execute(
            "ALTER TABLE scans ADD COLUMN scope_fingerprint TEXT NOT NULL DEFAULT ''"
        )
