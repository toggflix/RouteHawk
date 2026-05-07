from __future__ import annotations

import json
from typing import List

from routehawk.core.models import Finding


def import_nuclei_json(text: str) -> List[Finding]:
    findings = []
    for item in _json_records(text):
        info = item.get("info", {}) if isinstance(item.get("info"), dict) else {}
        matched = str(item.get("matched-at") or item.get("host") or item.get("url") or "unknown")
        template_id = str(item.get("template-id") or item.get("template") or "nuclei-template")
        severity = _severity(str(info.get("severity") or item.get("severity") or "info"))
        name = str(info.get("name") or template_id)
        findings.append(
            Finding(
                type="imported_nuclei",
                severity=severity,
                target=matched,
                endpoint=matched,
                evidence=[f"Nuclei template: {template_id}", f"Name: {name}"],
                manual_check=[
                    "Review the imported finding evidence manually.",
                    "Confirm the target is in scope.",
                    "Validate impact without automated exploitation.",
                ],
                confidence="medium",
            )
        )
    return findings


def _json_records(text: str) -> List[dict]:
    stripped = text.strip()
    if not stripped:
        return []
    if stripped.startswith("["):
        loaded = json.loads(stripped)
        return [item for item in loaded if isinstance(item, dict)] if isinstance(loaded, list) else []
    records = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line:
            continue
        loaded = json.loads(line)
        if isinstance(loaded, dict):
            records.append(loaded)
    return records


def _severity(value: str) -> str:
    lowered = value.lower()
    if lowered in {"critical", "high"}:
        return "high"
    if lowered == "medium":
        return "medium"
    if lowered == "low":
        return "low"
    return "info"
