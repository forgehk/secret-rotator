"""Hash-chained audit log.

Every record carries ``prev`` (the hash of the record before it, or 64 zeros
for the first one) and ``hash`` (SHA-256 over the record's canonical JSON
without the ``hash`` field). Editing, deleting or reordering a line breaks
the chain, and ``verify_log`` reports the first line where it breaks.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def record_hash(record: dict[str, Any]) -> str:
    """SHA-256 over the canonical JSON of ``record`` minus its ``hash`` field."""
    body = {k: v for k, v in record.items() if k != "hash"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def last_hash(path: Path | None) -> str:
    """Hash of the last record in ``path``, or GENESIS for a missing/empty log."""
    if path is None or not path.exists():
        return GENESIS
    last = ""
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                last = line
    if not last:
        return GENESIS
    # Never fail a rotation over the log itself: if the last line is unreadable
    # or predates chaining, start from GENESIS and let `audit verify` flag it.
    try:
        value = json.loads(last).get("hash")
    except (json.JSONDecodeError, AttributeError):
        return GENESIS
    return value if isinstance(value, str) else GENESIS


def chain(record: dict[str, Any], prev: str) -> dict[str, Any]:
    """Return a copy of ``record`` linked to ``prev`` and sealed with its hash."""
    sealed = {k: v for k, v in record.items() if k not in ("prev", "hash")}
    sealed["prev"] = prev
    sealed["hash"] = record_hash(sealed)
    return sealed


@dataclass
class AuditReport:
    ok: bool
    entries: int
    bad_line: int | None = None
    reason: str = ""


def verify_log(path: Path) -> AuditReport:
    """Walk the log and check every record's hash and its link to the previous one."""
    prev = GENESIS
    entries = 0
    with path.open("r", encoding="utf-8") as f:
        for lineno, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                return AuditReport(False, entries, lineno, f"not valid JSON: {exc.msg}")
            if not isinstance(record, dict) or "hash" not in record or "prev" not in record:
                return AuditReport(False, entries, lineno, "record is missing prev/hash")
            if record["prev"] != prev:
                return AuditReport(False, entries, lineno,
                                   "prev does not match the previous record (line removed or reordered)")
            if record_hash(record) != record["hash"]:
                return AuditReport(False, entries, lineno, "hash mismatch (record was modified)")
            prev = record["hash"]
            entries += 1
    return AuditReport(True, entries)
