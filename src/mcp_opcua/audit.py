# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial
# Copyright (c) 2026 USTechService Corporation
"""Append-only JSONL audit log with an optional SHA-256 hash chain."""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    canon = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canon.encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path, hash_chain: bool = True) -> None:
        self.path = path
        self.hash_chain = hash_chain
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._prev = self._last_hash()

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = ""
        with self.path.open("rb") as f:
            for line in f:
                if line.strip():
                    last = line.decode()
        if not last:
            return GENESIS
        return str(json.loads(last).get("hash", GENESIS))

    def append(self, **fields: Any) -> dict[str, Any]:
        with self._lock:
            rec: dict[str, Any] = {"ts": datetime.now(UTC).isoformat(), **fields}
            if self.hash_chain:
                rec["prev"] = self._prev
                rec["hash"] = _digest(rec)
                self._prev = rec["hash"]
            line = json.dumps(rec, default=str, separators=(",", ":"))
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()
            return rec


def verify(path: Path) -> tuple[bool, str]:
    """Check every record's hash and link. Returns (ok, message)."""
    if not path.is_file():
        return False, f"{path}: no such audit log"
    prev = GENESIS
    n = 0
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return False, f"line {lineno}: not valid JSON"
            if "hash" not in rec:
                return False, f"line {lineno}: no hash (log written without hash_chain?)"
            if rec.get("prev") != prev:
                return False, f"line {lineno}: chain broken (prev does not match)"
            if _digest(rec) != rec["hash"]:
                return False, f"line {lineno}: record modified (hash mismatch)"
            prev = rec["hash"]
            n += 1
    return True, f"ok: {n} records verified"
