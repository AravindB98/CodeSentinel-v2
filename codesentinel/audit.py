"""Tamper-evident, append-only audit log.

Government and regulated buyers require an immutable record of who scanned what
and when. Each entry is hash-chained to its predecessor (``hash = SHA-256(prev_hash
|| canonical_entry)``), so any insertion, deletion, or edit anywhere in the log
breaks the chain and is detectable by :func:`verify_chain`. The log is plain
JSON Lines — greppable, shippable to a SIEM, and independently verifiable.

Exporting/verifying the audit log is an Enterprise/Government feature; *writing*
it is always on so the record exists from day one.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

GENESIS = "0" * 64
_lock = threading.Lock()


def _canonical(entry: Dict[str, Any]) -> bytes:
    return json.dumps(entry, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _entry_hash(prev_hash: str, body: Dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(_canonical(body))
    return h.hexdigest()


class AuditLog:
    """Thread-safe, file-backed, hash-chained audit log."""

    def __init__(self, path: Optional[str] = None) -> None:
        self.path = Path(path or os.getenv("CODESENTINEL_AUDIT_LOG", "codesentinel-audit.log"))

    def _last_hash(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["hash"]
                    except Exception:  # pragma: no cover
                        continue
        return last

    def record(self, actor: str, action: str, **details: Any) -> Dict[str, Any]:
        """Append an event. Returns the written record (including its hash)."""
        with _lock:
            prev = self._last_hash()
            body = {
                "ts": time.time(),
                "actor": actor,
                "action": action,
                "details": details,
                "prev_hash": prev,
            }
            entry = dict(body)
            entry["hash"] = _entry_hash(prev, body)
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
            return entry

    def read(self, limit: Optional[int] = None,
             tenant: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        rows: List[Dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                if tenant and rec.get("actor") != tenant:
                    continue
                rows.append(rec)
        if limit:
            rows = rows[-limit:]
        return rows

    def verify_chain(self) -> Dict[str, Any]:
        """Recompute the chain and report the first break, if any."""
        prev = GENESIS
        count = 0
        for rec in self.read():
            body = {k: rec[k] for k in ("ts", "actor", "action", "details", "prev_hash")}
            expected = _entry_hash(prev, body)
            if rec.get("prev_hash") != prev or rec.get("hash") != expected:
                return {"valid": False, "broken_at": count, "entries": count}
            prev = rec["hash"]
            count += 1
        return {"valid": True, "entries": count}


_default: Optional[AuditLog] = None


def get_audit_log() -> AuditLog:
    global _default
    if _default is None:
        _default = AuditLog()
    return _default
