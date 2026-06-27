"""Normalized, reporter-facing result model.

The internal agent schemas (``SecurityFinding`` / ``QualityFinding``) are an
implementation detail of the graph. The engine projects them onto these stable
types so that reporters, the API, and integrators depend on one contract that
does not change when the graph internals do.
"""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from codesentinel.config import SEVERITY_ORDER, severity_rank


@dataclass
class Location:
    path: str
    start_line: int = 1
    end_line: int = 1
    snippet: str = ""


@dataclass
class Citation:
    doc: str = ""
    passage_id: str = ""
    excerpt: str | None = None


@dataclass
class Finding:
    rule_id: str                 # e.g. "CS-PY-SQLI" or finding id
    kind: str                    # "security" | "quality"
    category: str
    severity: str
    confidence: float
    message: str
    location: Location
    cwe: str | None = None
    owasp: str | None = None
    fix: str = ""
    citation: Citation | None = None
    fingerprint: str = ""

    def compute_fingerprint(self) -> str:
        """Stable identity for dedupe + baseline suppression.

        Intentionally excludes line numbers so that unrelated edits above a
        finding do not change its identity (only the code at the site and the
        rule/file do).
        """
        norm_snippet = " ".join((self.location.snippet or "").split())
        basis = "|".join([
            self.kind,
            self.cwe or self.rule_id,
            self.location.path,
            norm_snippet,
        ])
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:16]

    def __post_init__(self):
        if not self.fingerprint:
            self.fingerprint = self.compute_fingerprint()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class FileScan:
    path: str
    language: str | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    skipped: str | None = None  # reason if skipped


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    errors: list[str] = field(default_factory=list)
    tool: str = "codesentinel"
    tool_version: str = "0.0.0"
    edition: str = "community"
    target: str = "."
    duration_seconds: float = 0.0
    suppressed: int = 0

    # ---- Summaries ----
    def severity_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            counts[str(f.severity).upper()] = counts.get(str(f.severity).upper(), 0) + 1
        return counts

    def count_at_or_above(self, severity: str) -> int:
        thr = severity_rank(severity)
        return sum(1 for f in self.findings if severity_rank(f.severity) <= thr)

    def gate_failed(self, fail_on: str, max_findings: int | None = None) -> bool:
        """True if the result should fail CI under the given policy."""
        if self.count_at_or_above(fail_on) > 0:
            return True
        if max_findings is not None and len(self.findings) > max_findings:
            return True
        return False

    def summary(self) -> dict[str, Any]:
        sc = self.severity_counts()
        return {
            "total_findings": len(self.findings),
            "security": sum(1 for f in self.findings if f.kind == "security"),
            "quality": sum(1 for f in self.findings if f.kind == "quality"),
            "by_severity": sc,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "suppressed": self.suppressed,
            "errors": len(self.errors),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "tool_version": self.tool_version,
            "edition": self.edition,
            "target": self.target,
            "duration_seconds": round(self.duration_seconds, 3),
            "summary": self.summary(),
            "findings": [f.to_dict() for f in self.findings],
            "errors": self.errors,
        }
