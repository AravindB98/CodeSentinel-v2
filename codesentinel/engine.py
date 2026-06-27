"""Scanning engine: orchestrates the multi-agent graph across files and repos.

The engine is the product's core. It:
  * discovers in-scope files (config include/exclude/size/language),
  * runs the LangGraph review pipeline per file with bounded concurrency,
  * projects internal agent findings onto the normalized :mod:`models` types,
  * applies rule allow/deny lists, confidence and severity thresholds,
  * dedupes and suppresses findings via a baseline,
  * and returns a single :class:`ScanResult`.

It is import-light: nothing here requires an API key, LangGraph, or a vector DB
to be installed — every dependency degrades to a working offline path.
"""
from __future__ import annotations

import logging
import os
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from codesentinel.config import ScanConfig, load_config, meets_threshold
from codesentinel.editions import current_edition
from codesentinel.models import Citation, FileScan, Finding, Location, ScanResult

logger = logging.getLogger(__name__)


def _tool_version() -> str:
    try:
        from codesentinel import __version__
        return __version__
    except Exception:  # pragma: no cover
        return "0.0.0"


class Engine:
    """Reusable scanner. Build once; call :meth:`scan_path` / :meth:`scan_code`."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or load_config()
        # Honour mock/model selection before the LLM singleton is created.
        if self.config.llm.mock:
            os.environ["CODESENTINEL_MOCK_LLM"] = "1"
        from codesentinel.utils.llm_client import reset_llm
        reset_llm()
        self._graph = None  # built lazily (importing langgraph is optional)
        # Backend selection: deterministic rules engine when offline (no API key /
        # forced mock), full multi-agent LLM graph when a real model is available.
        engine = getattr(self.config, "engine", "auto")
        if engine == "auto":
            self.backend = "deterministic" if self.config.llm.mock else "llm"
        else:
            self.backend = engine

    # ---- Graph access ----
    def _get_graph(self):
        if self._graph is None:
            from codesentinel.graph.build_graph import build_graph
            self._graph = build_graph()
        return self._graph

    # ---- Public API ----
    def scan_code(
        self, code: str, language: str = "python", path: str = "snippet"
    ) -> ScanResult:
        """Scan a single in-memory snippet."""
        started = time.time()
        result = ScanResult(
            tool_version=_tool_version(),
            edition=current_edition(self.config).value,
            target=path,
        )
        fs = self._scan_one(path, language, code)
        self._absorb(result, [fs])
        result.duration_seconds = time.time() - started
        return result

    def scan_path(self, target: str) -> ScanResult:
        """Scan a file or directory tree."""
        started = time.time()
        target_path = Path(target)
        result = ScanResult(
            tool_version=_tool_version(),
            edition=current_edition(self.config).value,
            target=str(target_path),
        )
        baseline = self._load_baseline()

        files = list(self._discover(target_path))
        scans: list[FileScan] = []
        if self.config.concurrency > 1 and len(files) > 1:
            with ThreadPoolExecutor(max_workers=self.config.concurrency) as ex:
                futures = {
                    ex.submit(self._scan_file, p, rel): rel for p, rel in files
                }
                for fut in as_completed(futures):
                    scans.append(fut.result())
        else:
            for p, rel in files:
                scans.append(self._scan_file(p, rel))

        self._absorb(result, scans, baseline=baseline)
        result.duration_seconds = time.time() - started
        return result

    # ---- Discovery ----
    def _discover(self, target: Path):
        """Yield (absolute_path, repo_relative_path) for in-scope files."""
        if target.is_file():
            yield target, target.name
            return
        if not target.exists():
            raise FileNotFoundError(f"target not found: {target}")
        count = 0
        for p in sorted(target.rglob("*")):
            if not p.is_file():
                continue
            rel = str(p.relative_to(target))
            if self.config.language_for(p.name) is None:
                continue
            if not self.config.is_included(rel):
                continue
            try:
                if p.stat().st_size > self.config.max_file_bytes:
                    logger.info("skip (too large): %s", rel)
                    continue
            except OSError:
                continue
            yield p, rel
            count += 1
            if self.config.max_files and count >= self.config.max_files:
                logger.info("max_files reached (%d)", self.config.max_files)
                return

    def _scan_file(self, path: Path, rel: str) -> FileScan:
        language = self.config.language_for(path.name) or "unknown"
        try:
            code = path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:  # pragma: no cover
            return FileScan(path=rel, language=language, error=f"read error: {e}")
        return self._scan_one(rel, language, code)

    def _scan_one(self, rel: str, language: str, code: str) -> FileScan:
        fs = FileScan(path=rel, language=language)
        if not code.strip():
            fs.skipped = "empty"
            return fs
        if self.backend == "deterministic":
            return self._scan_one_deterministic(rel, language, code)
        state = {
            "input_code": code,
            "language": language,
            "run_id": uuid.uuid4().hex[:12],
            "retry_count": {},
            "trace": [],
            "config_rescan_on_empty": self.config.rescan_on_empty,
        }
        try:
            out = self._get_graph().invoke(state)
        except Exception as e:
            logger.exception("scan failed for %s", rel)
            fs.error = str(e)
            return fs

        verdict = out.get("evaluator_verdict")
        approved: set[str] | None = None
        if verdict is not None and not any(
            "circuit_breaker" in t for t in out.get("trace", [])
        ):
            approved = set(verdict.approved_ids)

        for sf in out.get("security_findings", []) or []:
            if approved is not None and sf.finding_id not in approved:
                continue
            fs.findings.append(self._project_security(sf, rel))
        if self.config.quality:
            for qf in out.get("quality_findings", []) or []:
                fs.findings.append(self._project_quality(qf, rel))
        return fs

    def _scan_one_deterministic(self, rel: str, language: str, code: str) -> FileScan:
        """Offline backend: run the regex rule registry directly.

        Deterministic rules cannot hallucinate, so the adversarial citation gate
        (whose job is to catch LLM-invented findings) is unnecessary here. Every
        finding still carries provenance: the rule's mapped RAG passage.
        """
        from codesentinel.rules import detect
        fs = FileScan(path=rel, language=language)
        try:
            for raw in detect(code, language):
                ev = raw["evidence"]
                rs = raw["rag_source"]
                fs.findings.append(Finding(
                    rule_id=raw.get("rule_id", raw["finding_id"]),
                    kind="security",
                    category=raw["category"],
                    severity=raw["severity"],
                    confidence=float(raw["confidence"]),
                    message=f'{raw["cwe_id"]} ({raw["owasp_ref"]})',
                    location=Location(path=rel, start_line=ev["line_start"],
                                      end_line=ev["line_end"], snippet=ev["snippet"]),
                    cwe=raw["cwe_id"], owasp=raw["owasp_ref"], fix=raw["fix"],
                    citation=Citation(doc=rs["doc"], passage_id=rs["passage_id"]),
                ))
        except Exception as e:  # pragma: no cover
            fs.error = str(e)
        return fs

    # ---- Projection: internal schema -> normalized Finding ----
    def _project_security(self, sf, rel: str) -> Finding:
        sev = sf.severity.value if hasattr(sf.severity, "value") else str(sf.severity)
        rs = sf.rag_source
        return Finding(
            rule_id=sf.finding_id,
            kind="security",
            category=sf.category,
            severity=sev,
            confidence=float(sf.confidence),
            message=f"{sf.cwe_id} ({sf.owasp_ref})",
            location=Location(
                path=rel,
                start_line=sf.evidence.line_start,
                end_line=sf.evidence.line_end,
                snippet=sf.evidence.snippet,
            ),
            cwe=sf.cwe_id,
            owasp=sf.owasp_ref,
            fix=sf.fix,
            citation=Citation(doc=rs.doc, passage_id=rs.passage_id,
                              excerpt=getattr(rs, "excerpt", None)),
        )

    def _project_quality(self, qf, rel: str) -> Finding:
        sev = qf.severity.value if hasattr(qf.severity, "value") else str(qf.severity)
        return Finding(
            rule_id=qf.finding_id,
            kind="quality",
            category=qf.category,
            severity=sev,
            confidence=float(qf.confidence),
            message=qf.rationale,
            location=Location(
                path=rel,
                start_line=qf.evidence.line_start,
                end_line=qf.evidence.line_end,
                snippet=qf.evidence.snippet,
            ),
            fix=qf.suggested_refactor,
        )

    # ---- Aggregation, filtering, suppression ----
    def _absorb(self, result: ScanResult, scans: list[FileScan],
                baseline: set[str] | None = None) -> None:
        seen: set[str] = set()
        baseline = baseline or set()
        for fs in scans:
            if fs.error:
                result.errors.append(f"{fs.path}: {fs.error}")
            if fs.skipped:
                result.files_skipped += 1
                continue
            result.files_scanned += 1
            for f in fs.findings:
                if not self._passes_policy(f):
                    continue
                if f.fingerprint in seen:
                    continue
                if f.fingerprint in baseline:
                    result.suppressed += 1
                    continue
                seen.add(f.fingerprint)
                result.findings.append(f)
        # Stable, useful ordering: severity desc, then path, then line.
        from codesentinel.config import severity_rank
        result.findings.sort(
            key=lambda f: (severity_rank(f.severity), f.location.path, f.location.start_line)
        )

    def _passes_policy(self, f: Finding) -> bool:
        if f.confidence < self.config.min_confidence:
            return False
        if not meets_threshold(f.severity, self.config.gate.severity_threshold):
            return False
        if not self.config.rule_enabled(f.rule_id, f.cwe or "", f.category):
            return False
        return True

    def _load_baseline(self) -> set[str]:
        if not self.config.baseline:
            return set()
        bp = Path(self.config.baseline)
        if not bp.is_file():
            logger.warning("baseline file not found: %s", bp)
            return set()
        import json
        try:
            data = json.loads(bp.read_text(encoding="utf-8"))
            return set(data.get("fingerprints", []))
        except Exception as e:  # pragma: no cover
            logger.warning("could not parse baseline: %s", e)
            return set()


# ---- Module-level convenience wrappers (public API) ----
def scan_path(target: str, config: ScanConfig | None = None) -> ScanResult:
    return Engine(config).scan_path(target)


def scan_code(code: str, language: str = "python",
              config: ScanConfig | None = None) -> ScanResult:
    return Engine(config).scan_code(code, language)
