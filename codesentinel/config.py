"""Configuration and policy model for CodeSentinel.

A single :class:`ScanConfig` controls scanning behaviour: which files are in
scope, which rules run, the severity gate that fails CI, LLM/retrieval
parameters, and licensing. Configuration is resolved in this precedence order
(highest wins):

    explicit overrides  >  environment variables  >  .codesentinel.yml  >  defaults

The model is implemented with stdlib dataclasses (no third-party dependency) so
that ``import codesentinel.config`` works in any environment, including minimal
air-gapped builds.
"""
from __future__ import annotations

import dataclasses
import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:  # YAML is a core dependency, but degrade gracefully if it is missing.
    import yaml
    _YAML = True
except Exception:  # pragma: no cover
    _YAML = False

CONFIG_FILENAMES = (".codesentinel.yml", ".codesentinel.yaml", "codesentinel.yml")

# Severity ordering, highest first. Used for thresholds and gates.
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
_SEV_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}  # 0 = most severe


def severity_rank(sev: str) -> int:
    """Return a rank where 0 is most severe; unknown severities sort lowest."""
    return _SEV_RANK.get(str(sev).upper(), len(SEVERITY_ORDER))


def meets_threshold(sev: str, threshold: str) -> bool:
    """True if ``sev`` is at least as severe as ``threshold``."""
    return severity_rank(sev) <= severity_rank(threshold)


# Files and directories never worth scanning. Kept conservative; users extend
# via the ``exclude`` config key.
DEFAULT_EXCLUDES: List[str] = [
    "**/.git/**", "**/.hg/**", "**/.svn/**",
    "**/node_modules/**", "**/bower_components/**", "**/vendor/**",
    "**/.venv/**", "**/venv/**", "**/env/**", "**/__pycache__/**",
    "**/dist/**", "**/build/**", "**/target/**", "**/out/**",
    "**/.mypy_cache/**", "**/.ruff_cache/**", "**/.pytest_cache/**",
    "**/site-packages/**", "**/.tox/**", "**/coverage/**",
    "**/*.min.js", "**/*.bundle.js", "**/*.map",
]

# Extension -> language. Drives both file selection and the detector dispatch.
DEFAULT_LANGUAGE_MAP: Dict[str, str] = {
    ".py": "python", ".pyi": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php", ".phtml": "php",
}


@dataclass
class LLMConfig:
    """LLM and retrieval parameters."""
    model: str = "claude-sonnet-4-5"
    mock: bool = False                 # force deterministic offline mode
    max_tokens: int = 4000
    temperature: float = 0.0
    retrieval_k: int = 6               # passages retrieved per finding pass
    max_retries: int = 3               # evaluator reroute circuit-breaker bound


@dataclass
class GateConfig:
    """CI gating policy."""
    severity_threshold: str = "INFO"   # minimum severity to *report*
    fail_on: str = "HIGH"              # findings at/above this -> non-zero exit
    max_findings: Optional[int] = None  # optional ceiling before failing


@dataclass
class ScanConfig:
    """Top-level scan configuration."""
    # Scope
    include: List[str] = field(default_factory=lambda: ["**/*"])
    exclude: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    language_map: Dict[str, str] = field(default_factory=lambda: dict(DEFAULT_LANGUAGE_MAP))
    max_file_bytes: int = 1_000_000    # skip files larger than this
    max_files: Optional[int] = None    # cap total files scanned (None = no cap)

    # Rules
    enabled_rules: Optional[List[str]] = None   # allow-list of rule/CWE ids (None = all)
    disabled_rules: List[str] = field(default_factory=list)  # deny-list of rule/CWE ids
    min_confidence: float = 0.5

    # Behaviour
    concurrency: int = 4
    rescan_on_empty: bool = False
    engine: str = "auto"               # "auto" | "deterministic" | "llm"
    baseline: Optional[str] = None     # path to a baseline file of suppressed fingerprints
    quality: bool = True               # run the code-quality auditor too

    # Sub-configs
    llm: LLMConfig = field(default_factory=LLMConfig)
    gate: GateConfig = field(default_factory=GateConfig)

    # Licensing
    license_key: Optional[str] = None

    # ---- Scope helpers ----
    def is_included(self, rel_path: str) -> bool:
        """Match a repo-relative path against include/exclude globs."""
        rel = rel_path.replace(os.sep, "/")
        if any(fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch("/" + rel, pat)
               for pat in self.exclude):
            return False
        return any(fnmatch.fnmatch(rel, pat) for pat in self.include)

    def language_for(self, path: str) -> Optional[str]:
        """Return the configured language for a file, or None if unsupported."""
        return self.language_map.get(Path(path).suffix.lower())

    def rule_enabled(self, *ids: str) -> bool:
        """True if a rule identified by any of ``ids`` (rule id, CWE) is active."""
        ids_l = {i.lower() for i in ids if i}
        if any(d.lower() in ids_l for d in self.disabled_rules):
            return False
        if self.enabled_rules is None:
            return True
        return any(e.lower() in ids_l for e in self.enabled_rules)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def _coerce(dc_type, data: Dict[str, Any]):
    """Build a dataclass from a dict, ignoring unknown keys and nesting sub-configs."""
    if not isinstance(data, dict):
        return dc_type()
    kwargs: Dict[str, Any] = {}
    fields = {f.name: f for f in dataclasses.fields(dc_type)}
    for name, f in fields.items():
        if name not in data:
            continue
        val = data[name]
        if name == "llm" and isinstance(val, dict):
            kwargs[name] = _coerce(LLMConfig, val)
        elif name == "gate" and isinstance(val, dict):
            kwargs[name] = _coerce(GateConfig, val)
        else:
            kwargs[name] = val
    return dc_type(**kwargs)


def find_config_file(start: Optional[str] = None) -> Optional[Path]:
    """Search ``start`` and its parents for a CodeSentinel config file."""
    cur = Path(start or os.getcwd()).resolve()
    for directory in [cur, *cur.parents]:
        for name in CONFIG_FILENAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def _apply_env(cfg: ScanConfig) -> ScanConfig:
    """Overlay environment-variable overrides onto a config."""
    if os.getenv("CODESENTINEL_MOCK_LLM") == "1":
        cfg.llm.mock = True
    if os.getenv("ANTHROPIC_API_KEY") and os.getenv("CODESENTINEL_MOCK_LLM") != "1":
        cfg.llm.mock = False
    if model := os.getenv("CODESENTINEL_MODEL"):
        cfg.llm.model = model
    if key := os.getenv("CODESENTINEL_LICENSE_KEY"):
        cfg.license_key = key
    if fail_on := os.getenv("CODESENTINEL_FAIL_ON"):
        cfg.gate.fail_on = fail_on.upper()
    return cfg


def load_config(
    path: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
    search_from: Optional[str] = None,
) -> ScanConfig:
    """Resolve effective configuration.

    Args:
        path: explicit path to a config file. If omitted, search upward from
            ``search_from`` (or cwd).
        overrides: dict merged last (highest precedence) — typically CLI flags.
        search_from: directory to begin the upward search for a config file.
    """
    data: Dict[str, Any] = {}
    cfg_path = Path(path) if path else find_config_file(search_from)
    if cfg_path and cfg_path.is_file():
        if not _YAML:
            raise RuntimeError(
                f"Config file {cfg_path} found but PyYAML is not installed. "
                "Install with `pip install pyyaml`."
            )
        loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{cfg_path}: top-level config must be a mapping")
        data.update(loaded)

    cfg = _coerce(ScanConfig, data)
    cfg = _apply_env(cfg)

    if overrides:
        for k, v in overrides.items():
            if v is None:
                continue
            if k in {"model", "mock", "max_tokens", "temperature", "retrieval_k", "max_retries"}:
                setattr(cfg.llm, k, v)
            elif k in {"severity_threshold", "fail_on", "max_findings"}:
                setattr(cfg.gate, k, v)
            elif hasattr(cfg, k):
                setattr(cfg, k, v)
    return cfg
