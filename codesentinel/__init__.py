"""CodeSentinel — multi-agent, retrieval-augmented code security review.

This package is the installable core. The public, stable entry points are
re-exported here so integrators can write ``from codesentinel import scan_path``
without depending on internal module layout.
"""
from __future__ import annotations

__all__ = [
    "__version__",
    "get_version",
    "scan_path",
    "scan_code",
    "Engine",
    "ScanConfig",
    "Edition",
    "current_edition",
]

__version__ = "1.0.0"


def get_version() -> str:
    """Return the installed CodeSentinel version string."""
    return __version__


def __getattr__(name: str):  # PEP 562 lazy exports — keep import cost low
    # Heavy submodules (engine pulls in the graph/RAG stack) are imported lazily
    # so that ``import codesentinel`` stays cheap for CLI ``--version`` etc.
    if name in {"scan_path", "scan_code", "Engine"}:
        from codesentinel.engine import Engine, scan_code, scan_path

        return {"scan_path": scan_path, "scan_code": scan_code, "Engine": Engine}[name]
    if name == "ScanConfig":
        from codesentinel.config import ScanConfig

        return ScanConfig
    if name in {"Edition", "current_edition"}:
        from codesentinel.editions import Edition, current_edition

        return {"Edition": Edition, "current_edition": current_edition}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
