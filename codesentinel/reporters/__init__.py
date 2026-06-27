"""Reporters: render a :class:`ScanResult` into an output format.

Supported formats: ``text`` (colorized terminal), ``json``, ``sarif`` (2.1.0),
``markdown``, ``html``.
"""
from __future__ import annotations

from typing import Callable, Dict

from codesentinel.models import ScanResult
from codesentinel.reporters import html as _html
from codesentinel.reporters import sarif as _sarif
from codesentinel.reporters import text as _text

FORMATS = ("text", "json", "sarif", "markdown", "html")


def render(result: ScanResult, fmt: str = "text", color: bool = True) -> str:
    fmt = (fmt or "text").lower()
    if fmt == "text":
        return _text.render_text(result, color=color)
    if fmt == "json":
        return _text.render_json(result)
    if fmt == "markdown" or fmt == "md":
        return _text.render_markdown(result)
    if fmt == "sarif":
        return _sarif.render(result)
    if fmt == "html":
        return _html.render(result)
    raise ValueError(f"unknown format '{fmt}' (choose from {', '.join(FORMATS)})")


__all__ = ["render", "FORMATS"]
