"""CycloneDX 1.5 SBOM generation.

A Software Bill of Materials is required by US EO 14028 / NIST SSDF for software
sold to the federal government, and increasingly expected by enterprise buyers.
This emits a valid CycloneDX 1.5 JSON document describing CodeSentinel and the
dependency versions actually resolved in the current environment.
"""
from __future__ import annotations

import datetime as _dt
import uuid
from importlib import metadata
from typing import Any

# Declared dependency surface (core + extras) we attempt to resolve.
_KNOWN = [
    "pydantic", "pyyaml", "numpy", "anthropic", "chromadb", "sentence-transformers",
    "scikit-learn", "langgraph", "langchain-core", "fastapi", "uvicorn",
    "python-multipart", "streamlit", "cryptography",
]


def _component(name: str, version: str, ctype: str = "library") -> dict[str, Any]:
    return {
        "type": ctype,
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{name.lower()}@{version}",
    }


def generate_sbom() -> dict[str, Any]:
    try:
        from codesentinel import __version__ as ver
    except Exception:  # pragma: no cover
        ver = "0.0.0"

    components: list[dict[str, Any]] = []
    for name in _KNOWN:
        try:
            components.append(_component(name, metadata.version(name)))
        except metadata.PackageNotFoundError:
            continue  # optional/extra not installed in this environment

    now = _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "CodeSentinel", "name": "codesentinel", "version": ver}],
            "component": {
                "type": "application",
                "name": "codesentinel",
                "version": ver,
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "purl": f"pkg:pypi/codesentinel@{ver}",
            },
        },
        "components": components,
    }
