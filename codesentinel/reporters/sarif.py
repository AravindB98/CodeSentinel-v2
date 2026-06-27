"""SARIF 2.1.0 reporter.

Static Analysis Results Interchange Format (OASIS standard) is the lingua franca
for security findings. Emitting valid SARIF lets CodeSentinel results upload to
GitHub code scanning, GitLab, Azure DevOps, and Defect Dojo with no glue code.

The output models rules as ``reportingDescriptor`` objects (one per CWE/category),
references them by index from each result, maps severities to SARIF levels plus
GitHub's numeric ``security-severity`` property, and carries CodeSentinel's RAG
citation and confidence as result properties — preserving the provenance that is
the product's differentiator.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List

from codesentinel.models import Finding, ScanResult

SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"
INFO_URI = "https://github.com/AravindB98/CodeSentinel"

# SARIF level per severity.
_LEVEL = {
    "CRITICAL": "error", "HIGH": "error",
    "MEDIUM": "warning", "LOW": "note", "INFO": "note",
}
# GitHub code scanning maps this 0.0-10.0 score to its own severity buckets.
_SECURITY_SEVERITY = {
    "CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "3.0", "INFO": "1.0",
}


def _rule_key(f: Finding) -> str:
    """Stable rule identity (the *class* of issue), distinct from instance id."""
    if f.cwe:
        return f.cwe
    return f"{f.kind}/{f.category}".replace(" ", "-")


def _build_rules(findings: List[Finding]):
    """Return (rule_descriptors, key->index map) deduped by rule identity."""
    descriptors: List[Dict[str, Any]] = []
    index: Dict[str, int] = {}
    for f in findings:
        key = _rule_key(f)
        if key in index:
            continue
        index[key] = len(descriptors)
        tags = [f.kind]
        if f.cwe:
            tags.append("external/cwe/" + f.cwe.lower())
        if f.owasp:
            tags.append("owasp")
        help_uri = (
            f"https://cwe.mitre.org/data/definitions/{f.cwe.split('-')[1]}.html"
            if f.cwe and f.cwe.startswith("CWE-") and f.cwe.split("-")[1].isdigit()
            else INFO_URI
        )
        descriptors.append({
            "id": key,
            "name": f.category.replace(" ", ""),
            "shortDescription": {"text": f.category},
            "fullDescription": {"text": f.message or f.category},
            "helpUri": help_uri,
            "defaultConfiguration": {"level": _LEVEL.get(f.severity.upper(), "warning")},
            "properties": {
                "tags": tags,
                "security-severity": _SECURITY_SEVERITY.get(f.severity.upper(), "5.0"),
                "cwe": f.cwe,
                "owasp": f.owasp,
            },
        })
    return descriptors, index


def _result(f: Finding, rule_index: int, rule_id: str) -> Dict[str, Any]:
    region: Dict[str, Any] = {
        "startLine": max(1, f.location.start_line),
        "endLine": max(f.location.start_line, f.location.end_line),
    }
    if f.location.snippet:
        region["snippet"] = {"text": f.location.snippet}
    msg = f.message or f.category
    if f.fix:
        msg = f"{msg}\nRemediation: {f.fix}"
    props: Dict[str, Any] = {"confidence": f.confidence, "kind": f.kind}
    if f.citation and f.citation.passage_id:
        props["provenance"] = f"{f.citation.doc}::{f.citation.passage_id}"
    if f.owasp:
        props["owasp"] = f.owasp
    return {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": _LEVEL.get(f.severity.upper(), "warning"),
        "message": {"text": msg},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": f.location.path, "uriBaseId": "SRCROOT"},
                "region": region,
            }
        }],
        "partialFingerprints": {"codesentinel/v1": f.fingerprint},
        "properties": props,
    }


def to_sarif(result: ScanResult) -> Dict[str, Any]:
    descriptors, index = _build_rules(result.findings)
    results = [
        _result(f, index[_rule_key(f)], _rule_key(f)) for f in result.findings
    ]
    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": "CodeSentinel",
                    "informationUri": INFO_URI,
                    "version": result.tool_version,
                    "rules": descriptors,
                }
            },
            "results": results,
            "columnKind": "utf16CodeUnits",
            "originalUriBaseIds": {"SRCROOT": {"uri": "file:///"}},
            "properties": {
                "edition": result.edition,
                "summary": result.summary(),
            },
        }],
    }


def render(result: ScanResult) -> str:
    return json.dumps(to_sarif(result), indent=2)
