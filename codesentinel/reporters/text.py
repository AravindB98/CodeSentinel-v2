"""Human-readable terminal and JSON/Markdown reporters."""
from __future__ import annotations

import json
from typing import Dict

from codesentinel.models import ScanResult

# ANSI colors (auto-disabled when not a TTY by the CLI).
_COL = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
    "LOW": "\033[36m", "INFO": "\033[37m", "RESET": "\033[0m", "DIM": "\033[2m",
    "BOLD": "\033[1m",
}


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_text(result: ScanResult, color: bool = True) -> str:
    def c(key: str) -> str:
        return _COL[key] if color else ""
    out = []
    s = result.summary()
    out.append(f"{c('BOLD')}CodeSentinel {result.tool_version}{c('RESET')} "
               f"({result.edition} edition) — target: {result.target}")
    out.append("")
    if not result.findings:
        out.append(f"{c('LOW')}No findings.{c('RESET')}")
    for f in result.findings:
        col = c(f.severity.upper())
        loc = f"{f.location.path}:{f.location.start_line}"
        tag = f.cwe or f.rule_id
        out.append(f"{col}{f.severity:<8}{c('RESET')} {tag:<10} {loc}")
        out.append(f"  {f.category}: {f.message.splitlines()[0]}")
        if f.location.snippet:
            out.append(f"  {c('DIM')}> {f.location.snippet.strip()[:120]}{c('RESET')}")
        if f.fix:
            out.append(f"  fix: {f.fix.splitlines()[0][:140]}")
        if f.citation and f.citation.passage_id:
            out.append(f"  {c('DIM')}provenance: {f.citation.doc}::{f.citation.passage_id} "
                       f"| confidence {f.confidence:.2f}{c('RESET')}")
        out.append("")
    by = s["by_severity"]
    out.append(f"{c('BOLD')}Summary:{c('RESET')} {s['total_findings']} finding(s) "
               f"[crit {by['CRITICAL']} · high {by['HIGH']} · med {by['MEDIUM']} · "
               f"low {by['LOW']} · info {by['INFO']}] across {s['files_scanned']} file(s); "
               f"{s['suppressed']} suppressed; {s['errors']} error(s).")
    return "\n".join(out)


def render_markdown(result: ScanResult) -> str:
    s = result.summary()
    by = s["by_severity"]
    out = [
        f"# CodeSentinel Report — `{result.target}`",
        "",
        f"**Version:** {result.tool_version} · **Edition:** {result.edition} · "
        f"**Duration:** {result.duration_seconds:.2f}s",
        "",
        "| Severity | Count |",
        "|---|---|",
        f"| Critical | {by['CRITICAL']} |",
        f"| High | {by['HIGH']} |",
        f"| Medium | {by['MEDIUM']} |",
        f"| Low | {by['LOW']} |",
        f"| Info | {by['INFO']} |",
        f"| **Total** | **{s['total_findings']}** |",
        "",
        f"Scanned {s['files_scanned']} file(s); {s['suppressed']} suppressed; "
        f"{s['errors']} error(s).",
        "",
    ]
    if result.findings:
        out.append("## Findings\n")
        for f in result.findings:
            tag = f.cwe or f.rule_id
            out.append(f"### {f.severity} · {tag} · `{f.location.path}:{f.location.start_line}`")
            out.append("")
            out.append(f"**{f.category}** — {f.message.splitlines()[0]}")
            out.append("")
            if f.location.snippet:
                out.append("```")
                out.append(f.location.snippet.strip())
                out.append("```")
            if f.fix:
                out.append(f"**Remediation:** {f.fix}")
                out.append("")
            if f.citation and f.citation.passage_id:
                out.append(f"_Provenance: {f.citation.doc} :: {f.citation.passage_id} "
                           f"· confidence {f.confidence:.2f}_")
            out.append("")
    return "\n".join(out)
