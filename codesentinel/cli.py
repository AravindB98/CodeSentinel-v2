"""CodeSentinel command-line interface.

Implemented with stdlib ``argparse`` so the CLI has zero third-party dependency
and runs in minimal / air-gapped installs. Exit codes are CI-friendly:

    0  success, gate passed
    1  findings at or above the configured fail-on severity (gate failed)
    2  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from codesentinel import __version__

EXIT_OK = 0
EXIT_GATE_FAILED = 1
EXIT_ERROR = 2

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _eprint(*a):
    print(*a, file=sys.stderr)


def _build_config(args):
    from codesentinel.config import load_config
    overrides = {}
    if getattr(args, "severity_threshold", None):
        overrides["severity_threshold"] = args.severity_threshold.upper()
    if getattr(args, "fail_on", None):
        overrides["fail_on"] = args.fail_on.upper()
    if getattr(args, "concurrency", None):
        overrides["concurrency"] = args.concurrency
    if getattr(args, "baseline", None):
        overrides["baseline"] = args.baseline
    if getattr(args, "mock", False):
        overrides["mock"] = True
    if getattr(args, "no_quality", False):
        overrides["quality"] = False
    return load_config(path=getattr(args, "config", None), overrides=overrides,
                       search_from=getattr(args, "path", None))


# ---------------- commands ----------------
def cmd_scan(args) -> int:
    from codesentinel.engine import Engine
    from codesentinel.reporters import render
    cfg = _build_config(args)
    try:
        engine = Engine(cfg)
        result = engine.scan_path(args.path)
    except FileNotFoundError as e:
        _eprint(f"error: {e}")
        return EXIT_ERROR

    color = sys.stdout.isatty() and not args.no_color
    out = render(result, args.format, color=color)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        if args.format != "json" or not args.quiet:
            _eprint(f"wrote {args.format} report to {args.output}")
    else:
        print(out)

    failed = result.gate_failed(cfg.gate.fail_on, cfg.gate.max_findings)
    if not args.quiet and args.output:
        s = result.summary()
        _eprint(f"{s['total_findings']} finding(s); gate fail-on={cfg.gate.fail_on}; "
                f"{'FAILED' if failed else 'passed'}")
    return EXIT_GATE_FAILED if failed else EXIT_OK


def cmd_serve(args) -> int:
    try:
        import uvicorn  # noqa
    except ImportError:
        _eprint("error: API extras not installed. Run: pip install 'codesentinel[api]'")
        return EXIT_ERROR
    import uvicorn

    from codesentinel.api.app import create_app
    host = args.host or os.getenv("CODESENTINEL_HOST", "0.0.0.0")
    port = args.port or int(os.getenv("CODESENTINEL_PORT", "8080"))
    _eprint(f"CodeSentinel API listening on http://{host}:{port}  (docs at /docs)")
    uvicorn.run(create_app(), host=host, port=port, log_level="info")
    return EXIT_OK


def cmd_ingest(args) -> int:
    import runpy
    runpy.run_module("codesentinel.rag.ingest", run_name="__main__")
    return EXIT_OK


def cmd_rules(args) -> int:
    from codesentinel.rules import iter_rules
    rules = list(iter_rules())
    if args.json:
        print(json.dumps([r.to_dict() for r in rules], indent=2))
    else:
        print(f"{'RULE ID':<16}{'CWE':<10}{'LANG':<12}{'SEVERITY':<10}DESCRIPTION")
        for r in rules:
            print(f"{r.rule_id:<16}{(r.cwe or '-'):<10}{r.language:<12}"
                  f"{r.severity:<10}{r.title}")
        print(f"\n{len(rules)} rules across "
              f"{len({r.language for r in rules})} languages.")
    return EXIT_OK


def cmd_baseline(args) -> int:
    from codesentinel.engine import Engine
    cfg = _build_config(args)
    result = Engine(cfg).scan_path(args.path)
    payload = {
        "version": 1,
        "tool_version": __version__,
        "fingerprints": sorted({f.fingerprint for f in result.findings}),
    }
    Path(args.output).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    _eprint(f"wrote baseline with {len(payload['fingerprints'])} fingerprint(s) "
            f"to {args.output}")
    return EXIT_OK


def cmd_sbom(args) -> int:
    from codesentinel.sbom import generate_sbom
    sbom = generate_sbom()
    out = json.dumps(sbom, indent=2)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _eprint(f"wrote CycloneDX SBOM to {args.output}")
    else:
        print(out)
    return EXIT_OK


def cmd_license(args) -> int:
    from codesentinel.editions import EDITION_FEATURES, Edition, current_edition, verify_license
    if args.license_cmd == "info":
        token = args.token or os.getenv("CODESENTINEL_LICENSE_KEY")
        ed = current_edition(token=token)
        info = verify_license(token) if token else None
        print(json.dumps({
            "edition": ed.value,
            "verified": bool(info and info.verified),
            "tenant": info.tenant if info else None,
            "expired": info.expired if info else None,
            "features": sorted(f.value for f in EDITION_FEATURES[ed]),
        }, indent=2))
        return EXIT_OK
    if args.license_cmd == "keygen":
        from codesentinel.editions import generate_keypair
        priv, pub = generate_keypair()
        Path(args.private_out).write_text(priv)
        Path(args.public_out).write_text(pub)
        _eprint(f"wrote private key -> {args.private_out}, public key -> {args.public_out}")
        return EXIT_OK
    if args.license_cmd == "issue":
        from codesentinel.editions import issue_license
        priv = Path(args.private_key).read_text()
        tok = issue_license(priv, args.tenant, Edition(args.edition),
                            valid_days=args.days, seats=args.seats)
        print(tok)
        return EXIT_OK
    _eprint("usage: codesentinel license {info|keygen|issue}")
    return EXIT_ERROR


def cmd_version(args) -> int:
    from codesentinel.editions import current_edition
    print(f"CodeSentinel {__version__} ({current_edition().value} edition)")
    return EXIT_OK


# ---------------- parser ----------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="codesentinel",
        description="Multi-agent, RAG-grounded code security review.",
    )
    p.add_argument("--version", action="version", version=f"CodeSentinel {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    def add_scan_opts(sp):
        sp.add_argument("path", help="file or directory to scan")
        sp.add_argument("-c", "--config", help="path to .codesentinel.yml")
        sp.add_argument("--severity-threshold", choices=SEVERITIES,
                        help="minimum severity to report")
        sp.add_argument("--fail-on", choices=SEVERITIES,
                        help="fail (exit 1) on findings at/above this severity")
        sp.add_argument("--baseline", help="baseline file of fingerprints to suppress")
        sp.add_argument("--concurrency", type=int, help="parallel file workers")
        sp.add_argument("--mock", action="store_true",
                        help="force deterministic offline mode (no LLM/API key)")
        sp.add_argument("--no-quality", action="store_true",
                        help="security findings only (skip quality auditor)")

    sp = sub.add_parser("scan", help="scan a path for vulnerabilities")
    add_scan_opts(sp)
    sp.add_argument("-f", "--format", default="text",
                    choices=["text", "json", "sarif", "markdown", "html"])
    sp.add_argument("-o", "--output", help="write report to a file instead of stdout")
    sp.add_argument("--no-color", action="store_true")
    sp.add_argument("--quiet", action="store_true")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("serve", help="run the REST API service")
    sp.add_argument("--host")
    sp.add_argument("--port", type=int)
    sp.set_defaults(func=cmd_serve)

    sp = sub.add_parser("ingest", help="(re)build the RAG knowledge base")
    sp.set_defaults(func=cmd_ingest)

    sp = sub.add_parser("rules", help="list detection rules")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(func=cmd_rules)

    sp = sub.add_parser("baseline", help="create a baseline of current findings")
    add_scan_opts(sp)
    sp.add_argument("-o", "--output", default=".codesentinel-baseline.json")
    sp.set_defaults(func=cmd_baseline)

    sp = sub.add_parser("sbom", help="emit a CycloneDX SBOM for this install")
    sp.add_argument("-o", "--output")
    sp.set_defaults(func=cmd_sbom)

    sp = sub.add_parser("license", help="license info and (vendor) issuance")
    lsub = sp.add_subparsers(dest="license_cmd", required=True)
    li = lsub.add_parser("info")
    li.add_argument("--token")
    lk = lsub.add_parser("keygen")
    lk.add_argument("--private-out", default="codesentinel_priv.pem")
    lk.add_argument("--public-out", default="codesentinel_pub.pem")
    ls = lsub.add_parser("issue")
    ls.add_argument("--private-key", required=True)
    ls.add_argument("--tenant", required=True)
    ls.add_argument("--edition", required=True,
                    choices=["community", "team", "enterprise", "government"])
    ls.add_argument("--days", type=int, default=365)
    ls.add_argument("--seats", type=int)
    sp.set_defaults(func=cmd_license)

    sp = sub.add_parser("version", help="print version and edition")
    sp.set_defaults(func=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:  # pragma: no cover
        _eprint("interrupted")
        return EXIT_ERROR
    except Exception as e:  # pragma: no cover
        _eprint(f"error: {e}")
        if os.getenv("CODESENTINEL_DEBUG"):
            raise
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
