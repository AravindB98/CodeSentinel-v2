# CodeSentinel — REST API Reference

Base URL: `http://<host>:8080` · Interactive docs: `/docs` (OpenAPI/Swagger).

## Authentication

Send the API key as `X-API-Key: <secret>` or `Authorization: Bearer <secret>`.
Keys map to a tenant; results and audit entries are tenant-scoped.

## Endpoints

### Operational (unauthenticated)

| Method | Path | Description |
|---|---|---|
| GET | `/healthz` | Liveness. `{"status":"ok"}` |
| GET | `/readyz` | Readiness (verifies the retriever loads) |
| GET | `/metrics` | Prometheus metrics |
| GET | `/version` | Version and active edition |

### v1 (authenticated)

| Method | Path | Description |
|---|---|---|
| POST | `/v1/scan` | Scan a snippet. Body: `{code, language, filename?, format?}` |
| GET | `/v1/scans` | List the tenant's recent scans |
| GET | `/v1/scans/{id}` | Fetch a stored scan result |
| GET | `/v1/rules` | List detection rules |
| GET | `/v1/audit` | Export tenant audit log (Enterprise/Government) |

## Example

```bash
curl -s http://localhost:8080/v1/scan \
  -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"code":"cur.execute(f\"select {x}\")","language":"python","filename":"db.py"}'
```

Response (abridged):

```json
{
  "tool": "codesentinel", "tool_version": "1.0.0", "edition": "community",
  "summary": {"total_findings": 1, "by_severity": {"CRITICAL": 1, ...}},
  "findings": [{
    "rule_id": "SEC-001", "kind": "security", "severity": "CRITICAL",
    "cwe": "CWE-89", "owasp": "A03:2025 Injection", "confidence": 0.94,
    "message": "CWE-89 (A03:2025 Injection)",
    "location": {"path": "db.py", "start_line": 1, "end_line": 1, "snippet": "..."},
    "fix": "Use parameterized queries ...",
    "citation": {"doc": "patterns.md", "passage_id": "PY-01"},
    "fingerprint": "…"
  }],
  "scan_id": "…"
}
```

Set `"format": "sarif"` to receive a SARIF 2.1.0 document instead.

## Status codes

`200` ok · `401` missing/invalid key · `402` feature needs a higher edition ·
`404` scan not found (or other tenant) · `413` body too large · `429` rate limited.
