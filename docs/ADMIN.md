# CodeSentinel — Administration Reference

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | Enables AI review. Unset → offline mode. |
| `CODESENTINEL_MOCK_LLM` | — | `1` forces deterministic offline mode. |
| `CODESENTINEL_MODEL` | `claude-sonnet-4-5` | Model id for AI mode. |
| `CODESENTINEL_API_KEYS` | — | `tenant:secret` pairs (comma-separated) for the API. |
| `CODESENTINEL_API_OPEN` | — | `1` allows unauthenticated API (dev only). |
| `CODESENTINEL_LICENSE_KEY` | — | Signed license token (`CS1.<...>`). |
| `CODESENTINEL_LICENSE_PUBKEY` | — | PEM (or path) of the license verification key. |
| `CODESENTINEL_HOST` / `CODESENTINEL_PORT` | `0.0.0.0` / `8080` | API bind. |
| `CODESENTINEL_MAX_BODY_BYTES` | `1048576` | Max request body size. |
| `CODESENTINEL_AUDIT_LOG` | `codesentinel-audit.log` | Audit log path. |
| `CODESENTINEL_LOG_FORMAT` | `json` | `json` or `text`. |
| `CODESENTINEL_FAIL_ON` | `HIGH` | Default CI gate severity. |

## `.codesentinel.yml`

```yaml
include: ["**/*"]
exclude: ["**/vendor/**", "**/*.min.js"]
max_file_bytes: 1000000
concurrency: 8
quality: true
min_confidence: 0.5
engine: auto            # auto | deterministic | llm
rescan_on_empty: false
baseline: .codesentinel-baseline.json
disabled_rules: ["CS-PY-WEAKHASH"]   # rule id, CWE, or category
gate:
  severity_threshold: INFO   # minimum severity to report
  fail_on: HIGH              # exit 1 at/above this
  max_findings: null
llm:
  model: claude-sonnet-4-5
  retrieval_k: 6
  max_retries: 3
```

## Baselines (suppressing known findings)

```bash
codesentinel baseline . -o .codesentinel-baseline.json   # snapshot current findings
codesentinel scan . --baseline .codesentinel-baseline.json
```

Baselines store stable fingerprints (rule + file + normalized snippet, line-
independent) so pre-existing findings are suppressed while new ones still fail CI.

## Licensing operations

```bash
# Vendor: generate a signing keypair and issue a license
codesentinel license keygen --private-out priv.pem --public-out pub.pem
codesentinel license issue --private-key priv.pem --tenant acme \
  --edition enterprise --days 365 --seats 50
# Customer: verify what an environment/token resolves to
CODESENTINEL_LICENSE_PUBKEY="$(cat pub.pem)" \
CODESENTINEL_LICENSE_KEY="CS1...." codesentinel license info
```

## Observability

- `/metrics` — Prometheus exposition (scans, findings by severity, durations, auth
  failures). Scrape it with a standard Prometheus job.
- Structured JSON logs to stdout with `request_id`, `tenant`, `path`, `status`,
  `duration_ms` — ship to your SIEM/log pipeline.
- `/healthz` (liveness), `/readyz` (readiness; checks the retriever).

## Audit log

Append-only, hash-chained JSON Lines. Verify integrity any time:

```python
from codesentinel.audit import get_audit_log
print(get_audit_log().verify_chain())   # {'valid': True, 'entries': N}
```

Export via `GET /v1/audit` (Enterprise/Government license required).
