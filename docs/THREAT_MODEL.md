# CodeSentinel — Threat Model

Scope: the CodeSentinel scanning engine, CLI, and REST service as deployed by a
customer (on-prem, air-gapped, or SaaS). Methodology: STRIDE over the data-flow
below. This is a living document; revise per release and per deployment.

## Assets

- Customer **source code** submitted for review (most sensitive; may be classified).
- **Findings** and their provenance (security-relevant; reveal weaknesses).
- **Audit log** (integrity-critical; compliance evidence).
- **API keys / license keys / model API keys** (secrets).

## Trust boundaries

```
   developer / CI ──TLS──> [ ingress ] ──> [ CodeSentinel API ] ──> [ engine ]
                                              │                         │
                                       audit log (disk)        RAG index (local)
                                              │                         │
                                     (AI mode only) ──TLS──> model provider API
```

The boundary that matters most: in **offline mode** the code never crosses the
process boundary to any network. In **AI mode** the code under review is sent to the
configured model provider over TLS — a deliberate, documented trust decision.

## STRIDE analysis

| Threat | Vector | Mitigation |
|---|---|---|
| **S**poofing | Forged API caller | API-key auth, constant-time compare, default-deny; SSO (Enterprise) |
| **S**poofing | Forged license to unlock paid features | Ed25519 signature verified offline; tamper → Community |
| **T**ampering | Edited audit log to hide activity | Hash-chained entries; `verify_chain` detects any edit/insert/delete |
| **T**ampering | Malicious config/baseline file | Config is data-only (no code eval); baselines are fingerprint lists |
| **R**epudiation | "I never ran that scan" | Per-tenant audit entries with timestamps and request IDs |
| **I**nfo disclosure | Code leaks to a third-party model | Offline mode keeps code in-process; AI mode documented & opt-in |
| **I**nfo disclosure | Secrets in logs | Secrets never logged; structured logs allow-list fields |
| **I**nfo disclosure | Cross-tenant data access | Results stored per-tenant; access scoped to the authenticated tenant |
| **D**enial of service | Oversized payloads / scan floods | Body-size limit, per-tenant rate limiting, file-size/count caps, concurrency bound, retry circuit-breaker |
| **D**enial of service | Pathological regex/code | Bounded rule set; per-line matching; size caps |
| **E**levation of privilege | Container escape | Non-root, read-only FS, dropped capabilities, seccomp; no SUID |
| **E**levation of privilege | Feature gate bypass | Server-side `require_feature` checks, not client-trusted |

## Residual risks & assumptions

- **AI-mode confidentiality** depends on the chosen model provider's terms; use
  offline mode for data that must not transit a third party.
- **Single-node rate limiting** is in-process; multi-replica deployments should add
  a shared limiter at the ingress.
- **The operator** is responsible for TLS termination, secret storage, network
  policy, and shipping the audit log to durable, access-controlled storage.
- CodeSentinel reduces, but does not eliminate, the risk of missed vulnerabilities
  (false negatives); it complements — does not replace — secure-by-design practices
  and human review.

## Abuse cases explicitly designed against

- A developer cannot silence a finding by editing the audit trail (chain breaks).
- A customer cannot unlock Enterprise features by editing config or forging a key.
- An unauthenticated caller cannot scan, list, or read another tenant's results.
