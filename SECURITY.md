# Security Policy

## Reporting a vulnerability

We take the security of CodeSentinel seriously. If you discover a vulnerability:

- **Email:** security@codesentinel.example (placeholder — replace before publishing)
- **Encrypted reports:** request our PGP key in your first message.
- **Please do not** open a public issue for security reports.

Include: affected version/commit, a description, reproduction steps or PoC, and
impact. We aim to acknowledge within **3 business days** and to provide a
remediation timeline within **10 business days**.

## Coordinated disclosure

We follow coordinated disclosure. We will work with you on a fix and a disclosure
date, and credit reporters who wish to be named. Please give us a reasonable window
(typically up to 90 days) before public disclosure.

## Supported versions

Security fixes are provided for the latest minor release line. Enterprise/Government
customers receive backported fixes per their support agreement.

| Version | Supported |
|---|---|
| 1.x | ✓ |
| < 1.0 | ✗ |

## Product security posture

- No telemetry or phone-home; license verification is fully offline.
- Container runs as non-root with a read-only root filesystem and dropped Linux
  capabilities; Helm defaults are least-privilege.
- Dependencies are tracked via SBOM (`codesentinel sbom`) and monitored with
  Dependabot; the project self-scans (CodeQL + CodeSentinel) in CI.
- Secrets are never logged; request/response bodies are size-limited; audit logs
  are hash-chained and tamper-evident.

## Hardening checklist for operators

1. Set `CODESENTINEL_API_KEYS` (never run the API in open mode in production).
2. Terminate TLS at your ingress; the app emits HSTS and strict security headers.
3. Mount the audit log on durable, access-controlled storage and ship it to your SIEM.
4. Run offline mode (`CODESENTINEL_MOCK_LLM=1`) for data that must not transit a model provider.
5. Pin the image by digest and verify the release SBOM/provenance.
