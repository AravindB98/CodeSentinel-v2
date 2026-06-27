# CodeSentinel Editions & Pricing

> Indicative list pricing to anchor packaging and procurement conversations.
> Final pricing, discounts, and government schedule rates are set by the seller;
> replace the figures below before publishing. All paid tiers are available as an
> annual subscription; Government is available via direct contract.

CodeSentinel is **open-core**. The engine is free; paid editions add the controls
that security teams, enterprises, and public-sector buyers require to deploy at
scale and under compliance obligations.

## Editions at a glance

| | **Community** | **Team** | **Enterprise** | **Government** |
|---|---|---|---|---|
| Price | Free (Apache-2.0) | **$29 / contributor / mo** | **Custom** (from ~$40k/yr) | **Custom** (contract) |
| Multi-agent AI review (with API key) | ✓ | ✓ | ✓ | ✓ |
| Deterministic offline engine (6 languages) | ✓ | ✓ | ✓ | ✓ |
| SARIF / JSON / HTML / Markdown reports | ✓ | ✓ | ✓ | ✓ |
| CLI, REST API, GitHub Action, Docker, Helm | ✓ | ✓ | ✓ | ✓ |
| Prometheus metrics & structured logs | ✓ | ✓ | ✓ | ✓ |
| Private / custom rule packs | — | ✓ | ✓ | ✓ |
| Multi-tenant isolation & quotas | — | — | ✓ | ✓ |
| SSO (SAML/OIDC), SCIM | — | — | ✓ | ✓ |
| Tamper-evident audit log export | — | — | ✓ | ✓ |
| Compliance report packs (NIST/FedRAMP/CRA) | — | — | ✓ | ✓ |
| Supported air-gapped deployment | — | — | Add-on | ✓ |
| Support | Community | Business hours | 24×5, SLA | 24×7, dedicated |
| Procurement | — | Self-serve / card | MSA | Direct / reseller / schedule |

## How we price vs. the market

Public per-developer SAST list prices for reference (2026): Semgrep Team
**$35/contributor/mo**, Snyk Code **$25/developer/mo**, SonarQube priced per line
of code, and Checkmarx/Enterprise platforms custom-quoted and materially higher.
CodeSentinel Team is positioned to undercut the comparable Semgrep/Snyk tier while
adding the capability none of them have: **every finding is RAG-grounded and
adversarially validated, cutting the false-positive triage tax that makes teams
abandon SAST tools.**

## Why each tier exists (value, not just features)

- **Community** is the adoption funnel and the air-gapped baseline. A government
  lab can run the deterministic engine with zero outbound network and zero cost.
- **Team** monetizes the moment a squad wants private rules and a supported cadence.
- **Enterprise** monetizes the controls a CISO needs to roll the tool out across
  business units: tenant isolation, SSO, audit, and compliance evidence.
- **Government** monetizes the assurance public-sector buyers must have: supported
  air-gapped operation, FedRAMP-aligned controls, and contract vehicles.

## Packaging notes

- **Seat definition:** a *contributor* is a unique author who pushes code scanned
  in a billing month (the industry-standard active-committer model).
- **Usage option:** Enterprise can alternatively meter by **scans or LOC** for CI-
  heavy or monorepo customers — see your Order Form.
- **Evaluation:** 30-day Enterprise evaluation licenses are issued as time-boxed
  signed keys (`codesentinel license issue --days 30`).

Contact: **sales@codesentinel.example** (placeholder).
