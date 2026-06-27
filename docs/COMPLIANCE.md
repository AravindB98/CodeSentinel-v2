# CodeSentinel — Compliance & Regulatory Alignment

This document maps CodeSentinel's capabilities to the frameworks most relevant to
security vendors and public-sector buyers. CodeSentinel is a tool that *supports*
your compliance program; it is not itself a certification. Statements below
describe product capabilities and where they contribute evidence. Validate against
your authorizing official, auditor, or counsel.

_Last reviewed: June 2026._

## 1. NIST Secure Software Development Framework (SSDF, SP 800-218)

US Executive Order 14028 requires software sold to the federal government to attest
to SSDF practices. CodeSentinel contributes directly:

| SSDF practice | How CodeSentinel helps |
|---|---|
| PW.7 — Review/analyze human-readable code | Multi-agent + deterministic static review with CWE/OWASP mapping |
| PW.8 — Test executable code | SARIF output integrates into CI gates and code scanning |
| RV.1 — Identify & confirm vulnerabilities | Adversarial Evaluator confirms each finding; provenance enables triage |
| PS.3 — Archive & protect each release | SBOM generation (`codesentinel sbom`, CycloneDX 1.5) |
| PO.3/PO.5 — Toolchain & environments | Reproducible container/Helm deploys; offline/air-gapped operation |

## 2. NIST AI Risk Management Framework (AI RMF 1.0) & ISO/IEC 42001

CodeSentinel uses generative AI, so it is built to the AI-governance bar buyers now
ask about:

- **Map/Measure:** the Evaluator Guardian measures and rejects ungrounded model
  output; the benchmark harness quantifies false-positive/true-positive rates.
- **Manage:** deterministic fallback means the system degrades safely without the
  model; citations make AI output contestable and auditable.
- **Transparency:** every AI finding records its grounding passage and confidence —
  supporting ISO/IEC 42001 AI management-system evidence.

## 3. SOC 2 (Trust Services Criteria)

For the *service* deployment (SaaS or managed on-prem), CodeSentinel provides the
technical controls that underpin SOC 2:

| TSC | Capability |
|---|---|
| CC6.1 Logical access | API-key auth, tenant scoping, default-deny, SSO (Enterprise) |
| CC7.2 Monitoring | Prometheus metrics, structured JSON logs, health/readiness probes |
| CC7.3 Incident evidence | Tamper-evident, hash-chained audit log with offline verification |
| CC8.1 Change management | CI/CD with tests, CodeQL, dependency review, signed releases + SBOM |

## 4. ISO/IEC 27001

Maps to Annex A controls including A.8.25–A.8.28 (secure development, secure
coding), A.8.8 (technical vulnerability management), and A.5.23 (cloud services
security). CodeSentinel is deployable in customer-controlled environments to satisfy
data-residency and sovereignty requirements.

## 5. FedRAMP (incl. 20x)

FedRAMP authorization rests on NIST SP 800-53 Rev 5 controls; the FedRAMP 20x
modernization (Phase 2→3 through 2026) emphasizes **automated, machine-readable
validation** of those controls. CodeSentinel fits both:

- Self-hostable inside an existing FedRAMP-authorized boundary (no third-party data
  egress required; offline mode sends nothing outbound).
- Machine-readable outputs (SARIF, Prometheus, JSON audit) suit automated control
  evidence and Key Security Indicators.
- Hardened container (non-root, read-only FS, dropped capabilities) and least-
  privilege Helm defaults align with 800-53 CM/AC/SC control families.

> CodeSentinel is not itself FedRAMP-authorized; it is deployable **within** a
> customer's authorization boundary as a supporting tool.

## 6. EU Cyber Resilience Act (CRA)

The CRA entered into force on 10 December 2024. Manufacturers of products with
digital elements face **vulnerability- and incident-reporting obligations from 11
September 2026**, with the **full set of obligations applying from 11 December
2027** — including secure-by-design, vulnerability handling, SBOMs, and security
updates across the support period. CodeSentinel supports CRA readiness by:

- Continuous vulnerability identification in your own products (secure-by-design,
  vulnerability handling process evidence).
- SBOM generation for the CRA's bill-of-materials expectation.
- CI-native gating so security defects are caught before release.

## 7. Data handling & privacy

- **Offline mode** processes code entirely in-process; nothing leaves the host.
- **AI mode** sends only the code under review to the configured model provider;
  deploy in offline mode for data that must not transit third parties.
- No telemetry or phone-home. License verification is fully offline (Ed25519).

## References

- EU Cyber Resilience Act — European Commission: https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act
- CRA reporting obligations: https://digital-strategy.ec.europa.eu/en/policies/cra-reporting
- FedRAMP 20x program updates (2026): https://federalnewsnetwork.com/it-modernization/2026/05/risk-compliance-exchange-2026-fedramps-nicole-thompson-on-clearing-up-authorization-confusion/
- NIST SSDF SP 800-218: https://csrc.nist.gov/publications/detail/sp/800-218/final
