# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/), and this project adheres to
Semantic Versioning.

## [1.0.0] — 2026-06-27

The research prototype becomes a deployable, sellable product. Open-core.

### Added
- **Installable package** (`pip install codesentinel`) with `codesentinel`/`cs`
  console entry points and an offline-capable lean core plus extras
  (`llm`, `rag`, `graph`, `api`, `ui`, `dev`).
- **Scanning engine** for files and repositories: discovery with include/exclude
  globs, language detection, size caps, bounded concurrency, dedupe, baseline
  suppression, severity/confidence policy, and a CI gate.
- **Deterministic rule engine** — 32 rules across Python, JavaScript, TypeScript,
  Java, Go, Ruby, and PHP — for fully offline/air-gapped scanning with provenance.
- **Reporters:** SARIF 2.1.0 (GitHub/GitLab/Azure code scanning), JSON, Markdown,
  and standalone HTML.
- **CLI:** `scan`, `serve`, `ingest`, `rules`, `baseline`, `sbom`, `license`,
  `version`, with CI-friendly exit codes.
- **REST API** (FastAPI): `/v1/scan`, `/v1/scans`, `/v1/rules`, `/v1/audit`, plus
  `/healthz`, `/readyz`, `/metrics`, `/version`. API-key auth, tenant isolation,
  rate limiting, security headers, and body-size limits.
- **Enterprise foundations:** Ed25519 **offline** license verification and edition
  gating; tamper-evident **hash-chained audit log**; Prometheus metrics; structured
  JSON logging; CycloneDX 1.5 **SBOM** generation.
- **Deployment:** non-root multi-stage Dockerfile, docker-compose, hardened Helm
  chart, composite GitHub Action, and CI/CD (tests matrix, CodeQL, self-scan,
  signed releases with SBOM/provenance).
- **Documentation:** pricing/editions, solution brief, compliance mapping (NIST
  SSDF/AI RMF, SOC 2, ISO 27001/42001, FedRAMP, EU CRA), threat model, security
  policy, deployment/admin/API guides.

### Changed
- Repository restructured under a single `codesentinel.*` namespace (was top-level
  `graph`/`rag`/`rl`/`synth`/`utils`).
- Relicensed the open core from MIT to **Apache-2.0** (adds an explicit patent
  grant); added a commercial license for Enterprise/Government features.

### Fixed
- **Schema validation under pydantic.** Contract checks (fix length, confidence
  bounds, ID formats) previously ran only in the dataclass fallback and were
  silently bypassed when pydantic — the real dependency — was installed. Validation
  now fires in both modes; the full suite passes **with pydantic installed**
  (previously 3 tests failed).
- Evaluator no longer forces up to two sentinel retries on clean files (≈3× cost
  reduction on no-finding inputs, with no change to benchmark TPR/FPR).
