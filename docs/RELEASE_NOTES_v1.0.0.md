# CodeSentinel v1.0.0 — "Research to Product"

CodeSentinel graduates from an academic prototype to a deployable, open-core
security product that cybersecurity firms and public-sector teams can run in
production — on-prem, in Kubernetes, or fully air-gapped.

## Highlights

- **Scan real repos, not just snippets.** New `codesentinel` CLI walks files and
  repositories with include/exclude rules, language detection, concurrency,
  baselines, and CI-friendly exit codes.
- **Two engines, one tool.** A deterministic 32-rule engine across Python,
  JavaScript, TypeScript, Java, Go, Ruby, and PHP runs **fully offline** (no API
  key, nothing leaves your network), while the multi-agent RAG pipeline adds AI
  depth when a model is available.
- **Drops into your toolchain.** SARIF 2.1.0 (GitHub/GitLab/Azure code scanning),
  JSON/Markdown/HTML reports, a one-line GitHub Action, Docker image, and a
  hardened Helm chart.
- **Built for the enterprise/government buyer.** REST API with API-key auth,
  tenant isolation, rate limiting, Prometheus metrics, structured logs, and a
  tamper-evident hash-chained audit log.
- **Open-core & sellable.** Core under Apache-2.0; Enterprise/Government features
  gated by **offline Ed25519 license keys** (no phone-home). Pricing, solution
  brief, and compliance mapping (NIST SSDF/AI RMF, SOC 2, ISO, FedRAMP, EU CRA)
  included.

## Quality

- **67 tests** pass with and without optional dependencies (was 35).
- Fixed a latent bug where schema validation was silently bypassed under pydantic.
- Reproducible benchmark unchanged: multi-agent **TPR 1.0 / FPR 0.0** (mock);
  prior real-model result stands at **97% fewer false positives** vs. a single
  prompt.

## Install

```bash
pip install "codesentinel[llm]"
codesentinel scan ./your-repo --fail-on HIGH -f sarif -o results.sarif
```

See the [CHANGELOG](../CHANGELOG.md) for the full list and [README](../README.md)
to get started.

> Note: replace placeholder contacts (sales@/security@codesentinel.example) and
> have counsel review `LICENSE-COMMERCIAL.md` before commercial use.
