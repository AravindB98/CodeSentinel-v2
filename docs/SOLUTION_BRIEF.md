# CodeSentinel — Solution Brief

**RAG-grounded, adversarially-validated AI code security review.**
Find real vulnerabilities, not false alarms — with provenance auditors can trust.

## The problem

LLM code reviewers are fast and capable, but naive single-prompt deployments fail
in three structural ways: findings are **ungrounded** (the model invents plausible
bugs), output is **monolithic** (no adversary challenges a claim, so false
positives flow through), and errors are **untraceable** (no record of what the
model knew). A tool that flags thirty false positives per ten files is abandoned
by developers within a week — and is unacceptable to a regulator.

## The approach

CodeSentinel closes all three failure modes **architecturally**, not with a better
prompt:

1. **Specialize.** Three narrow agents — Security Sentinel, Quality Auditor,
   Evaluator Guardian — instead of one model doing everything.
2. **Ground.** Every security claim must cite a passage from a curated knowledge
   base (OWASP Top 10 2025, CWE, language patterns). Uncited findings are rejected
   programmatically before a human sees them.
3. **Adversarially validate.** A dedicated Evaluator runs a two-layer check
   (programmatic + semantic) on every finding and reroutes rejects upstream, with a
   bounded retry circuit-breaker.

## The result

Against a hand-labeled suite with a real Claude Sonnet model, the single-prompt
baseline produced **30 false positives**; the multi-agent pipeline produced **1** —
a **97% reduction in hallucinated findings, attributable purely to the
architecture** (same model, same prompts, same samples). Paired-suite significance:
McNemar's exact p = 0.0312.

## Why security firms and governments buy it

- **Provenance for every finding.** "Line 47 is CWE-502" links to the exact OWASP/CWE
  passage that defines it — one click to verify. Essential for regulated audits.
- **Runs air-gapped.** A deterministic 32-rule engine across Python, JavaScript,
  TypeScript, Java, Go, Ruby, and PHP works with **zero outbound network and no API
  key** — then the multi-agent AI layer adds depth when a model is available.
- **Drops into the toolchain.** SARIF 2.1.0 uploads straight to GitHub/GitLab/Azure
  code scanning; a one-line GitHub Action gates pull requests; CLI exit codes gate
  any CI.
- **Deploys where you operate.** Single non-root container, hardened Helm chart for
  Kubernetes, on-prem or SaaS. SSO, multi-tenant isolation, tamper-evident audit.
- **Compliance-ready.** Maps to NIST SSDF, NIST AI RMF, SOC 2, ISO 27001/42001, and
  supports EU CRA / FedRAMP evidence needs. Ships an SBOM.

## Proof points

- 35/35 unit tests pass (with and without optional dependencies).
- Deterministic, reproducible benchmark harness included (`make benchmark`).
- Every finding carries a CWE, an OWASP 2025 mapping, a fix, and a citation.

## Get started

```bash
pip install "codesentinel[llm]"
codesentinel scan ./your-repo --fail-on HIGH -f sarif -o results.sarif
```

Evaluation licenses, pilots, and procurement: **sales@codesentinel.example** (placeholder).
