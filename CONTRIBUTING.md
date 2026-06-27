# Contributing to CodeSentinel

Thanks for your interest! Contributions to the open core are welcome under
Apache-2.0.

## Ground rules

- **DCO sign-off required.** Commit with `git commit -s` to certify the
  [Developer Certificate of Origin](https://developercertificate.org/).
- Inbound = outbound: contributions are licensed under Apache-2.0 (see `LICENSING.md`).
- Be excellent to each other. A `CODE_OF_CONDUCT` (Contributor Covenant) applies.

## Development setup

```bash
git clone https://github.com/AravindB98/CodeSentinel.git
cd CodeSentinel
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
python -m codesentinel.rag.ingest      # build the RAG index
pre-commit install
make test                              # CODESENTINEL_MOCK_LLM=1 pytest
```

## Before you open a PR

```bash
make lint        # ruff
make typecheck   # mypy (advisory)
make test        # full suite, must stay green (with and without optional deps)
```

- Tests run deterministically in mock mode (no API key needed).
- If you change detection behavior, **re-run `make benchmark`** and note any TPR/FPR
  movement in the PR description.
- New rules go in `codesentinel/rules.py` and must cite a corpus passage in
  `codesentinel/rag/data/patterns.md` (add the passage if needed, then re-ingest).

## Adding a detection rule

1. Add a `Rule(...)` to `RULES` in `codesentinel/rules.py`.
2. Add or reference a passage in `patterns.md` and run `codesentinel ingest`.
3. Add a test in `tests/` covering a true positive and a clean negative.
4. `codesentinel rules` should list your rule; SARIF output should carry its CWE.

## Reporting security issues

Do **not** open a public issue. See `SECURITY.md`.
