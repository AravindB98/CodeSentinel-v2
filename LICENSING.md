# CodeSentinel Licensing (Open Core)

CodeSentinel uses an **open-core** model. The scanning engine is free and open
source; a set of clearly delineated Enterprise/Government capabilities require a
commercial license.

## Open Core — Apache License 2.0

Everything in this repository is licensed under **Apache-2.0** (see `LICENSE`)
**except** the components listed under *Commercial Features* below. The open core
is fully functional on its own and includes:

- The multi-agent review pipeline (Security Sentinel, Quality Auditor, Evaluator
  Guardian) and the RAG retrieval stack.
- The deterministic rule engine (`codesentinel/rules.py`) across all supported
  languages.
- The CLI (`codesentinel scan`), all reporters (text/JSON/**SARIF 2.1.0**/Markdown/HTML),
  the configuration system, and the baseline workflow.
- The REST API core (`/v1/scan`, `/v1/scans`, `/v1/rules`, `/healthz`, `/readyz`,
  `/metrics`, `/version`), API-key auth, and Prometheus metrics.
- Docker image, Helm chart, and the GitHub Action.

You may use, modify, self-host, and redistribute the open core under Apache-2.0,
including in commercial settings.

## Commercial Features (require a paid license)

The following are licensed under `LICENSE-COMMERCIAL.md` and gated by a signed
license key (`codesentinel/editions.py`). Using them in production without a
valid license is not permitted:

| Feature | Edition |
|---|---|
| Tamper-evident **audit log export** (`/v1/audit`) | Enterprise, Government |
| **Multi-tenant** isolation & quotas at scale | Enterprise, Government |
| **SSO** (SAML/OIDC) and SCIM provisioning | Enterprise, Government |
| **Compliance report packs** (NIST/FedRAMP/CRA-mapped) | Enterprise, Government |
| Private/custom **rule packs** and tuning | Team, Enterprise, Government |
| Supported **air-gapped** operation & hardened images | Government |
| Priority support & SLAs | Enterprise, Government |

The license key is verified **offline** with an Ed25519 signature (no phone-home),
which is required for air-gapped and classified environments. Absent or invalid
licenses degrade gracefully to the Community edition — scanning always works.

## Contributions

Contributions to the open core are accepted under the Apache-2.0 license and the
inbound=outbound principle. By submitting a contribution you agree it may be
distributed under Apache-2.0. A lightweight Developer Certificate of Origin (DCO)
sign-off (`git commit -s`) is required; see `CONTRIBUTING.md`.

## Trademarks

"CodeSentinel" and associated logos are trademarks of the project author. The
Apache-2.0 license does not grant trademark rights; see `LICENSE` §6.

## Questions

Commercial licensing, evaluation licenses, and procurement: **sales@codesentinel.example**
(placeholder — replace with your sales contact before publishing).
