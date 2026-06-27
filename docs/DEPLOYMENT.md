# CodeSentinel — Deployment Guide

CodeSentinel runs the same artifact four ways: as a CLI in CI, a single container,
a Kubernetes service, or fully air-gapped. Pick the row that matches your buyer.

## 0. Operating modes

| Mode | When | Network | How |
|---|---|---|---|
| **Offline / deterministic** | Air-gapped, classified, no API budget | None | `CODESENTINEL_MOCK_LLM=1` |
| **AI / multi-agent** | Maximum depth | TLS to model provider | set `ANTHROPIC_API_KEY` |

Offline mode uses the 32-rule deterministic engine across 6 languages and sends
**nothing** outbound. AI mode adds the multi-agent RAG pipeline.

## 1. CLI in CI (simplest)

```bash
pip install "codesentinel[llm]"
codesentinel scan . --fail-on HIGH -f sarif -o results.sarif
# exit code 1 if any finding >= HIGH, 0 otherwise
```

GitHub Actions: use the bundled Action (`examples/github-code-scanning.yml`) to gate
PRs and upload SARIF to code scanning. For GitLab/Azure, publish the SARIF artifact
to their respective code-scanning ingests.

## 2. Single container (on-prem)

```bash
docker compose up --build        # reads .env
# or
docker build -t codesentinel:1.0.0 .
docker run --rm -p 8080:8080 \
  -e CODESENTINEL_API_KEYS="acme:$(openssl rand -hex 24)" \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  codesentinel:1.0.0
curl localhost:8080/healthz
```

The image is non-root, has a read-only-friendly layout, bundles the RAG index, and
exposes `/healthz`, `/readyz`, `/metrics`.

## 3. Kubernetes (Helm)

```bash
helm upgrade --install codesentinel deploy/helm/codesentinel \
  --set image.repository=ghcr.io/aravindb98/codesentinel \
  --set secrets.apiKeys="acme:$(openssl rand -hex 24)" \
  --set ingress.enabled=true \
  --set ingress.hosts[0].host=codesentinel.internal
```

The chart ships HPA, ingress, a hardened security context (non-root, read-only root
FS, dropped capabilities, seccomp RuntimeDefault), liveness/readiness probes, and a
Secret template. For production secrets, prefer an external secret store (External
Secrets Operator / Vault) over chart values.

## 4. Air-gapped install

1. On a connected host, build the image and `docker save` it, or `pip download`
   `codesentinel[api,llm]` into a wheelhouse.
2. Transfer the artifact across your boundary.
3. Load (`docker load`) or install from the wheelhouse (`pip install --no-index
   --find-links ./wheelhouse codesentinel[api]`).
4. Run with `CODESENTINEL_MOCK_LLM=1`. The RAG index is prebuilt in the image; for
   wheel installs run `codesentinel ingest` once.
5. Apply a Government-edition license (offline Ed25519 key) to enable air-gapped
   support and compliance packs.

## 5. SaaS / multi-tenant

Run multiple replicas behind your ingress; configure one `tenant:secret` API key per
customer; front with a shared rate limiter; ship the per-tenant audit log to your
SIEM. Multi-tenant isolation and SSO are Enterprise features.

## Configuration precedence

`CLI flags > environment variables > .codesentinel.yml > built-in defaults`

See `docs/ADMIN.md` for the full environment and `.codesentinel.yml` reference.
