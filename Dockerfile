# syntax=docker/dockerfile:1
# ─────────────────────────────────────────────────────────────────────────────
# CodeSentinel — multi-stage, non-root, slim production image.
# Bundles the deterministic rule engine + RAG index so the container scans
# fully offline (air-gapped). Provide ANTHROPIC_API_KEY at runtime to enable
# the multi-agent AI review path.
# ─────────────────────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder
WORKDIR /build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY pyproject.toml README.md ./
COPY codesentinel ./codesentinel
# Install with API + LLM extras into an isolated prefix we copy to the runtime stage.
RUN pip install --prefix=/install ".[api,llm]"
# Pre-build the RAG knowledge base so first scan is instant and works offline.
RUN PYTHONPATH=/install/lib/python3.12/site-packages python -m codesentinel.rag.ingest || true

FROM python:3.12-slim AS runtime
LABEL org.opencontainers.image.title="CodeSentinel" \
      org.opencontainers.image.description="Multi-agent, RAG-grounded code security review" \
      org.opencontainers.image.source="https://github.com/AravindB98/CodeSentinel" \
      org.opencontainers.image.licenses="Apache-2.0"
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    CODESENTINEL_HOST=0.0.0.0 CODESENTINEL_PORT=8080 \
    CODESENTINEL_LOG_FORMAT=json
# Non-root runtime user.
RUN groupadd -r app && useradd -r -g app -d /app -s /usr/sbin/nologin app
WORKDIR /app
COPY --from=builder /install /usr/local
COPY --from=builder /build/codesentinel /app/codesentinel
USER app
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)" || exit 1
ENTRYPOINT ["python", "-m", "codesentinel.cli"]
CMD ["serve"]
