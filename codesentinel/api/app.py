"""FastAPI application factory for the CodeSentinel service.

Exposes a versioned ``/v1`` API for scanning, results retrieval, rule listing and
(enterprise-gated) audit export, plus unauthenticated operational endpoints
(``/healthz``, ``/readyz``, ``/metrics``, ``/version``). Cross-cutting concerns —
request IDs, structured access logs, security headers, body-size limits, API-key
auth, per-tenant rate limiting, audit logging and Prometheus metrics — are wired
in here.
"""

import logging
import time
from collections import OrderedDict
from typing import Dict, Optional

from codesentinel import __version__
from codesentinel.audit import get_audit_log
from codesentinel.editions import Feature, current_edition, has_feature
from codesentinel.observability import configure_logging, metrics, new_request_id

logger = logging.getLogger("codesentinel.api")

MAX_BODY_BYTES_DEFAULT = 1_048_576
_MAX_STORE_PER_TENANT = 200


def create_app(config=None):
    from fastapi import Depends, FastAPI, Header, HTTPException, Request
    from fastapi.responses import JSONResponse, PlainTextResponse
    from pydantic import BaseModel, Field

    from codesentinel.api.auth import Principal, RateLimiter, authenticate
    from codesentinel.config import load_config

    configure_logging()
    cfg = config or load_config()
    limiter = RateLimiter()
    audit = get_audit_log()
    # tenant -> OrderedDict[scan_id, result_dict]
    store: Dict[str, "OrderedDict[str, dict]"] = {}

    app = FastAPI(
        title="CodeSentinel API",
        version=__version__,
        description="Multi-agent, RAG-grounded code security review with provenance.",
    )

    # ---- Request models ----
    class ScanRequest(BaseModel):
        code: str = Field(..., description="Source code to review")
        language: str = Field("python", description="python|javascript|typescript|java|go|ruby|php")
        filename: str = Field("snippet", description="Logical path for the snippet")
        format: str = Field("json", description="json|sarif")

    # ---- Middleware ----
    import os
    max_body = int(os.getenv("CODESENTINEL_MAX_BODY_BYTES", MAX_BODY_BYTES_DEFAULT))

    @app.middleware("http")
    async def _observability(request: Request, call_next):
        rid = request.headers.get("x-request-id") or new_request_id()
        start = time.time()
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > max_body:
            return JSONResponse(status_code=413, content={"error": "request body too large"})
        try:
            response = await call_next(request)
        except Exception:  # pragma: no cover
            logger.exception("unhandled error", extra={"request_id": rid, "path": request.url.path})
            return JSONResponse(status_code=500, content={"error": "internal error", "request_id": rid})
        dur_ms = int((time.time() - start) * 1000)
        response.headers["X-Request-ID"] = rid
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'"
        response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        logger.info("request", extra={"request_id": rid, "path": request.url.path,
                                      "status": response.status_code, "duration_ms": dur_ms})
        return response

    # ---- Auth dependency ----
    def get_principal(
        authorization: Optional[str] = Header(None),
        x_api_key: Optional[str] = Header(None),
    ) -> Principal:
        key = x_api_key
        if not key and authorization and authorization.lower().startswith("bearer "):
            key = authorization[7:].strip()
        principal = authenticate(key)
        if principal is None:
            metrics.inc("codesentinel_auth_failures_total")
            raise HTTPException(status_code=401, detail="invalid or missing API key")
        if not limiter.allow(principal.tenant):
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        return principal

    # ---- Operational (unauthenticated) ----
    @app.get("/healthz")
    def healthz():
        return {"status": "ok", "version": __version__}

    @app.get("/readyz")
    def readyz():
        try:
            from codesentinel.rag.retriever import get_retriever
            get_retriever().retrieve("readiness probe", k=1)
            return {"status": "ready"}
        except Exception as e:  # pragma: no cover
            raise HTTPException(status_code=503, detail=f"not ready: {e}")

    @app.get("/metrics")
    def prometheus_metrics():
        return PlainTextResponse(metrics.render(), media_type="text/plain; version=0.0.4")

    @app.get("/version")
    def version():
        return {"name": "codesentinel", "version": __version__,
                "edition": current_edition(cfg).value}

    # ---- v1 (authenticated) ----
    @app.post("/v1/scan")
    def scan(req: ScanRequest, principal: Principal = Depends(get_principal)):
        from codesentinel.engine import Engine
        t0 = time.time()
        result = Engine(cfg).scan_code(req.code, req.language, req.filename)
        dur = time.time() - t0
        metrics.inc("codesentinel_scans_total", {"tenant": principal.tenant, "status": "ok"})
        metrics.observe("codesentinel_scan_duration_seconds", dur, {"tenant": principal.tenant})
        for sev, n in result.severity_counts().items():
            if n:
                metrics.inc("codesentinel_findings_total", {"severity": sev}, n)
        audit.record(principal.tenant, "scan", filename=req.filename,
                     language=req.language, findings=len(result.findings),
                     edition=result.edition)

        scan_id = new_request_id()[:12]
        payload = result.to_dict()
        payload["scan_id"] = scan_id
        tstore = store.setdefault(principal.tenant, OrderedDict())
        tstore[scan_id] = payload
        while len(tstore) > _MAX_STORE_PER_TENANT:
            tstore.popitem(last=False)

        if req.format == "sarif":
            from codesentinel.reporters.sarif import to_sarif
            sarif = to_sarif(result)
            sarif["runs"][0]["properties"]["scan_id"] = scan_id
            return JSONResponse(content=sarif)
        return payload

    @app.get("/v1/scans")
    def list_scans(principal: Principal = Depends(get_principal)):
        tstore = store.get(principal.tenant, {})
        return {"scans": [{"scan_id": k, "summary": v["summary"]} for k, v in tstore.items()]}

    @app.get("/v1/scans/{scan_id}")
    def get_scan(scan_id: str, principal: Principal = Depends(get_principal)):
        tstore = store.get(principal.tenant, {})
        if scan_id not in tstore:
            raise HTTPException(status_code=404, detail="scan not found")
        return tstore[scan_id]

    @app.get("/v1/rules")
    def list_rules(principal: Principal = Depends(get_principal)):
        from codesentinel.rules import iter_rules
        return {"rules": [r.to_dict() for r in iter_rules()]}

    @app.get("/v1/audit")
    def audit_export(limit: int = 1000, principal: Principal = Depends(get_principal)):
        # Enterprise/Government feature.
        if not has_feature(Feature.AUDIT_EXPORT, cfg):
            raise HTTPException(status_code=402,
                                detail="audit export requires an Enterprise or Government license")
        return {"chain": audit.verify_chain(),
                "entries": audit.read(limit=limit, tenant=principal.tenant)}

    return app
