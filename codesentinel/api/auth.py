"""API authentication, tenant scoping, and rate limiting.

Keys are configured out-of-band via ``CODESENTINEL_API_KEYS`` as a comma list of
``tenant:secret`` pairs. Each accepted key resolves to a :class:`Principal`
carrying the tenant and the active license edition, so handlers can both scope
data per tenant and gate enterprise features.

If no keys are configured the service refuses authenticated routes unless
``CODESENTINEL_API_OPEN=1`` is set explicitly (local development), which is logged
loudly. Default-deny is the safe posture for a security product.
"""
from __future__ import annotations

import hmac
import logging
import os
import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional

from codesentinel.editions import Edition, current_edition

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Principal:
    tenant: str
    edition: Edition
    key_id: str


def _load_keys() -> Dict[str, str]:
    """Return {secret: tenant} from the environment."""
    raw = os.getenv("CODESENTINEL_API_KEYS", "").strip()
    keys: Dict[str, str] = {}
    for pair in raw.split(","):
        pair = pair.strip()
        if not pair or ":" not in pair:
            continue
        tenant, secret = pair.split(":", 1)
        keys[secret.strip()] = tenant.strip()
    return keys


def _open_mode() -> bool:
    return os.getenv("CODESENTINEL_API_OPEN") == "1"


def authenticate(api_key: Optional[str]) -> Optional[Principal]:
    """Resolve a presented key to a Principal, or None if unauthenticated."""
    keys = _load_keys()
    edition = current_edition()
    if not keys:
        if _open_mode():
            return Principal(tenant="dev", edition=edition, key_id="open")
        return None
    if not api_key:
        return None
    # Constant-time compare against each configured secret.
    for secret, tenant in keys.items():
        if hmac.compare_digest(secret, api_key):
            return Principal(tenant=tenant, edition=edition, key_id=tenant)
    return None


class RateLimiter:
    """Per-tenant token bucket (in-memory). For multi-replica deployments,
    front with a shared limiter (e.g. an ingress or Redis); this protects a
    single instance and is sufficient for on-prem single-node installs."""

    def __init__(self, rate_per_min: int = 120, burst: int = 60) -> None:
        self.rate = rate_per_min / 60.0
        self.burst = burst
        self._buckets: Dict[str, list] = {}
        self._lock = threading.Lock()

    def allow(self, tenant: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(tenant, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < 1:
                self._buckets[tenant] = (tokens, now)
                return False
            self._buckets[tenant] = (tokens - 1, now)
            return True
