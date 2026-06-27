"""Open-core edition gating and offline license verification.

CodeSentinel is open-core: the scanning engine, CLI, SARIF output and REST API
are free (Community). Enterprise/Government capabilities — SSO, tamper-evident
audit export, multi-tenant isolation, compliance packs, air-gapped support — are
unlocked by a signed license.

Licenses are **Ed25519-signed tokens verified entirely offline** (no phone-home),
which is a hard requirement for air-gapped and classified deployments. The vendor
holds the private key; the product ships/loads only the public key. A license
that is missing, malformed, expired, or signed by the wrong key silently falls
back to the Community edition rather than failing closed — scanning always works.

Token format::

    CS1.<base64url(payload_json)>.<base64url(ed25519_signature)>
"""
from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    _CRYPTO = True
except Exception:  # pragma: no cover
    _CRYPTO = False

TOKEN_PREFIX = "CS1"


class Edition(str, Enum):
    COMMUNITY = "community"
    TEAM = "team"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"


class Feature(str, Enum):
    SCAN = "scan"                      # core scanning (all editions)
    SARIF = "sarif"                    # SARIF/JSON/HTML reporting (all editions)
    API = "api"                        # REST API service
    MULTI_TENANT = "multi_tenant"      # tenant isolation on the API
    SSO = "sso"                        # SAML/OIDC single sign-on
    AUDIT_EXPORT = "audit_export"      # signed/hash-chained audit log export
    CUSTOM_RULES = "custom_rules"      # private rule packs
    COMPLIANCE_PACKS = "compliance_packs"  # NIST/FedRAMP/CRA mapped reports
    AIRGAP = "airgap"                  # supported air-gapped operation
    PRIORITY_SUPPORT = "priority_support"


# Feature entitlements per edition. Higher editions are supersets.
_BASE: set[Feature] = {Feature.SCAN, Feature.SARIF, Feature.API}
EDITION_FEATURES = {
    Edition.COMMUNITY: set(_BASE),
    Edition.TEAM: _BASE | {Feature.CUSTOM_RULES},
    Edition.ENTERPRISE: _BASE | {
        Feature.CUSTOM_RULES, Feature.MULTI_TENANT, Feature.SSO,
        Feature.AUDIT_EXPORT, Feature.COMPLIANCE_PACKS, Feature.PRIORITY_SUPPORT,
    },
    Edition.GOVERNMENT: _BASE | {
        Feature.CUSTOM_RULES, Feature.MULTI_TENANT, Feature.SSO,
        Feature.AUDIT_EXPORT, Feature.COMPLIANCE_PACKS, Feature.PRIORITY_SUPPORT,
        Feature.AIRGAP,
    },
}


class LicenseError(RuntimeError):
    """Raised when an entitlement check fails for a gated feature."""


@dataclass(frozen=True)
class LicenseInfo:
    tenant: str
    edition: Edition
    issued: int
    expires: int            # unix seconds; 0 == perpetual
    seats: int | None = None
    verified: bool = False  # True only when the Ed25519 signature checked out

    @property
    def expired(self) -> bool:
        return self.expires != 0 and time.time() > self.expires

    @property
    def features(self) -> set[Feature]:
        if not self.verified or self.expired:
            return set(EDITION_FEATURES[Edition.COMMUNITY])
        return set(EDITION_FEATURES.get(self.edition, EDITION_FEATURES[Edition.COMMUNITY]))


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _load_public_key(pubkey_pem: str | None):
    """Resolve the verification key from an argument, env var, or file path."""
    if not _CRYPTO:
        return None
    pem = pubkey_pem or os.getenv("CODESENTINEL_LICENSE_PUBKEY")
    if pem and pem.strip().startswith("-----BEGIN"):
        return serialization.load_pem_public_key(pem.encode())
    # Treat as a path
    path = pem or os.getenv("CODESENTINEL_LICENSE_PUBKEY_FILE")
    if path and Path(path).is_file():
        return serialization.load_pem_public_key(Path(path).read_bytes())
    return None


def verify_license(token: str, pubkey_pem: str | None = None) -> LicenseInfo | None:
    """Parse and cryptographically verify a license token.

    Returns ``LicenseInfo`` with ``verified=True`` only if the Ed25519 signature
    is valid for the configured public key. Returns ``None`` for an absent or
    structurally invalid token. A structurally valid but unverifiable token (no
    public key configured, or bad signature) returns ``LicenseInfo`` with
    ``verified=False`` (Community entitlements).
    """
    if not token:
        return None
    try:
        prefix, payload_b64, sig_b64 = token.strip().split(".")
        if prefix != TOKEN_PREFIX:
            return None
        payload_raw = _b64url_decode(payload_b64)
        payload = json.loads(payload_raw)
        info_kwargs = dict(
            tenant=str(payload["tenant"]),
            edition=Edition(payload["edition"]),
            issued=int(payload.get("issued", 0)),
            expires=int(payload.get("expires", 0)),
            seats=payload.get("seats"),
        )
    except Exception as e:
        logger.warning("Malformed license token: %s", e)
        return None

    verified = False
    pub = _load_public_key(pubkey_pem)
    if pub is not None:
        try:
            pub.verify(_b64url_decode(sig_b64), payload_raw)
            verified = True
        except InvalidSignature:
            logger.warning("License signature verification FAILED for tenant=%s", info_kwargs["tenant"])
        except Exception as e:  # pragma: no cover
            logger.warning("License verification error: %s", e)
    else:
        logger.info("No license public key configured; treating license as unverified (Community).")

    return LicenseInfo(verified=verified, **info_kwargs)


def current_edition(config=None, token: str | None = None) -> Edition:
    """Resolve the active edition from config/env. Defaults to Community."""
    tok = token
    if tok is None and config is not None:
        tok = getattr(config, "license_key", None)
    if tok is None:
        tok = os.getenv("CODESENTINEL_LICENSE_KEY")
    info = verify_license(tok) if tok else None
    if info and info.verified and not info.expired:
        return info.edition
    return Edition.COMMUNITY


def has_feature(feature: Feature, config=None, token: str | None = None) -> bool:
    return feature in EDITION_FEATURES[current_edition(config, token)]


def require_feature(feature: Feature, config=None, token: str | None = None) -> None:
    """Raise :class:`LicenseError` if the active edition lacks ``feature``."""
    ed = current_edition(config, token)
    if feature not in EDITION_FEATURES[ed]:
        raise LicenseError(
            f"Feature '{feature.value}' requires a higher edition than '{ed.value}'. "
            f"Contact sales@codesentinel.example to upgrade."
        )


# ---------------------------------------------------------------------------
# Vendor-side helpers (used to mint licenses; not needed by customers).
# ---------------------------------------------------------------------------
def generate_keypair() -> tuple[str, str]:  # pragma: no cover - tooling
    """Return (private_pem, public_pem) for a fresh Ed25519 signing key."""
    if not _CRYPTO:
        raise RuntimeError("cryptography is required to generate keys")
    priv = Ed25519PrivateKey.generate()
    priv_pem = priv.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv_pem, pub_pem


def issue_license(  # pragma: no cover - tooling
    private_pem: str,
    tenant: str,
    edition: Edition,
    valid_days: int = 365,
    seats: int | None = None,
) -> str:
    """Mint a signed license token (vendor-side)."""
    if not _CRYPTO:
        raise RuntimeError("cryptography is required to issue licenses")
    now = int(time.time())
    payload = {
        "tenant": tenant,
        "edition": Edition(edition).value,
        "issued": now,
        "expires": 0 if valid_days <= 0 else now + valid_days * 86400,
    }
    if seats is not None:
        payload["seats"] = seats
    payload_raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    priv = serialization.load_pem_private_key(private_pem.encode(), password=None)
    sig = priv.sign(payload_raw)
    return f"{TOKEN_PREFIX}.{_b64url_encode(payload_raw)}.{_b64url_encode(sig)}"
