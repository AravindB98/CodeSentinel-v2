"""Offline Ed25519 licensing and edition feature-gating."""
import pytest

crypto = pytest.importorskip("cryptography")
from codesentinel.editions import (
    Edition,
    Feature,
    LicenseError,
    current_edition,
    generate_keypair,
    issue_license,
    require_feature,
    verify_license,
)


def test_sign_verify_roundtrip():
    priv, pub = generate_keypair()
    tok = issue_license(priv, "acme", Edition.ENTERPRISE, valid_days=30, seats=10)
    info = verify_license(tok, pub)
    assert info and info.verified and not info.expired
    assert info.edition == Edition.ENTERPRISE
    assert Feature.AUDIT_EXPORT in info.features and Feature.SSO in info.features


def test_tampered_token_does_not_verify():
    priv, pub = generate_keypair()
    tok = issue_license(priv, "acme", Edition.ENTERPRISE)
    tampered = tok[:-6] + ("AAAAAA" if not tok.endswith("AAAAAA") else "BBBBBB")
    info = verify_license(tampered, pub)
    assert not (info and info.verified)


def test_unverified_falls_back_to_community():
    priv, pub = generate_keypair()
    tok = issue_license(priv, "acme", Edition.GOVERNMENT)
    info = verify_license(tok, None)   # no key configured
    assert info is not None and info.verified is False
    assert Feature.AIRGAP not in info.features


def test_require_feature_gating(monkeypatch):
    priv, pub = generate_keypair()
    tok = issue_license(priv, "acme", Edition.ENTERPRISE)
    monkeypatch.setenv("CODESENTINEL_LICENSE_KEY", tok)
    monkeypatch.setenv("CODESENTINEL_LICENSE_PUBKEY", pub)
    assert current_edition() == Edition.ENTERPRISE
    require_feature(Feature.AUDIT_EXPORT)   # no raise
    monkeypatch.delenv("CODESENTINEL_LICENSE_PUBKEY")
    assert current_edition() == Edition.COMMUNITY
    with pytest.raises(LicenseError):
        require_feature(Feature.AUDIT_EXPORT)
