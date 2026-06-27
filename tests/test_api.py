"""REST API: auth, tenant isolation, formats, feature gating."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")
from fastapi.testclient import TestClient


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("CODESENTINEL_MOCK_LLM", "1")
    monkeypatch.setenv("CODESENTINEL_API_KEYS", "acme:k-acme,gov:k-gov")
    monkeypatch.delenv("CODESENTINEL_LICENSE_PUBKEY", raising=False)
    from codesentinel.api.app import create_app
    return TestClient(create_app())


def test_ops_endpoints(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/version").json()["name"] == "codesentinel"
    assert "codesentinel_scans_total" in client.get("/metrics").text


def test_requires_auth(client):
    assert client.post("/v1/scan", json={"code": "x=1", "language": "python"}).status_code == 401


def test_scan_and_tenant_isolation(client):
    H = {"X-API-Key": "k-acme"}
    code = 'cur.execute(f"select {x}")\npickle.loads(b)'
    r = client.post("/v1/scan", headers=H, json={"code": code, "language": "python", "filename": "db.py"})
    assert r.status_code == 200
    sid = r.json()["scan_id"]
    assert r.json()["summary"]["total_findings"] >= 2
    assert client.get(f"/v1/scans/{sid}", headers=H).status_code == 200
    # other tenant cannot read it
    assert client.get(f"/v1/scans/{sid}", headers={"X-API-Key": "k-gov"}).status_code == 404


def test_sarif_format(client):
    H = {"X-API-Key": "k-acme"}
    r = client.post("/v1/scan", headers=H, json={"code": 'pickle.loads(b)', "language": "python", "format": "sarif"})
    assert r.json()["version"] == "2.1.0"


def test_audit_gated_for_community(client):
    assert client.get("/v1/audit", headers={"X-API-Key": "k-acme"}).status_code == 402


def test_rules_listing(client):
    assert len(client.get("/v1/rules", headers={"X-API-Key": "k-acme"}).json()["rules"]) >= 30
