"""Hash-chained audit log: integrity and tamper detection."""
import json

from codesentinel.audit import AuditLog


def test_chain_valid(tmp_path):
    log = AuditLog(str(tmp_path / "a.log"))
    log.record("acme", "scan", target="a.py", findings=2)
    log.record("acme", "scan", target="b.py", findings=0)
    log.record("gov", "scan", target="c.go", findings=1)
    v = log.verify_chain()
    assert v["valid"] and v["entries"] == 3
    assert len(log.read(tenant="acme")) == 2


def test_tamper_detected(tmp_path):
    p = tmp_path / "a.log"
    log = AuditLog(str(p))
    log.record("acme", "scan", target="a.py", findings=2)
    log.record("acme", "scan", target="b.py", findings=5)
    lines = p.read_text().splitlines()
    rec = json.loads(lines[0]); rec["details"]["findings"] = 999
    lines[0] = json.dumps(rec, sort_keys=True)
    p.write_text("\n".join(lines) + "\n")
    assert log.verify_chain()["valid"] is False
