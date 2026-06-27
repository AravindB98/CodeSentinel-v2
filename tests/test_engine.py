"""Engine: multi-file scanning, backends, policy, baseline suppression."""
from codesentinel.config import load_config
from codesentinel.engine import Engine, scan_code


def _mock_cfg(**kw):
    c = load_config(overrides={"mock": True})
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_deterministic_backend_selected_offline():
    assert Engine(_mock_cfg()).backend == "deterministic"


def test_scan_code_finds_and_orders():
    code = 'cur.execute(f"select {x}")\npickle.loads(b)\nhashlib.md5(b"x")'
    r = Engine(_mock_cfg()).scan_code(code, "python", "db.py")
    cwes = [f.cwe for f in r.findings]
    assert "CWE-89" in cwes and "CWE-502" in cwes
    # severity-sorted: criticals before mediums
    sev = [f.severity for f in r.findings]
    assert sev == sorted(sev, key=lambda s: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(s))


def test_repo_scan_respects_excludes(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "a.py").write_text('cur.execute(f"select {x}")\n')
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "b.js").write_text('db.query(`select ${x}`)\n')
    r = Engine(_mock_cfg()).scan_path(str(tmp_path))
    paths = {f.location.path for f in r.findings}
    assert any("a.py" in p for p in paths)
    assert not any("node_modules" in p for p in paths)


def test_gate_and_thresholds():
    code = 'cur.execute(f"select {x}")'   # CRITICAL
    r = scan_code(code, "python", config=_mock_cfg())
    assert r.gate_failed("HIGH") is True
    assert r.count_at_or_above("CRITICAL") == 1
    # raise reporting threshold above the finding -> filtered out
    cfg = _mock_cfg()
    cfg.gate.severity_threshold = "CRITICAL"
    cfg.min_confidence = 0.99   # filter the 0.94 SQLi
    r2 = Engine(cfg).scan_code(code, "python", "db.py")
    assert len(r2.findings) == 0


def test_baseline_suppression(tmp_path):
    (tmp_path / "x.py").write_text("pickle.loads(b)\n")
    cfg = _mock_cfg()
    first = Engine(cfg).scan_path(str(tmp_path))
    assert first.findings, "expected a finding to baseline"
    fp = first.findings[0].fingerprint
    baseline = tmp_path / "baseline.json"
    baseline.write_text('{"fingerprints": ["' + fp + '"]}')
    cfg2 = _mock_cfg(); cfg2.baseline = str(baseline)
    second = Engine(cfg2).scan_path(str(tmp_path))
    assert second.suppressed >= 1
    assert all(f.fingerprint != fp for f in second.findings)
