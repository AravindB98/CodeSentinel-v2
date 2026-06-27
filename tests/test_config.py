"""Config loading, precedence, and policy helpers."""
from codesentinel.config import ScanConfig, load_config, meets_threshold, severity_rank


def test_defaults():
    c = load_config()
    assert c.gate.fail_on == "HIGH"
    assert c.min_confidence == 0.5
    assert c.engine == "auto"


def test_scope_matching():
    c = ScanConfig()
    assert c.is_included("app/main.py")
    assert not c.is_included("node_modules/x/y.js")
    assert not c.is_included("dist/bundle.js")
    assert c.language_for("a.py") == "python"
    assert c.language_for("a.tsx") == "typescript"
    assert c.language_for("a.unknown") is None


def test_rule_toggles():
    c = ScanConfig(disabled_rules=["CWE-89"])
    assert not c.rule_enabled("CWE-89", "SEC-001")
    assert c.rule_enabled("CWE-502")
    c2 = ScanConfig(enabled_rules=["CS-PY-PICKLE"])
    assert c2.rule_enabled("CS-PY-PICKLE")
    assert not c2.rule_enabled("CS-PY-SQLI-FSTR")


def test_severity_helpers():
    assert severity_rank("CRITICAL") < severity_rank("LOW")
    assert meets_threshold("CRITICAL", "HIGH")
    assert not meets_threshold("LOW", "HIGH")


def test_env_override(monkeypatch):
    monkeypatch.setenv("CODESENTINEL_FAIL_ON", "critical")
    assert load_config().gate.fail_on == "CRITICAL"


def test_yaml_file(tmp_path, monkeypatch):
    monkeypatch.delenv('CODESENTINEL_MODEL', raising=False)
    monkeypatch.delenv('CODESENTINEL_FAIL_ON', raising=False)
    cfg = tmp_path / ".codesentinel.yml"
    cfg.write_text("concurrency: 7\ngate:\n  fail_on: CRITICAL\nllm:\n  model: m1\n")
    c = load_config(path=str(cfg))
    assert c.concurrency == 7 and c.gate.fail_on == "CRITICAL" and c.llm.model == "m1"
