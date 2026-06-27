"""Reporters: SARIF 2.1.0 validity and all-format rendering."""
from codesentinel.config import load_config
from codesentinel.engine import Engine
from codesentinel.reporters import FORMATS, render
from codesentinel.reporters.sarif import to_sarif


def _result():
    cfg = load_config(overrides={"mock": True})
    code = ('cur.execute(f"select {x}")\npickle.loads(b)\n'
            'requests.get(u, verify=False)\nhashlib.md5(b"x")')
    return Engine(cfg).scan_code(code, "python", "svc/db.py")


def test_sarif_structure():
    r = _result()
    s = to_sarif(r)
    assert s["version"] == "2.1.0"
    run = s["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    assert run["results"], "expected results"
    for res in run["results"]:
        assert res["level"] in ("error", "warning", "note")
        assert 0 <= res["ruleIndex"] < len(rules)
        assert rules[res["ruleIndex"]]["id"] == res["ruleId"]
        assert "partialFingerprints" in res
        assert res["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_sarif_security_severity_property():
    s = to_sarif(_result())
    for rule in s["runs"][0]["tool"]["driver"]["rules"]:
        assert "security-severity" in rule["properties"]


def test_all_formats_render():
    r = _result()
    for fmt in FORMATS:
        out = render(r, fmt, color=False)
        assert isinstance(out, str) and len(out) > 50
    assert "<!DOCTYPE html>" in render(r, "html")
    assert "# CodeSentinel" in render(r, "markdown")
