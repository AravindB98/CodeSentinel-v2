"""Deterministic rule registry: coverage, detection, and citation integrity."""
import re
from pathlib import Path

from codesentinel.rules import RULES, detect, iter_rules, rules_for


def test_language_coverage():
    langs = {r.language for r in RULES}
    assert {"python", "javascript", "java", "go", "ruby", "php"} <= langs
    # TypeScript shares the JS ruleset
    assert rules_for("typescript") == rules_for("javascript")
    assert len(rules_for("typescript")) > 0


def test_detection_per_language():
    cases = {
        "python": ('cur.execute(f"select {x}")', "CWE-89"),
        "go": ('db.Query(fmt.Sprintf("select %s", id))', "CWE-89"),
        "php": ('system($_GET["c"]);', "CWE-78"),
        "ruby": ('system("ls #{params[:x]}")', "CWE-78"),
        "java": ('new ObjectInputStream(in).readObject();', "CWE-502"),
    }
    for lang, (code, cwe) in cases.items():
        cwes = {f["cwe_id"] for f in detect(code, lang)}
        assert cwe in cwes, f"{lang}: expected {cwe}, got {cwes}"


def test_clean_code_no_findings():
    assert detect("def add(a, b):\n    return a + b\n", "python") == []


def test_requires_guard():
    # eval rule only fires when 'request' appears in the file
    assert detect("eval(x)", "python") == []
    assert any(f["cwe_id"] == "CWE-94" for f in detect("y = request.args\neval(y)", "python"))


def test_all_citations_resolve():
    corpus = Path("codesentinel/rag/data/patterns.md").read_text()
    ids = set(re.findall(r'^([A-Z0-9\-]+)\|\|\|', corpus, re.M))
    for r in RULES:
        assert r.rag_pid in ids, f"{r.rule_id} cites missing passage {r.rag_pid}"


def test_iter_rules_sorted_and_serializable():
    rules = list(iter_rules())
    assert rules == sorted(rules, key=lambda r: (r.language, r.rule_id))
    assert all("rule_id" in r.to_dict() for r in rules)
