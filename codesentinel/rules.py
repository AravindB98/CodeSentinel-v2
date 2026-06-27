"""Declarative deterministic rule registry (offline / air-gapped detection).

These regex rules are the *deterministic* layer of CodeSentinel. They run with
no LLM and no network — which is what makes the tool usable in air-gapped and
classified environments, and what powers the reproducible benchmark. The LLM
layer (Security Sentinel) adds semantic reasoning on top; the Evaluator Guardian
then validates every finding. This registry is the single source of truth: the
offline detector, ``codesentinel rules`` and the docs all read from it.

Each rule cites a passage in the RAG corpus (``rag_doc`` / ``rag_pid``) so that
even deterministic findings carry provenance, exactly like LLM findings.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# Languages that share the JS ruleset.
JS_LANGS = {"javascript", "typescript"}


@dataclass
class Rule:
    rule_id: str
    language: str            # "python" | "javascript" | "typescript" | "java" | "go" | "ruby" | "php"
    cwe: str
    owasp: str
    category: str
    severity: str
    confidence: float
    pattern: str            # regex matched per-line
    fix: str
    rag_doc: str
    rag_pid: str
    title: str
    requires: Optional[str] = None   # substring that must appear somewhere in the file
    flags: int = re.IGNORECASE
    _rx: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    def compiled(self) -> re.Pattern:
        if self._rx is None:
            self._rx = re.compile(self.pattern, self.flags)
        return self._rx

    def applies_to(self, language: str) -> bool:
        if self.language in JS_LANGS:
            return language in JS_LANGS
        return self.language == language

    def to_dict(self) -> Dict[str, str]:
        return {
            "rule_id": self.rule_id, "language": self.language, "cwe": self.cwe,
            "owasp": self.owasp, "category": self.category, "severity": self.severity,
            "confidence": self.confidence, "title": self.title,
            "rag_source": f"{self.rag_doc}::{self.rag_pid}",
        }


# OWASP 2025 category shorthands
A01 = "A01:2025 Broken Access Control"
A02 = "A02:2025 Cryptographic Failures"
A03 = "A03:2025 Injection"
A05 = "A05:2025 Security Misconfiguration"
A07 = "A07:2025 Identification and Authentication Failures"
A08 = "A08:2025 Software and Data Integrity Failures"
A10 = "A10:2025 Server-Side Request Forgery"

RULES: List[Rule] = [
    # ---------------- Python ----------------
    Rule("CS-PY-SQLI-FSTR", "python", "CWE-89", A03, "SQL Injection", "CRITICAL", 0.94,
         r'execute\s*\(\s*f["\']',
         "Use parameterized queries with placeholders instead of f-strings. "
         "Example: cursor.execute(\"SELECT * FROM users WHERE id = ?\", (uid,)).",
         "patterns.md", "PY-01", "SQL injection via f-string in execute()"),
    Rule("CS-PY-SQLI-CONCAT", "python", "CWE-89", A03, "SQL Injection", "CRITICAL", 0.90,
         r'execute\s*\([^)]*(\.format\(|["\'][^"\']*["\']\s*\+)',
         "Use parameterized queries rather than .format() or string concatenation.",
         "patterns.md", "PY-01", "SQL injection via concatenation/format"),
    Rule("CS-PY-PICKLE", "python", "CWE-502", A08, "Insecure Deserialization", "CRITICAL", 0.96,
         r'pickle\.loads?\s*\(',
         "Never unpickle untrusted data. Use json.loads() with schema validation, "
         "or a signed serializer such as itsdangerous.",
         "patterns.md", "PY-02", "Unsafe pickle deserialization"),
    Rule("CS-PY-YAML", "python", "CWE-502", A08, "Insecure Deserialization", "HIGH", 0.85,
         r'yaml\.load\s*\((?![^)]*Safe)',
         "Replace yaml.load(data) with yaml.safe_load(data).",
         "patterns.md", "PY-07", "yaml.load without SafeLoader"),
    Rule("CS-PY-CMDI", "python", "CWE-78", A03, "Command Injection", "HIGH", 0.88,
         r'subprocess\.(run|Popen|call|check_output)\s*\([^)]*shell\s*=\s*True',
         "Remove shell=True and pass arguments as a list; validate against an allow-list.",
         "patterns.md", "PY-03", "subprocess with shell=True"),
    Rule("CS-PY-OSSYSTEM", "python", "CWE-78", A03, "Command Injection", "HIGH", 0.84,
         r'os\.system\s*\(',
         "Avoid os.system; use subprocess.run([...]) with a list of arguments.",
         "patterns.md", "PY-03", "os.system command execution"),
    Rule("CS-PY-EVAL", "python", "CWE-94", A03, "Code Injection", "CRITICAL", 0.92,
         r'\beval\s*\(', "Do not eval request-derived input; parse explicitly or allow-list.",
         "patterns.md", "PY-04", "eval() on untrusted input", requires="request"),
    Rule("CS-PY-TLS", "python", "CWE-295", A02, "Improper Certificate Validation", "HIGH", 0.90,
         r'verify\s*=\s*False',
         "Remove verify=False; pass a CA bundle path if a custom root is needed.",
         "patterns.md", "PY-06", "TLS verification disabled"),
    Rule("CS-PY-WEAKHASH", "python", "CWE-327", A02, "Weak Cryptography", "MEDIUM", 0.75,
         r'hashlib\.(md5|sha1)\s*\(',
         "Use sha256+ for integrity; bcrypt/argon2 (passlib) for passwords.",
         "patterns.md", "PY-08", "Weak hash (MD5/SHA1)"),
    Rule("CS-PY-SECRET", "python", "CWE-798", A07, "Hardcoded Credentials", "HIGH", 0.80,
         r'(password|api_key|secret|token)\s*=\s*["\'][A-Za-z0-9_\-]{8,}["\']',
         "Load secrets from env or a secrets manager; rotate any committed value.",
         "patterns.md", "PY-05", "Hard-coded credential"),
    Rule("CS-PY-FLASKDEBUG", "python", "CWE-489", A05, "Security Misconfiguration", "MEDIUM", 0.7,
         r'\.run\s*\([^)]*debug\s*=\s*True',
         "Never run with debug=True in production; the Werkzeug debugger allows RCE.",
         "patterns.md", "PY-09", "Flask debug mode enabled"),

    # ---------------- JavaScript / TypeScript ----------------
    Rule("CS-JS-EVAL", "javascript", "CWE-94", A03, "Code Injection", "CRITICAL", 0.90,
         r'\beval\s*\(', "Remove eval on user input; parse or allow-list operations.",
         "patterns.md", "JS-01", "eval() on untrusted input", requires="req"),
    Rule("CS-JS-SQLI", "javascript", "CWE-89", A03, "SQL Injection", "CRITICAL", 0.93,
         r'\.(query|execute)\s*\(\s*`[^`]*\$\{',
         "Use parameterized queries: db.query(\"... WHERE id = ?\", [id]).",
         "patterns.md", "JS-02", "SQL injection via template literal"),
    Rule("CS-JS-XSS", "javascript", "CWE-79", A03, "Cross-Site Scripting", "HIGH", 0.80,
         r'\.innerHTML\s*=',
         "Use textContent, or sanitize with DOMPurify.sanitize() for rich HTML.",
         "patterns.md", "JS-04", "DOM XSS via innerHTML"),
    Rule("CS-JS-CHILDPROC", "javascript", "CWE-78", A03, "Command Injection", "HIGH", 0.85,
         r'child_process\.(exec|execSync)\s*\(',
         "Use execFile/spawn with an argument array; never interpolate user input.",
         "patterns.md", "JS-05", "child_process.exec command injection"),
    Rule("CS-JS-PROTO", "javascript", "CWE-1321", A08, "Prototype Pollution", "HIGH", 0.7,
         r'Object\.assign\s*\(\s*\{\s*\}\s*,\s*(req|JSON\.parse)',
         "Validate/whitelist keys before merging untrusted objects; freeze prototypes.",
         "patterns.md", "JS-06", "Prototype pollution via Object.assign"),
    Rule("CS-JS-SECRET", "javascript", "CWE-798", A07, "Hardcoded Credentials", "HIGH", 0.78,
         r'(apiKey|api_key|secret|token|password)\s*[:=]\s*["\'][A-Za-z0-9_\-]{8,}["\']',
         "Load secrets from environment variables; never commit them.",
         "patterns.md", "JS-07", "Hard-coded credential"),

    # ---------------- Java ----------------
    Rule("CS-JAVA-SQLI", "java", "CWE-89", A03, "SQL Injection", "CRITICAL", 0.9,
         r'(createStatement\(\)|Statement)[^;]*executeQuery\s*\([^)]*\+',
         "Use PreparedStatement with bound parameters instead of string concatenation.",
         "patterns.md", "JAVA-01", "SQL injection via Statement concatenation"),
    Rule("CS-JAVA-DESER", "java", "CWE-502", A08, "Insecure Deserialization", "CRITICAL", 0.9,
         r'new\s+ObjectInputStream\s*\(',
         "Avoid Java native deserialization of untrusted data; use a safe format and "
         "an allow-list (e.g. ValidatingObjectInputStream).",
         "patterns.md", "JAVA-02", "Unsafe ObjectInputStream deserialization"),
    Rule("CS-JAVA-CMDI", "java", "CWE-78", A03, "Command Injection", "HIGH", 0.86,
         r'Runtime\.getRuntime\(\)\.exec\s*\(',
         "Validate inputs and prefer ProcessBuilder with a fixed argument list.",
         "patterns.md", "JAVA-03", "Runtime.exec command injection"),
    Rule("CS-JAVA-XXE", "java", "CWE-611", A05, "XML External Entity", "HIGH", 0.82,
         r'DocumentBuilderFactory\.newInstance\(\)',
         "Disable external entities: setFeature(\"...disallow-doctype-decl\", true).",
         "patterns.md", "JAVA-04", "XXE-prone DocumentBuilderFactory"),

    # ---------------- Go ----------------
    Rule("CS-GO-SQLI", "go", "CWE-89", A03, "SQL Injection", "CRITICAL", 0.9,
         r'\.(Query|Exec)\s*\(\s*(fmt\.Sprintf|"[^"]*"\s*\+)',
         "Use parameterized queries with $1/? placeholders, not fmt.Sprintf.",
         "patterns.md", "GO-01", "SQL injection via Sprintf"),
    Rule("CS-GO-CMDI", "go", "CWE-78", A03, "Command Injection", "HIGH", 0.85,
         r'exec\.Command\s*\(\s*"(sh|bash|cmd)"',
         "Avoid invoking a shell; call the binary directly with explicit args.",
         "patterns.md", "GO-02", "exec.Command shell invocation"),
    Rule("CS-GO-TLS", "go", "CWE-295", A02, "Improper Certificate Validation", "HIGH", 0.88,
         r'InsecureSkipVerify\s*:\s*true',
         "Never set InsecureSkipVerify: true in production.",
         "patterns.md", "GO-03", "TLS verification disabled"),
    Rule("CS-GO-WEAKHASH", "go", "CWE-327", A02, "Weak Cryptography", "MEDIUM", 0.72,
         r'(md5|sha1)\.New\s*\(',
         "Use sha256+; for passwords use bcrypt/argon2.",
         "patterns.md", "GO-04", "Weak hash (MD5/SHA1)"),

    # ---------------- Ruby ----------------
    Rule("CS-RB-CMDI", "ruby", "CWE-78", A03, "Command Injection", "HIGH", 0.85,
         r'(system|`|%x|exec)\s*\(?["\'`][^"\'`]*#\{',
         "Never interpolate input into shell commands; pass an argument array.",
         "patterns.md", "RB-01", "Command injection via interpolation"),
    Rule("CS-RB-EVAL", "ruby", "CWE-94", A03, "Code Injection", "CRITICAL", 0.9,
         r'\b(eval|instance_eval|class_eval)\s*\(',
         "Avoid eval on untrusted input; use explicit dispatch.",
         "patterns.md", "RB-02", "eval() on untrusted input", requires="params"),
    Rule("CS-RB-YAML", "ruby", "CWE-502", A08, "Insecure Deserialization", "HIGH", 0.83,
         r'YAML\.load\s*\((?!.*safe)',
         "Use YAML.safe_load; YAML.load can instantiate arbitrary objects.",
         "patterns.md", "RB-03", "YAML.load deserialization"),

    # ---------------- PHP ----------------
    Rule("CS-PHP-SQLI", "php", "CWE-89", A03, "SQL Injection", "CRITICAL", 0.9,
         r'(mysqli_query|->query)\s*\([^)]*\$_(GET|POST|REQUEST)',
         "Use prepared statements with bound parameters (PDO/mysqli).",
         "patterns.md", "PHP-01", "SQL injection from request superglobal"),
    Rule("CS-PHP-CMDI", "php", "CWE-78", A03, "Command Injection", "HIGH", 0.86,
         r'(system|exec|shell_exec|passthru)\s*\([^)]*\$_(GET|POST|REQUEST)',
         "Never pass request data to shell functions; use escapeshellarg or avoid shells.",
         "patterns.md", "PHP-02", "Command injection from request"),
    Rule("CS-PHP-EVAL", "php", "CWE-94", A03, "Code Injection", "CRITICAL", 0.92,
         r'\beval\s*\(\s*\$',
         "Never eval dynamic input; restructure to explicit logic.",
         "patterns.md", "PHP-03", "eval() on dynamic input"),
    Rule("CS-PHP-INCLUDE", "php", "CWE-98", A03, "File Inclusion", "HIGH", 0.84,
         r'(include|require)(_once)?\s*\(?\s*\$_(GET|POST|REQUEST)',
         "Never include files chosen by request data; use a fixed allow-list.",
         "patterns.md", "PHP-04", "Remote/Local file inclusion"),
]


def iter_rules():
    """Yield all rules, sorted by language then id."""
    return sorted(RULES, key=lambda r: (r.language, r.rule_id))


def rules_for(language: str) -> List[Rule]:
    return [r for r in RULES if r.applies_to(language)]


def detect(code: str, language: str) -> List[dict]:
    """Run the deterministic ruleset over ``code`` and return finding dicts.

    Output shape matches the Security Sentinel's JSON contract so it can drive
    the offline/mock path and feed the same Evaluator and schemas.
    """
    findings: List[dict] = []
    applicable = rules_for(language)
    if not applicable:
        return findings
    code_l = code.lower()
    lines = code.splitlines()
    idx = 1
    for i, line in enumerate(lines):
        for rule in applicable:
            if rule.requires and rule.requires.lower() not in code_l:
                continue
            if rule.compiled().search(line):
                findings.append({
                    "finding_id": f"SEC-{idx:03d}",
                    "category": rule.category,
                    "cwe_id": rule.cwe,
                    "owasp_ref": rule.owasp,
                    "severity": rule.severity,
                    "confidence": rule.confidence,
                    "evidence": {
                        "file": "snippet",
                        "line_start": i + 1,
                        "line_end": i + 1,
                        "snippet": line.strip()[:300],
                    },
                    "fix": rule.fix,
                    "rag_source": {"doc": rule.rag_doc, "passage_id": rule.rag_pid},
                    "rule_id": rule.rule_id,
                })
                idx += 1
                break  # one finding per line
    return findings
