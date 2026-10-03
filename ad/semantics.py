"""Lightweight semantic passes.

Regex rules miss the single most common A/D bug in this family of services: a
login handler that reads the submitted password and then never checks it. The
handlers look perfectly ordinary, so this pass extracts function bodies and
answers a concrete question:

    is a credential read from the request actually consumed inside the same
    function scope?

It also catches request data reaching an HTML sink, and plaintext password
storage, which need a small amount of local dataflow to see.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Evidence, Finding
from .models import fingerprint as fp_of
from .models import line_of

CREDENTIAL_NAMES = ("password", "passwd", "pwd", "pass", "secret", "magicword", "magic_word")

# Reads of a credential from the request.
CREDENTIAL_READ = re.compile(
    r"(?i)\b(?P<var>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:"
    r"request\.(?:form|args|json|data)\.?(?:get)?\s*[(\[.]\s*['\"](?P<k1>[^'\"]+)['\"]"
    r"|c\.PostForm\s*\(\s*['\"](?P<k2>[^'\"]+)['\"]"
    r"|c\.PostFormArray\s*\(\s*['\"](?P<k3>[^'\"]+)['\"]"
    r"|req\.(?:body|query|params)\s*(?:\.|\[\s*['\"])(?P<k4>[^'\"\]\.]+)['\"]?\s*\]?"
    r"|r\.(?:Form|PostForm|FormValue)\.Get\s*\(\s*['\"](?P<k5>[^'\"]+)['\"]"
    r"|\$_POST\s*\[\s*['\"](?P<k6>[^'\"]+)['\"]"
    r"|\$_REQUEST\s*\[\s*['\"](?P<k7>[^'\"]+)['\"]"
    r"|\$_GET\s*\[\s*['\"](?P<k8>[^'\"]+)['\"]"
    r"|params\.(?:get|query)\s*\(\s*['\"](?P<k9>[^'\"]+)['\"]"
    r"|request\.GET\s*\(\s*['\"](?P<k10>[^'\"]+)['\"]"
    r")"
)

# Anything that consumes a credential: comparison, hashing, verification, lookup.
CREDENTIAL_CONSUMED = re.compile(
    r"(?i)(?:==|===|!=|!==|compare|verify|check_?password|generate_password_hash|"
    r"password_hash|bcrypt|argon|scrypt|pbkdf|hmac|constant_time|"
    r"sha(?:1|256|512)|md5\s*\(|SELECT\s+[^\n]{0,80}password|UPDATE\s+[^\n]{0,80}password)"
)

HTML_SINK = re.compile(
    r"(?i)(?:fmt\.Sprintf|String\.Format|\.format\(|f[\"']|\+\s*\w|innerHTML|"
    r"outerHTML|document\.write|render_template_string|c\."
    r"(?:HTML|String)|jsonify\s*\(|json\.dumps\s*\()"
)
HTML_TAG = re.compile(r"(?i)<(?:div|span|script|img|a|p|html|body|input|textarea)\b")

PASSWORD_STORAGE = re.compile(
    r"(?i)INSERT\s+INTO\s+[\w.]*\w*(?:users?|accounts?|members?|auth)\w*[^;\n]{0,120}password"
    r"|\b(?:create|add|register|signup|insert)_?user\b[^)\n]{0,120}password"
)
HASH_NEARBY = re.compile(
    r"(?i)(?:generate_password_hash|Hash::make|password_hash|bcrypt|argon|scrypt|"
    r"createHash|sha256?|md5\s*\(|pbkdf2)"
)

# Persisting a credential is a legitimate use during registration, so it counts
# as consumption. The weakness there is storage, not verification, and that is
# reported separately by AD-CRYPTO-004.
STORAGE_SINK = re.compile(
    r"(?i)(?:INSERT\s+INTO|\b(?:insert|add|create|register|signup|save)_?user\b|"
    r"\.create\s*\(|\.save\s*\(|\.insert\s*\()"
)


@dataclass
class Scope:
    name: str
    file: str
    start: int
    end: int
    body: str

    @property
    def text(self) -> str:
        return self.body


BRACE_LANGS = {".go", ".js", ".ts", ".tsx", ".jsx", ".php", ".java", ".cs", ".kt", ".rs", ".c", ".cpp"}
FUNC_START = re.compile(
    r"^\s*(?:async\s+)?(?:def|function|func|fn|sub)\s+(?P<name>\w+)\s*\("
    r"|^\s*(?P<name2>\w+)\s*=\s*(?:async\s*)?(?:function\s*)?\(?[^=\n]*\)?\s*=>\s*\{"
    r"|^\s*(?P<name3>\w+)\s*:\s*function\s*\("
    r"|^\s*public\s+function\s+(?P<name4>\w+)\s*\("
)


def extract_scopes(text: str, suffix: str) -> list[Scope]:
    if suffix == ".py":
        return _python_scopes(text)
    return _brace_scopes(text)


def _python_scopes(text: str) -> list[Scope]:
    lines = text.splitlines()
    scopes: list[Scope] = []
    starts: list[tuple[int, int, str]] = []
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = re.match(r"^(\s*)(?:async\s+)?def\s+(\w+)\s*\(", line)
        if match:
            starts.append((index, len(match.group(1)), match.group(2)))
    for position, (index, indent, name) in enumerate(starts):
        end = len(lines)
        for next_index, next_indent, _ in starts[position + 1 :]:
            if next_indent <= indent:
                end = next_index
                break
        body = "\n".join(lines[index:end])
        scopes.append(Scope(name=name, file="", start=index + 1, end=end, body=body))
    return scopes


def _brace_scopes(text: str) -> list[Scope]:
    scopes: list[Scope] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = FUNC_START.match(line)
        if not match:
            continue
        # Yield the captured value, not the group name, so descriptions quote
        # the real function.
        name = next(
            (v for v in (match.group("name"), match.group("name2"),
                         match.group("name3"), match.group("name4")) if v),
            "anonymous",
        )
        open_at = line.find("{")
        if open_at == -1:
            continue
        depth = 0
        end = index
        for cursor in range(index, len(lines)):
            segment = lines[cursor]
            for char in segment:
                if char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
                    if depth == 0:
                        end = cursor
                        break
            if depth == 0:
                break
        else:
            end = len(lines) - 1
        body = "\n".join(lines[index : end + 1])
        scopes.append(Scope(name=name, file="", start=index + 1, end=end + 1, body=body))
    return scopes


def _tag(text: str, suffix: str, rule_id: str, category: str, title: str, severity: str,
         description: str, exploit: str, breaker: str, remediation: str, cwe, sources,
         index: int, confidence: str = "high") -> Finding:
    line = index
    snippet = re.sub(r"\s+", " ", text.strip())[:500]
    return Finding(
        rule_id=rule_id,
        category=category,
        title=title,
        severity=severity,
        confidence=confidence,
        evidence=Evidence(file="", line=line, snippet=snippet, fingerprint=fp_of(snippet)),
        description=description,
        exploit=exploit,
        breaker=breaker,
        remediation=remediation,
        cwe=cwe,
        sources=sources,
    )


def check_unused_credentials(
    scopes: list[Scope], rel: str, sources: tuple[str, ...]
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for scope in scopes:
        body = scope.body
        for match in CREDENTIAL_READ.finditer(body):
            key = next((match.group(f"k{i}") for i in range(1, 11) if match.group(f"k{i}")), None)
            if not key or not any(name in key.lower() for name in CREDENTIAL_NAMES):
                continue
            var = match.group("var")
            if not var:
                continue
            # Consume every later mention of the variable, excluding the read
            # itself. No mention at all is the strongest form of the bug.
            tail = body[match.end() :]
            used = False
            for mention in re.finditer(rf"\b{re.escape(var)}\b", tail):
                window = tail[max(0, mention.start() - 60) : mention.end() + 60]
                if CREDENTIAL_CONSUMED.search(window):
                    used = True
                    break
            # Registration paths legitimately persist the credential.
            if not used and STORAGE_SINK.search(body):
                used = True
            if used:
                continue
            line = scope.start + line_of(body, match.start()) - 1
            snippet = re.sub(r"\s+", " ", body.strip())[:500]
            fingerprint = fp_of(f"{scope.name}:{var}:{snippet}")
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            findings.append(
                Finding(
                    rule_id="AD-AUTH-001",
                    category="AUTH_BYPASS",
                    title="Credential read from the request and never verified",
                    severity="critical",
                    confidence="high",
                    evidence=Evidence(rel, line, snippet, fingerprint),
                    description=(
                        f"`{var}` is populated from the submitted "
                        f"`{key}` field in `{scope.name}()` and is never compared, hashed "
                        "or looked up. Authentication therefore succeeds for any password."
                    ),
                    exploit=(
                        f"Log in as any existing username with an arbitrary password. "
                        f"The instance grants `{scope.name}()`'s full session."
                    ),
                    breaker=(
                        "None. The checker authenticates with its real credentials, so this "
                        "invisible to scoring and must be found by review."
                    ),
                    remediation="Verify the submitted credential against a stored hash.",
                    cwe=("CWE-287", "CWE-308"),
                    sources=sources,
                )
            )
    return findings


def check_request_to_html(
    scopes: list[Scope], rel: str, sources: tuple[str, ...]
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for scope in scopes:
        body = scope.body
        sink = HTML_SINK.search(body)
        tag = HTML_TAG.search(body)
        if not sink or not tag:
            continue
        tainted: set[str] = set()
        for match in CREDENTIAL_READ.finditer(body):
            var = match.group("var")
            if var:
                tainted.add(var)
        for match in re.finditer(r"(?i)\b([A-Za-z_]\w*)\s*=\s*(?:request|req|params|input)", body):
            tainted.add(match.group(1))
        formatted = set(re.findall(r"\b([A-Za-z_]\w*)\b", body[sink.end() : sink.end() + 200]))
        if not (tainted & formatted):
            continue
        line = scope.start + min(line_of(body, sink.start()), 1) - 1
        snippet = re.sub(r"\s+", " ", body.strip())[:500]
        fingerprint = fp_of(f"html:{scope.name}:{snippet}")
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(
            Finding(
                rule_id="AD-XSS-002",
                category="XSS",
                title="Request-controlled value rendered into an HTML response",
                severity="high",
                confidence="medium",
                evidence=Evidence(rel, line, snippet, fingerprint),
                description=(
                    f"`{scope.name}()` builds HTML by string formatting and feeds it request "
                    "data. No escaping is applied on this path."
                ),
                exploit=(
                    "Submit a payload such as `<script>...</script>` or an event handler; it is "
                    "reflected verbatim in the victim's session."
                ),
                breaker=(
                    "A payload that re-enters the checker's session can corrupt its state; a "
                    "malformed payload that raises an exception stops the instance (IV.5)."
                ),
                remediation="Escape on output, or render through the template engine's escaping.",
                cwe=("CWE-79",),
                sources=sources,
            )
        )
    return findings


def check_plaintext_password_storage(
    scopes: list[Scope], rel: str, sources: tuple[str, ...]
) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for scope in scopes:
        body = scope.body
        if not PASSWORD_STORAGE.search(body):
            continue
        if HASH_NEARBY.search(body):
            continue
        snippet = re.sub(r"\s+", " ", body.strip())[:500]
        fingerprint = fp_of(f"plain:{scope.name}:{snippet}")
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        findings.append(
            Finding(
                rule_id="AD-CRYPTO-004",
                category="WEAK_CRYPTO",
                title="Password persisted without a hash",
                severity="critical",
                confidence="high",
                evidence=Evidence(rel, scope.start, snippet, fingerprint),
                description=(
                    f"`{scope.name}()` writes a password column with no hashing call in scope. "
                    "Anyone who reaches the datastore - directly, via SQLi or via traversal - "
                    "reads every team's plaintext credentials."
                ),
                exploit="Reach the datastore, dump the table, log in as any team.",
                breaker=(
                    "None for the checker, which uses correct credentials. But combined with any "
                    "read primitive this is a total compromise of the instance."
                ),
                remediation="Hash with bcrypt/argon2/scrypt and a per-user salt before storing.",
                cwe=("CWE-256", "CWE-312"),
                sources=sources,
            )
        )
    return findings


def run_all(text: str, rel: str, suffix: str, sources: tuple[str, ...]) -> list[Finding]:
    scopes = extract_scopes(text, suffix)
    findings: list[Finding] = []
    findings.extend(check_unused_credentials(scopes, rel, sources))
    findings.extend(check_request_to_html(scopes, rel, sources))
    findings.extend(check_plaintext_password_storage(scopes, rel, sources))
    return findings