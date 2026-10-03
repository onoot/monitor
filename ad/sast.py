"""Static analysis engine.

Deliberately dependency-free: regex rules over source text, plus light
structural extraction of routes and flag-related sinks. Every finding carries
file, line, snippet and the rule's exploit/breaker rationale so a reviewer can
confirm or discard it without rerunning anything.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import semantics
from .models import Evidence, Finding
from .models import fingerprint as _fingerprint
from .models import line_of as _line_of
from .rules import RULES, Rule, severity_rank

LOCAL_SOURCE = ("local:AltayCoin/Curs/Magiclib/Omnyhub",)

TEXT_SUFFIXES = {
    ".py", ".go", ".js", ".ts", ".tsx", ".jsx", ".vue", ".php", ".rb", ".java",
    ".kt", ".cs", ".c", ".cpp", ".h", ".yml", ".yaml", ".json", ".env", ".sql",
    ".html", ".tpl", ".twig", ".conf", ".ini", ".toml", ".txt", ".sh", ".lua",
}

ROUTE_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Flask / FastAPI / aiohttp
    re.compile(r"@\w+\.(?:route|get|post|put|delete|patch|websocket)\(\s*[\"'](?P<p>[^\"']+)[\"']"),
    # Laravel / Slim / Symfony routes
    re.compile(r"Route::(?:get|post|put|delete|patch|any|match|resource)\s*\(\s*[\"'](?P<p>[^\"']+)[\"']"),
    # Express / Koa / Nest
    re.compile(r"\b(?:app|router|r)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*[\"'](?P<p>[^\"']+)[\"']"),
    # Gin / Echo / chi / gorilla
    re.compile(r"\b\w+\.(?:GET|POST|PUT|DELETE|PATCH|Any|HandleFunc)\s*\(\s*[\"'](?P<p>[^\"']+)[\"']"),
    re.compile(r"(?:Handle|HandleFunc)\s*\(\s*[\"'](?P<p>[^\"']+)[\"']"),
    # Spring / Axum
    re.compile(r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?[\"'](?P<p>[^\"']+)[\"']"),
    # Nest / Angular / Adonis style decorators (no `Mapping` suffix)
    re.compile(r"@(?:Get|Post|Put|Delete|Patch)\s*\(\s*[\"']?(?P<p>[^\"',)]{1,80})[\"']?\s*\)"),
)

FLAG_TOKENS = re.compile(
    r"(?i)\b(flag|flags|flag_path|flag_file|getflag|setflag|putflag|ctf_?flag)\b"
)

PROTECTED_HINT = re.compile(
    r"(?i)(?:chec?k_?auth|autch|authenticat|authguard|authmiddleware|@useguards|"
    r"\bauth\b|login|session|password|passwd|admin|role|permission|owner|secret|"
    r"verify|token|credential|require_?auth|login_?required|jwt|bearer)"
)

CREDENTIAL_FIELDS = (
    "password", "passwd", "pass", "pwd", "secret", "secretkey", "secret_key",
    "token", "authorization", "auth", "apikey", "api_key", "session", "cookie",
)


@dataclass
class Route:
    path: str
    method: str
    file: str
    line: int
    guarded: bool = False
    id_param: bool = False

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "method": self.method,
            "file": self.file,
            "line": self.line,
            "guarded": self.guarded,
            "id_param": self.id_param,
        }


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (-severity_rank(f.severity), f.rule_id, f.evidence.file, f.evidence.line))


def _excluded(rel_posix: str, name: str, patterns: list[str]) -> bool:
    for pattern in patterns:
        candidate = pattern.replace("\\", "/")
        if candidate.startswith("**/"):
            candidate = candidate[3:]
        if "/" in candidate:
            # Directory-style exclusion: any path containing the segment.
            segments = candidate.rstrip("**").strip("/").split("/")
            segments = [s for s in segments if s and s != "**"]
            parts = rel_posix.split("/")[:-1]
            if segments and any(
                parts[i : i + len(segments)] == segments for i in range(len(parts))
            ):
                return True
            if rel_posix.rstrip("/").endswith("/".join(segments)) and "**" in pattern:
                return True
            continue
        # Bare filename/glob: match against the file name.
        if fnmatch.fnmatch(name, candidate):
            return True
    return False


def _iter_source_files(roots: list[Path], excluded: list[str]) -> tuple[list[Path], int]:
    files: list[Path] = []
    skipped = 0
    seen: set[Path] = set()
    for root in roots:
        if root.is_file():
            if root not in seen:
                seen.add(root)
                files.append(root)
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path in seen:
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                rel = path.name
            if _excluded(rel, path.name, excluded):
                skipped += 1
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES and not path.name.startswith(".env"):
                skipped += 1
                continue
            seen.add(path)
            files.append(path)
    return files, skipped


# After the SQL literal: a binding argument list means the statement is safe.
BOUND_PARAMS = re.compile(
    r"""(?x)
    (?: ["'] \s* , \s* \(          # execute("...%s", (x,))
      | ["'] \s* % \s* \(          # "... %s ..." % (x,)
      | ["'] \s* \.\s* format \s* \( # "...{}...".format(x)
      | ,\s* \( \s* \w              # f(query, (x))
    )
    """
)

POST_FILTERS = {
    "bound_sql": lambda text, match: bool(
        BOUND_PARAMS.search(text, match.start(), min(len(text), match.end() + 240))
    ),
}


def _relative(path: Path, roots: list[Path]) -> str:
    for root in roots:
        try:
            return str(path.relative_to(root)).replace("\\", "/")
        except ValueError:
            continue
    return path.name


def _context_window(text: str, start: int, end: int, radius: int = 220) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    snippet = text[left:right].strip()
    snippet = re.sub(r"\s+", " ", snippet)
    return snippet[:500]


def scan(roots: list[Path], excluded: list[str], max_bytes: int = 2_000_000) -> ScanResult:
    files, skipped = _iter_source_files(roots, excluded)
    result = ScanResult(files_skipped=skipped)
    seen_keys: set[tuple[str, str]] = set()
    texts: dict[str, str] = {}

    for path in files:
        try:
            if path.stat().st_size > max_bytes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            continue
        if not text.strip():
            continue
        result.files_scanned += 1
        rel = _relative(path, roots)

        result.routes.extend(_extract_routes(text, rel))
        texts[rel] = text
        seen_keys = _apply_rules(text, rel, result, seen_keys)
        result.findings.extend(semantics.run_all(text, rel, Path(rel).suffix.lower(), LOCAL_SOURCE))

    result.routes = _dedupe_routes(result.routes)
    result.findings.extend(_unguarded_route_findings(result.routes, texts))
    return result


HANDLER_REF = re.compile(r",\s*([A-Za-z_$][\w$]*(?:\.\w+)*)\s*\)?\s*[;)]?\s*$")


DEFINE_RE = re.compile(
    r"(?:export\s+)?(?:const|let|var|async\s+function|function)\s+"
    r"(?P<name>[A-Za-z_$][\w$]*)\s*(?:=\s*(?:async\s*)?\(|=\s*async\b|\()"
)


def _handler_is_guarded(texts: dict[str, str], route: Route) -> bool | None:
    """Follow ``app.get("/x", Handler.name)`` to the handler body and look for auth.

    Returns None when the handler cannot be pinned to exactly one definition,
    so the caller can lower the confidence instead of guessing.
    """
    source_lines = texts.get(route.file, "").splitlines()
    if not source_lines or route.line > len(source_lines):
        return None
    match = HANDLER_REF.search(source_lines[route.line - 1].rstrip())
    if not match:
        return None
    ref = match.group(1)
    name = ref.split(".")[-1]
    if not name:
        return None

    definition_re = re.compile(
        rf"(?:export\s+)?(?:const|let|var|async\s+function|function)\s+{re.escape(name)}\b"
    )
    owners = [key for key, text in texts.items() if definition_re.search(text)]
    if route.file in owners:
        owners.remove(route.file)
    if not owners:
        return None
    if len(owners) > 1:
        # Ambiguous name: only trust it when the file name echoes the module ref.
        module = ref.rsplit(".", 1)[0].split(".")[-1].lower() if "." in ref else ""
        narrowed = [k for k in owners if module[:4] and module[:4] in Path(k).stem.lower()]
        if len(narrowed) != 1:
            return None
        owners = narrowed

    body_source = texts[owners[0]]
    found = definition_re.search(body_source)
    if not found:
        return None
    body = body_source[found.start() : found.start() + 1800]
    return bool(PROTECTED_HINT.search(body))


def _unguarded_route_findings(routes: list[Route], texts: dict[str, str]) -> list[Finding]:
    """Data-bearing routes with no authentication check at the route or in the handler."""
    out: list[Finding] = []
    seen: set[str] = set()
    for route in routes:
        if route.guarded or route.key in seen:
            continue
        if PUBLIC_HINT.search(route.path) or not SENSITIVE_HINT.search(route.path):
            continue
        handled = _handler_is_guarded(texts, route)
        if handled:
            continue
        confidence = "low" if handled is None else "medium"
        seen.add(route.key)
        out.append(
            Finding(
                rule_id="AD-AUTH-002",
                category="AUTH_BYPASS",
                title=f"Unauthenticated {route.method} {route.path}",
                severity="high",
                evidence=Evidence(
                    file=route.file,
                    line=route.line,
                    snippet=f"{route.method} {route.path}",
                    fingerprint=_fingerprint(route.key),
                ),
                description=(
                    "The route declaration has no authentication decorator, middleware or "
                    "session check in its surrounding lines, while the path points at per-user "
                    "or global data."
                ),
                exploit="Call the endpoint directly without any session or token.",
                breaker=(
                    "Usually none: checkers keep using authenticated endpoints, so teams read "
                    "the data freely while scoring continues."
                ),
                remediation="Apply the same auth guard used by the neighbouring routes.",
                cwe=("CWE-306",),
                sources=LOCAL_SOURCE,
                confidence=confidence,
            )
        )
    return out


def _apply_rules(
    text: str, rel: str, result: ScanResult, seen_keys: set[tuple[str, str]]
) -> set[tuple[str, str]]:
    suffix = Path(rel).suffix.lower()
    for rule in RULES:
        if not rule.applies_to(suffix):
            continue
        low = text.lower()
        if rule.must_contain and not all(token.lower() in low for token in rule.must_contain):
            continue
        if rule.must_not_contain and any(token.lower() in low for token in rule.must_not_contain):
            continue

        for match in rule.pattern.finditer(text):
            if rule.post and POST_FILTERS.get(rule.post, lambda *_: False)(text, match):
                continue
            window_start = max(0, match.start() - 400)
            window = text[window_start : match.end() + 400]
            if rule.must_not_contain and any(token.lower() in window.lower() for token in rule.must_not_contain):
                continue

            line = _line_of(text, match.start())
            snippet = _context_window(text, match.start(), match.end())
            key = (rule.id, f"{rel}:{_fingerprint(snippet)}")
            if key in seen_keys:
                continue
            seen_keys.add(key)

            result.findings.append(
                Finding(
                    rule_id=rule.id,
                    category=rule.category,
                    title=rule.title,
                    severity=rule.severity,
                    confidence=_confidence(rule, snippet),
                    evidence=Evidence(
                        file=rel,
                        line=line,
                        snippet=snippet,
                        fingerprint=_fingerprint(snippet),
                    ),
                    description=rule.description,
                    exploit=rule.exploit,
                    breaker=rule.breaker,
                    remediation=rule.remediation,
                    cwe=rule.cwe,
                    sources=rule.sources,
                )
            )
    return seen_keys


def _confidence(rule: Rule, snippet: str) -> str:
    if rule.category == "CHECKER_BREAKING" or rule.breaker.startswith("YES"):
        return "high"
    if re.search(r"(?:request|params|body|input|argv|query)", snippet, re.I):
        return "high"
    if re.search(r"(?:TODO|FIXME|example\.com|localhost|127\.0\.0\.1|test)", snippet, re.I):
        return "low"
    return "medium"


def _dedupe_routes(routes: list[Route]) -> list[Route]:
    seen: set[tuple[str, str]] = set()
    out: list[Route] = []
    for route in sorted(routes, key=lambda r: (r.path, r.method)):
        key = (route.method, route.path)
        if key in seen:
            continue
        seen.add(key)
        out.append(route)
    return out


HTTP_VERBS = ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD")

METHOD_LIST = re.compile(r"methods?\s*[:=]\s*\[(?P<list>[^\]]*)\]", re.I)


def _methods_for(token: str, tail: str) -> list[str]:
    """Resolve the HTTP verbs a route declaration covers."""
    listed = METHOD_LIST.search(tail)
    if listed:
        verbs = [
            v.upper()
            for v in re.findall(r"[\"']([A-Za-z]+)[\"']", listed.group("list"))
            if v.upper() in HTTP_VERBS
        ]
        if verbs:
            return verbs
    low = token.lower()
    if re.search(r"\bany\b|\.use\b|\.all\b|\bresource\b", low):
        return ["ANY"]
    for verb in ("get", "post", "put", "delete", "patch", "options", "head"):
        if f".{verb}" in low or f'"{verb}"' in low:
            return [verb.upper()]
    # Flask defaults to GET when the declaration omits `methods`.
    return ["GET"]


def _extract_routes(text: str, rel: str) -> list[Route]:
    lines = text.splitlines()
    raw: list[tuple[int, str, str, str]] = []
    for pattern in ROUTE_PATTERNS:
        for match in pattern.finditer(text):
            raw.append(
                (
                    _line_of(text, match.start()),
                    match.group("p"),
                    match.group(0),
                    text[match.end() : match.end() + 200],
                )
            )
    raw.sort()

    routes: list[Route] = []
    for index, (line_no, path, token, tail) in enumerate(raw):
        # A route owns the lines up to the next route declaration, so an
        # adjacent route's @UseGuards cannot mask a missing one.
        next_line = raw[index + 1][0] if index + 1 < len(raw) else line_no + 12
        block = "\n".join(lines[max(0, line_no - 1) : max(line_no + 1, next_line)])
        guarded = bool(PROTECTED_HINT.search(block))
        id_param = bool(re.search(r"\{[^}]*id[^}]*\}|:\w*id\b|<int:", path, re.I))
        for method in _methods_for(token, tail):
            routes.append(
                Route(
                    path=path,
                    method=method,
                    file=rel,
                    line=line_no,
                    guarded=guarded,
                    id_param=id_param,
                )
            )
    return routes


PUBLIC_HINT = re.compile(
    r"(?i)(?:^/|\.)(?:login|logout|register|signup|signin|sign-in|sign_up|"
    r"static|assets?|public|favicon|robots|sitemap|health|ping|ready|livez|readyz|"
    r"docs?|swagger|openapi|redoc)(?:/|\.|$)|auth(?:/|$)"
)

SENSITIVE_HINT = re.compile(
    r"(?i)(?:user|account|profile|admin|dashboard|wallet|balance|coin|score|"
    r"flag|me\b|self\b|orders?|transactions?|invoice|history|all\b|list|table|info)"
)


def unguarded_id_routes(routes: list[Route]) -> list[Route]:
    """Routes taking an object id with no authentication hint nearby."""
    return [r for r in routes if r.id_param and not r.guarded]