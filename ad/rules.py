"""Detection rule pack.

Every rule is traceable to a concrete pattern observed either in the current
AltayCTF services or in the public SharLike-CTF-Team corpora
(AltayCTF-2017 / 2018 / 2019). The `sources` field records the evidence so a
reviewer can confirm the rule is not speculative.

Two independent axes matter for an A/D jury:

  exploit   how a competing team can abuse this against the *service owner*
  breaker   how this makes the *checker* fail and cost the jury points
            (AltayCTF 2026 rules IV.5 - do not break the service,
             IV.7 - flags and service availability)
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    title: str
    severity: str
    pattern: re.Pattern[str]
    languages: tuple[str, ...] = ()
    extensions: tuple[str, ...] = ()
    must_contain: tuple[str, ...] = ()
    must_not_contain: tuple[str, ...] = ()
    # Name of a post-match validator in ad.sast. Lets a rule reject matches that
    # look dangerous but are actually safe, e.g. bound SQL parameters.
    post: str = ""
    description: str = ""
    exploit: str = ""
    breaker: str = ""
    remediation: str = ""
    cwe: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()

    def applies_to(self, suffix: str) -> bool:
        if self.extensions and not any(suffix.endswith(ext) for ext in self.extensions):
            return False
        if self.languages and not any(suffix.endswith(ext) for ext in self.languages):
            return False
        return True


def _r(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


SOURCE_LOCAL = "local:AltayCoin/Curs/Magiclib/Omnyhub"
SOURCE_2019 = "corpus:altayctf-2019"
SOURCE_2018 = "corpus:AltayCTF-2018 checkers"

RULES: list[Rule] = [
    # ----------------------------------------------------------------- auth
    Rule(
        id="AD-AUTH-001",
        category="AUTH_BYPASS",
        title="Password/secret never verified on a privileged path",
        severity="critical",
        pattern=_r(r"(?i)\b(pass(word)?|secret|token)\s*(==|!=|===|!==)\s*['\"]{2}"),
        languages=(".py", ".js", ".ts", ".php", ".go", ".rb"),
        description=(
            "A comparison against an empty literal, or the absence of any credential "
            "check on a handler that returns protected data, lets an unauthenticated "
            "team read another team's data."
        ),
        exploit="Call the endpoint without credentials, or with an empty password.",
        breaker="None. The checker keeps working; the service owner silently leaks data.",
        remediation="Verify the credential server-side on every protected handler.",
        cwe=("CWE-287", "CWE-306"),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-AUTH-002",
        category="AUTH_BYPASS",
        title="Handler declares no authentication requirement",
        severity="medium",
        pattern=_r(r"@(?:app|module|bp|router)\.(?:route|get|post|put|delete|patch)\b"),
        languages=(".py", ".php", ".go", ".rb"),
        must_not_contain=("login_required", "auth_required", "@permission", "middleware('auth')"),
        description=(
            "Route registration with no adjacent authentication decorator/middleware. "
            "Static hints only - must be confirmed at runtime."
        ),
        exploit="Fetch the route unauthenticated.",
        breaker="None directly.",
        remediation="Apply an auth decorator/middleware to every non-public route.",
        cwe=("CWE-306",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-AUTH-003",
        category="AUTH_BYPASS",
        title="Session/cookie store key hardcoded",
        severity="high",
        pattern=_r(r"(?:NewCookieStore|CookieStore|cookieSecret|SESSION_SECRET|SECRET_KEY)"
                   r"\s*\(?\s*\[?\s*[\"'][^\"'\n]{4,}[\"']"),
        languages=(".py", ".go", ".js", ".ts", ".php", ".env"),
        description=(
            "A static signing key lets a team forge session cookies for arbitrary "
            "user ids, escalating privileges across the whole instance."
        ),
        exploit="Forge a session cookie carrying another user's id.",
        breaker="None for the checker, which uses real credentials.",
        remediation="Load the secret from the environment, rotate per deployment.",
        cwe=("CWE-798", "CWE-347"),
        sources=(SOURCE_2019,),
    ),
    # ------------------------------------------------------- privilege / IDOR
    Rule(
        id="AD-IDOR-001",
        category="IDOR",
        title="Object id taken from the request and used without ownership check",
        severity="high",
        pattern=_r(r"(?:findOrFail|find|get|select|find_by|objects)\s*\(\s*\$?\(?(?:request|id|params|user_id)"),
        languages=(".py", ".php", ".js", ".ts", ".go"),
        description=(
            "Entity lookup keyed directly on a client-supplied identifier. When the "
            "lookup is not intersected with the authenticated principal it becomes "
            "horizontal privilege escalation over another team's records."
        ),
        exploit="Swap the id in the URL/body for a victim's id.",
        breaker="None.",
        remediation="Scope every lookup by the authenticated owner id.",
        cwe=("CWE-639", "CWE-862"),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-PRIV-001",
        category="PRIVILEGE_ESCALATION",
        title="Role / permission supplied by the client at registration or update",
        severity="critical",
        pattern=_r(r"(?i)\b(role|permission|isAdmin|is_admin|level|lvl|access)\s*"
                   r"(?:=|:)\s*(?:request|params|_GET|_POST|body|data|json|req)\b"),
        languages=(".py", ".php", ".js", ".ts", ".go"),
        description=(
            "Privileged attributes are read straight from the request. A team that "
            "registers with an elevated role immediately owns the instance."
        ),
        exploit="Register or update the profile sending role/permission=1.",
        breaker="None.",
        remediation="Ignore client-supplied privileged fields; derive them server-side.",
        cwe=("CWE-269", "CWE-915"),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-PRIV-002",
        category="PRIVILEGE_ESCALATION",
        title="Authorisation decided from a client-controlled value",
        severity="high",
        pattern=_r(r"(?i)if\s*\(\s*['\"]?(?:role|isAdmin|is_admin|permission|level)['\"]?\s*"
                   r"(?:===|==|!=)\s*(?:['\"]?(?:request|session|cookie|jwt|payload|token))"),
        languages=(".js", ".ts", ".py", ".php"),
        description="A decoded token/session field decides access without a signature check.",
        exploit="Craft a token whose privilege claim is elevated.",
        breaker="None.",
        remediation="Verify the signature server-side before trusting any claim.",
        cwe=("CWE-863",),
        sources=(SOURCE_LOCAL,),
    ),
    Rule(
        id="AD-PRIV-004",
        category="PRIVILEGE_ESCALATION",
        title="Privilege flag copied straight out of an unverified token",
        severity="critical",
        pattern=_r(
            r"(?i)(?:is_?admin|isAdmin|role|permission|level|lvl|admin)\s*[:=]\s*"
            r"(?:bool(?:ean)?\s*\(\s*)?(?:[A-Za-z_$\.]*\.)?"
            r"(?:decoded|payload|claims|token|jwt|req\.auth|request\.auth)\b"
        ),
        languages=(".js", ".ts", ".py", ".php", ".go"),
        description=(
            "An administrative flag is taken from the request's own token payload. Combined with "
            "a decode-only token check this is a full account takeover primitive: no secret is "
            "needed, only the ability to base64 a claim."
        ),
        exploit=(
            "Take any valid token, edit the isAdmin/role claim, re-base64 the payload and replay "
            "the request with the forged token."
        ),
        breaker=(
            "None. The checker uses tokens minted by the service, so it keeps working while teams "
            "escalate freely."
        ),
        remediation=(
            "Verify the signature and read privileges from the server-side user record, never "
            "from client-supplied token contents."
        ),
        cwe=("CWE-863", "CWE-345"),
        sources=(SOURCE_LOCAL,),
    ),
    Rule(
        id="AD-JWT-002",
        category="CRYPTOGRAPHY",
        title="Hardcoded JWT signing secret in the repository",
        severity="critical",
        pattern=_r(
            r"(?i)(?:jwt|jsonwebtoken|token)\s*\.\s*(?:sign|verify|decode)\s*\(\s*"
            r"[A-Za-z_$\.\[\]]+\s*,\s*[\"'][^\"'\n]{3,}[\"']"
            r"|[\"']?(?:JWT_?SECRET|SECRET_?KEY|TOKEN_?SECRET)[\"']?\s*[:=]\s*[\"'][^\"'\n]{3,}[\"']"
        ),
        languages=(".js", ".ts", ".py", ".go", ".php", ".rb", ".env"),
        description=(
            "A literal signing secret is embedded in the code, so it is identical for every "
            "deployment and readable by anyone with the source."
        ),
        exploit=(
            "Sign arbitrary tokens offline with the leaked secret. Every token forged this way "
            "passes verification, including admin claims."
        ),
        breaker=(
            "None. Checkers present genuine tokens, so scoring is unaffected while teams mint "
            "valid identities for any user."
        ),
        remediation=(
            "Load the secret from the environment, rotate it, and reject tokens signed with "
            "anything but the current secret."
        ),
        cwe=("CWE-798", "CWE-321"),
        sources=(SOURCE_LOCAL,),
    ),
    Rule(
        id="AD-AUTH-005",
        category="AUTH_BYPASS",
        title="Optional authentication: the permission flag defaults to permissive",
        severity="high",
        pattern=_r(
            r"(?im)(?:let|var|const)\s+(?P<flag>\w*(?:is_?admin|is_?auth|authenticated|"
            r"authorized|is_?valid|allowed|permitted)\w*)\s*=\s*(?:false|0|null|undefined)\s*;"
            r"[\s\S]{0,400}?"
            r"(?:if\s*\(\s*\w*(?:token|auth|header|session|jwt)\w*\s*\)[\s\S]{0,200}?"
            r"\b(?P=flag)\s*=\s*true"
            r"|(?P=flag)\s*=\s*(?:decoded|payload|claims|jwt)\b)"
        ),
        languages=(".js", ".ts", ".py", ".go", ".php"),
        description=(
            "The handler starts with the permissive value and only upgrades to the restrictive "
            "one when a valid token happens to be present. A request without any credential "
            "therefore proceeds down the privileged path instead of being rejected."
        ),
        exploit=(
            "Send the request with no Authorization header. The flag stays at its default and "
            "the response is still produced."
        ),
        breaker=(
            "Usually none: checkers authenticate properly, so the permissive default only "
            "affects teams."
        ),
        remediation=(
            "Fail closed: return 401/403 unless the credential validated, and compute the "
            "permission once instead of defaulting it."
        ),
        cwe=("CWE-287", "CWE-636"),
        sources=(SOURCE_LOCAL,),
    ),
    Rule(
        id="AD-PRIV-003",
        category="PRIVILEGE_ESCALATION",
        title="Target user id taken from the request instead of the session",
        severity="critical",
        pattern=_r(r"(?:Where|where)\s*\(\s*[\"']?(?:login|id|username)[\"']?\s*,\s*"
                   r"\$?request->get\s*\(|\$request->get\s*\(\s*[\"']login"),
        languages=(".php", ".py", ".js", ".ts"),
        description=(
            "A sensitive mutation is applied to whichever account the request names "
            "rather than the caller. Password change on an arbitrary account is a "
            "full takeover primitive."
        ),
        exploit="Send another user's login in the same request as your session cookie.",
        breaker="None.",
        remediation="Derive the subject from the authenticated session only.",
        cwe=("CWE-639",),
        sources=(SOURCE_2019,),
    ),
    # ------------------------------------------------------------------ jwt
    Rule(
        id="AD-JWT-001",
        category="JWT_VERIFY_MISSING",
        title="JWT decoded without verifying the signature",
        severity="critical",
        pattern=_r(r"jwt\.decode\s*\(|\.decode\s*\(\s*[\"']HS256[\"']"),
        languages=(".js", ".ts", ".py"),
        must_not_contain=("jwt.verify", "verify_signature", "signature", "cert="),
        description=(
            "decode() only base64-parses the payload. Any team can mint an admin token "
            "without knowing the signing key."
        ),
        exploit="Craft a token with an elevated claim and replay it.",
        breaker="None.",
        remediation="Call verify() with the algorithm pinned explicitly.",
        cwe=("CWE-347", "CWE-345"),
        sources=(SOURCE_LOCAL,),
    ),
    # --------------------------------------------------------------- crypto
    Rule(
        id="AD-CRYPTO-001",
        category="WEAK_CRYPTO",
        title="Fast hash used as a password hash",
        severity="high",
        pattern=_r(r"(?i)\b(?:md5|sha1)\s*\(?\s*(?:new\s*\(\s*\))?\s*\)?\s*[.\w\]]*"
                   r"(?:password|passwd|pwd|pass)"),
        languages=(".py", ".go", ".js", ".ts", ".php"),
        description=(
            "Unsalted MD5/SHA1 password hashes are recoverable in bulk. A team that "
            "reads the database cracks every other team's password."
        ),
        exploit="Crack the harvested hashes offline.",
        breaker="None.",
        remediation="Use bcrypt/argon2/scrypt with a per-user salt.",
        cwe=("CWE-916", "CWE-327"),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-CRYPTO-002",
        category="WEAK_CRYPTO",
        title="Encoding or homebrew cipher used where confidentiality is claimed",
        severity="high",
        pattern=_r(r"(?i)\b(xor|arc4|rc4|base64|b64encode|codecs\.encode)\b[^\n]{0,40}"
                   r"\b(encrypt|decrypt|cipher|secret|password|passwd)\b"),
        languages=(".py", ".js", ".ts", ".go", ".php"),
        description=(
            "base64/XOR/RC4 provide no confidentiality. Any value the service believes "
            "is secret is recoverable by any participant."
        ),
        exploit="Decode the value; it is plaintext in disguise.",
        breaker="None.",
        remediation="Use authenticated encryption (AES-GCM/ChaCha20-Poly1305).",
        cwe=("CWE-327", "CWE-311"),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    Rule(
        id="AD-CRYPTO-003",
        category="WEAK_CRYPTO",
        title="Deterministic secret derived only from public data",
        severity="high",
        pattern=_r(r"(?i)(?:"
                   r"\.\s*(?:update|digest|hex|toString|encode)\s*\(\s*[^)\n]{0,40}"
                   r"(?:login|username|user_?name|email)"
                   r"|"
                   r"(?:md5|sha1|sha224|sha256|sha384|sha512|hash|digest)\s*\(\s*"
                   r"[^)\n]{0,24}?(?:login|username|user_?name|email)\s*\)"
                   r")"),
        languages=(".py", ".php", ".js", ".ts", ".go", ".rb"),
        description=(
            "Invites, slugs, dialog tokens or session keys computed from the login alone are "
            "guessable by anyone who knows the victim's username."
        ),
        exploit="Recompute the value for a known username and use it.",
        breaker=(
            "A predictable format is a prerequisite for the checker, which scrapes such values "
            "out of responses. Changing the format silently breaks the checker; leaking the "
            "value to teams does not."
        ),
        remediation="Issue unpredictable server-side random tokens.",
        cwe=("CWE-330", "CWE-640"),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    # ------------------------------------------------------------------ sqli
    Rule(
        id="AD-SQL-001",
        category="SQLI",
        title="SQL statement built by string formatting or concatenation",
        severity="critical",
        pattern=_r(
            r"(?im)(?:"
            # SQL keyword inside a literal that also holds a format placeholder.
            # `(?<![\w.])` keeps method calls such as `.update(` / `.insert(` out.
            r"(?<![\w.])(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]{0,220}?"
            r"(?:%[sdvq](?![a-z])|\$\{|\{\s*[A-Za-z_$][\w.]*\}?|\+\s*[A-Za-z_$][\w.]*\s*\+)"
            r"|"
            # Formatting call wrapping a SQL literal (Go, Java, PHP, C#).
            r"(?:fmt\.Sprintf|String\.Format|sprintf|\.format\s*\(|%\s*\(|f[\"'])"
            r"[^\n]{0,220}?(?<![\w.])(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b"
            r")"
        ),
        post="bound_sql",
        languages=(".py", ".go", ".js", ".ts", ".php", ".java", ".rb"),
        description=(
            "The statement is assembled from runtime values instead of bound parameters, so a "
            "team can read or rewrite any row."
        ),
        exploit="Boolean, UNION or time based injection in the interpolated value.",
        breaker=(
            "One malformed request from any participant can raise a fatal driver error and the "
            "instance stops scoring (IV.5)."
        ),
        remediation="Use parameterised queries exclusively; never interpolate.",
        cwe=("CWE-89",),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    Rule(
        id="AD-SQL-002",
        category="SQLI",
        title="Sphinx/full-text query passed through with an injection filter",
        severity="high",
        pattern=_r(r"(?is)(?:sc\.Query|SetFilter|SetGroupBy)\s*\([^)]*\bquery\b|"
                   r"RemoveSpecialChars|rmSpecialChars"),
        languages=(".go", ".py",),
        description=(
            "Strip-list sanitising of a search query is bypassable, and Sphinx's own "
            "syntax is often reachable through the same parameter."
        ),
        exploit="Use operators the strip-list does not remove.",
        breaker="Malformed expressions can raise fatal errors server-side.",
        remediation="Parameterise and allow-list search syntax.",
        cwe=("CWE-89",),
        sources=(SOURCE_2019,),
    ),
    # ------------------------------------------------------------ injections
    Rule(
        id="AD-DESER-001",
        category="DESERIALIZATION",
        title="Unsafe deserialisation of user-controlled data",
        severity="critical",
        pattern=_r(r"yaml\.load\s*\((?![^)]*Safe)|pickle\.loads?\s*\(|"
                   r"ObjectInputStream|Marshal\.load|unserialize\s*\(\s*\$"),
        languages=(".py", ".php", ".java"),
        description="Arbitrary object construction leads to RCE inside the service container.",
        exploit="Send a crafted payload; gain code execution on the instance.",
        breaker="A crafted payload can kill the worker process (IV.5).",
        remediation="yaml.safe_load; never unpickle untrusted input.",
        cwe=("CWE-502",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-NOSQL-001",
        category="NOSQL_INJECTION",
        title="Request body used directly as a database query document",
        severity="high",
        pattern=_r(r"(?:find|findOne|find_one|update_one|delete_one)\s*\(\s*(?:req\.body|request\.json|"
                   r"params\.get|JSON\.parse|json\.loads)"),
        languages=(".js", ".ts", ".py"),
        description=(
            "Operator objects ($ne, $gt, $where) pass through untouched, so an "
            "authentication filter can be neutralised."
        ),
        exploit="Send {\"password\": {\"$ne\": null}}.",
        breaker="None.",
        remediation="Validate types field-by-field before querying.",
        cwe=("CWE-943",),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    Rule(
        id="AD-SSTI-001",
        category="TEMPLATE_INJECTION",
        title="Template source assembled from user input",
        severity="critical",
        pattern=_r(r"(?is)(?:template|render_template_string|Template)\s*\(\s*[^)\n]*"
                   r"(?:f[\"']|\"\s*\+\s*\w|\{\{)|render_template_string\s*\(\s*(?:f?[\"'])"),
        languages=(".py", ".php", ".go"),
        description="Server-side template injection yields code execution as the app user.",
        exploit="Submit {{7*7}} style payloads and read the evaluated result.",
        breaker="A crashing payload takes the instance down.",
        remediation="Never compile templates from request data.",
        cwe=("CWE-1336",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-XSS-001",
        category="XSS",
        title="Auto-escaping disabled or manual HTML concatenation",
        severity="medium",
        pattern=_r(r"(?i)autoescape\s*(?:=|:)\s*False|\|\s*safe\b|"
                   r"mark_safe\s*\(|\.innerHTML\s*=|v-html|dangerouslySetInnerHTML|"
                   r"template\.HTML\s*\(\s*(?:fmt\.|f[\"'])"),
        languages=(".py", ".js", ".ts", ".vue", ".php", ".go"),
        description=(
            "Stored XSS in a chat/profile surface executes in other teams' browsers "
            "inside the shared checker/jury UI."
        ),
        exploit="Post a payload that fires when a third party views the record.",
        breaker="Payloads that re-enter the checker's session can corrupt it.",
        remediation="Escape on output; avoid raw HTML sinks.",
        cwe=("CWE-79",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-PATH-001",
        category="PATH_TRAVERSAL",
        title="Filesystem path built from request data",
        severity="high",
        pattern=_r(r"(?:open|readFile|read_file|send_file|sendFile|file_get_contents|"
                   r"Path\(|\.join\s*\(|os\.path\.join)\s*\(?[^)\n]{0,80}"
                   r"(?:request|params|filename|file_?name|path\))"),
        languages=(".py", ".js", ".ts", ".php", ".go"),
        description="Directory escape lets a team read service source, flags on disk or /proc.",
        exploit="Use ../ sequences to escape the intended directory.",
        breaker="Accidental writes outside the tree corrupt the instance state.",
        remediation="Resolve and confine the path to an allow-listed root.",
        cwe=("CWE-22",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-SSRF-001",
        category="SSRF",
        title="Outbound request to a URL taken from the request",
        severity="high",
        pattern=_r(r"(?:requests\.(?:get|post)|http\.(?:Get|Post)|urlopen|axios\.\w+|"
                   r"fetch|WebClient\.DownloadString)\s*\(\s*[^)\n]{0,60}"
                   r"(?:request|params|body|json|url|target|host)"),
        languages=(".py", ".js", ".ts", ".php", ".go", ".cs"),
        description=(
            "Internal addresses are reachable: cloud metadata, the instance's database "
            "and the sibling containers become targets."
        ),
        exploit="Point the URL at 169.254.169.254 or the compose-internal DB host.",
        breaker="Hammering the DB stalls the instance.",
        remediation="Allow-list outbound destinations.",
        cwe=("CWE-918",),
        sources=(SOURCE_2019,),
    ),
    # ------------------------------------------------------- upload / files
    Rule(
        id="AD-UPLOAD-001",
        category="FILE_UPLOAD",
        title="Upload filename derived predictably from the client-supplied name",
        severity="high",
        pattern=_r(r"(?i)(?:newFileName|file_?name|target)\s*=\s*.*(?:md5|sha1|hash|basename)\s*\("),
        languages=(".py", ".php", ".js", ".ts"),
        description=(
            "md5(originalName) as the stored name makes every upload path "
            "predictable, so a team overwrites another team's avatar or post image."
        ),
        exploit="Upload under the same original filename to overwrite a victim's file.",
        breaker="Overwriting the checker's own asset breaks its read-back step.",
        remediation="Random server-side names, store outside the web root or serve via a handler.",
        cwe=("CWE-434", "CWE-73"),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-UPLOAD-002",
        category="FILE_UPLOAD",
        title="Upload stored inside the served document root",
        severity="high",
        pattern=_r(r"['\"]img/uploads['\"]|destinationPath\s*=\s*['\"][\w/]*uploads['\"]"),
        languages=(".py", ".php", ".js", ".ts"),
        description="Uploads become directly fetchable; combined with type confusion this is stored content injection.",
        exploit="Upload and then fetch the file back by its predictable path.",
        breaker="None.",
        remediation="Serve uploads through a controller with content-type and disposition control.",
        cwe=("CWE-434",),
        sources=(SOURCE_2019,),
    ),
    # ------------------------------------------------------------ data leaks
    Rule(
        id="AD-LEAK-001",
        category="INFO_LEAK",
        title="Debug flag or verbose error surface enabled",
        severity="medium",
        pattern=_r(r"DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|"
                   r"APP_DEBUG\s*=\s*true|display_errors\s*=\s*On|"
                   r"str\(err(?:or)?\)|traceback\.print_exc"),
        languages=(".py", ".php", ".env"),
        description="Stack traces and SQL fragments leak schema, paths and sometimes credentials.",
        exploit="Send malformed input and read the error body.",
        breaker="None.",
        remediation="Disable debug output in deployed configuration.",
        cwe=("CWE-209",),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    Rule(
        id="AD-LEAK-002",
        category="INFO_LEAK",
        title="Wildcard CORS on a state-changing or authenticated endpoint",
        severity="medium",
        pattern=_r(r"Access-Control-Allow-Origin['\"]?\s*[,:]\s*[\"']\*"),
        languages=(".py", ".go", ".js", ".ts", ".php"),
        description="Any origin may drive authenticated requests, widening cross-team attack surface.",
        exploit="Host a page that calls the instance with the victim's cookies.",
        breaker="None.",
        remediation="Reflect only trusted origins.",
        cwe=("CWE-942",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-LEAK-003",
        category="INFO_LEAK",
        title="Unscoped SELECT * returns credential-bearing rows",
        severity="high",
        pattern=_r(r"(?:User\.all\(\)|::all\(\)|\.all\(\)|SELECT \* FROM|\.find\(\{\s*\})"),
        languages=(".php", ".py", ".js", ".ts", ".go"),
        description="A listing endpoint without scoping hands over the whole user table in one request.",
        exploit="GET the listing and enumerate every team's data.",
        breaker="Large result sets can time the instance out.",
        remediation="Paginate and scope listings to the caller.",
        cwe=("CWE-200",),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    Rule(
        id="AD-LEAK-004",
        category="INFO_LEAK",
        title="Credentials hardcoded in image or config",
        severity="high",
        pattern=_r(r"(?i)(?:passwd|password|secret|apikey|api_key|token)\s*=\s*[\"'][^\"'\n]{4,}[\"']"),
        languages=(".py", ".go", ".js", ".ts", ".php", ".yml", ".yaml", ".env", ".json"),
        must_not_contain=("os.environ", "getenv", "process.env", "ENV[", "config("),
        description=(
            "Database or session credentials committed to the repository. Compose "
            "credentials also expose the datastore port to other participants."
        ),
        exploit="Connect to the datastore directly and read every team's rows.",
        breaker="None.",
        remediation="Inject secrets at deploy time; rotate anything ever committed.",
        cwe=("CWE-798", "CWE-312"),
        sources=(SOURCE_2019, SOURCE_LOCAL),
    ),
    Rule(
        id="AD-LEAK-005",
        category="INFO_LEAK",
        title="Private key or seed material shipped in the repository",
        severity="critical",
        pattern=_r(r"BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|APP_KEY\s*=\s*base64:|\bN\s*[:=]\s*\d{40,}"),
        languages=(".key", ".pem", ".env", ".py", ".json"),
        description="Published key material makes every signature/encryption step forgeable.",
        exploit="Derive keys and impersonate any user.",
        breaker="None.",
        remediation="Never commit key material; rotate immediately.",
        cwe=("CWE-321", "CWE-798"),
        sources=(SOURCE_2019,),
    ),
    # ------------------------------------------------------------ flag flow
    Rule(
        id="AD-FLAG-001",
        category="FLAG_EXPOSURE",
        title="Flag-shaped literal read from disk or database into a response",
        severity="high",
        pattern=_r(r"(?i)\bflag\b[^\n]{0,60}(?:open\(|read_text|select |findOne|find\(|\.get\(|"
                   r"res\.(?:send|write|json)|return\s+jsonify|response\.)"),
        languages=(".py", ".go", ".js", ".ts", ".php"),
        description="Direct flag read path; establish who can reach it and what authorisation guards it.",
        exploit="Follow the read path back to an unauthenticated or cross-team reachable sink.",
        breaker="Checker must keep seeing the flag after each round; audit caches here.",
        remediation="Guard every flag read with owner-scoped authorisation.",
        cwe=("CWE-200",),
        sources=(SOURCE_LOCAL, SOURCE_2018),
    ),
    Rule(
        id="AD-FLAG-002",
        category="FLAG_EXPOSURE",
        title="Flag path baked into the image/config",
        severity="medium",
        pattern=_r(r"(?i)FLAG_(?:PATH|FILE|DIR)\s*[=:]\s*[^\s\"']+|/flag(?:s)?[\"']?\s*[,)]"),
        languages=(".py", ".go", ".js", ".ts", ".php", ".yml", ".yaml", ".env", ".json"),
        description="Reveals where flags live; combined with traversal or file read it is directly abusable.",
        exploit="Traverse or request the revealed path.",
        breaker="None.",
        remediation="Keep the path unguessable and outside any served tree.",
        cwe=("CWE-548",),
        sources=(SOURCE_LOCAL,),
    ),
    Rule(
        id="AD-FLAG-003",
        category="FLAG_EXPOSURE",
        title="Cache layer on the flag read path",
        severity="medium",
        pattern=_r(r"(?:@cache|cached\(|Cache-Control|redis|memcache|lru_cache|apcu)"),
        languages=(".py", ".go", ".js", ".ts", ".php"),
        description=(
            "A shared cache in front of per-team flag reads can serve one team's flag "
            "to another, and staleness can break the checker's read-back (IV.5)."
        ),
        exploit="Replay a request whose cache key omits the team scope.",
        breaker="Stale cache breaks the old-flag read.",
        remediation="Key every cached entry by owner and invalidate on write.",
        cwe=("CWE-524",),
        sources=(SOURCE_2019,),
    ),
    # --------------------------------------------------------------- checker
    Rule(
        id="AD-CHK-001",
        category="CHECKER_BREAKING",
        title="Entity id only reachable by scraping a response",
        severity="medium",
        pattern=_r(r"(?i)re\.(?:findall|search|match|find)\s*\("),
        extensions=(".py",),
        description=(
            "Checkers in this series derive their own object id by regexing the "
            "registration response. Removing or renaming that fragment silently "
            "zeroes the score."
        ),
        exploit="N/A - this is a jury-side compatibility warning.",
        breaker=(
            "YES. Any response-shape change that drops the id fragment makes the "
            "checker abort at its first status report."
        ),
        remediation="Expose a stable, machine-readable id field (id/data-id/link) in the response.",
        cwe=("CWE-1188",),
        sources=(SOURCE_2018,),
    ),
    Rule(
        id="AD-CHK-002",
        category="CHECKER_BREAKING",
        title="Shared mutable state between requests (global/thread-local user context)",
        severity="high",
        pattern=_r(r"(?i)\bthreading\.local\b|\bg\s*=\s*flask\.g\b|@app\.context_processor|"
                   r"global\s+current_user|static\s+\w*(?:user|session|client)\w*"),
        languages=(".py", ".go", ".js", ".ts"),
        description=(
            "Cross-request state can leak one request's identity into another's "
            "response, which both leaks flags and corrupts checker sessions."
        ),
        exploit="Interleave your requests with the checker's to capture its context.",
        breaker="YES. The checker reads another team's data and reports a false negative.",
        remediation="Keep request state strictly per-request.",
        cwe=("CWE-362",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-CHK-003",
        category="CHECKER_BREAKING",
        title="Blocking or rate-limiting middleware on a checker-driven path",
        severity="medium",
        pattern=_r(r"(?i)rate_?limit|throttl|Limiter\s*\(|429|Too\s*Many\s*Requests"),
        languages=(".py", ".go", ".js", ".ts", ".php"),
        description=(
            "Checker traffic bursts. A limiter tuned for humans can 429 the checker "
            "and cost the jury points."
        ),
        exploit="N/A - jury-side.",
        breaker="YES if the limiter trips on the checker's burst pattern.",
        remediation="Exclude the checker network from limiting, or allow-list its bursts.",
        cwe=("CWE-770",),
        sources=(SOURCE_2018,),
    ),
    Rule(
        id="AD-CHK-004",
        category="CHECKER_BREAKING",
        title="Singleton/broken instance state between rounds",
        severity="medium",
        pattern=_r(r"(?i)memcached|singleton|static\s+(?:int|string|var)|"
                   r"OnceLock|sync\.Once|cache\.Set\("),
        languages=(".go", ".cs", ".php"),
        description=(
            "Checkers re-read last round's flag, so per-round state must persist "
            "across the full contest duration."
        ),
        exploit="N/A - jury-side.",
        breaker="YES. State evicted before the next round breaks the old-flag read.",
        remediation="Keep round-scoped state for the whole contest.",
        cwe=("CWE-459",),
        sources=(SOURCE_2018,),
    ),
    Rule(
        id="AD-CHK-005",
        category="CHECKER_BREAKING",
        title="Registration-time uniqueness constraint on a per-round value",
        severity="medium",
        pattern=_r(r"(?i)unique\s*(?:\(|:)\s*(?:true|1)|UNIQUE\s+(?:KEY|INDEX)|"
                   r"unique:users|unique\s*=\s*True"),
        languages=(".php", ".py", ".js", ".ts", ".sql", ".go"),
        description=(
            "If a checker-visible unique field collides between rounds (fixed login, "
            "fixed email, fixed slug) the second round cannot register."
        ),
        exploit="N/A - jury-side.",
        breaker="YES. Round N+1 registration fails outright.",
        remediation="Make the checker's random values part of the uniqueness scope.",
        cwe=("CWE-1023",),
        sources=(SOURCE_2018,),
    ),
    # --------------------------------------------------------------- generic
    Rule(
        id="AD-GEN-001",
        category="RATE_LIMIT_MISSING",
        title="No rate limiting / lockout on an authentication endpoint",
        severity="low",
        pattern=_r(r"(?i)(?:@module\.route|@app\.(?:route|post|get))\s*\([^)\n]*(?:login|signin|sign_in|auth)"),
        languages=(".py", ".php", ".go",),
        description="Allows credential stuffing against the checker-generated accounts.",
        exploit="Brute-force the checker's random username/password pair.",
        breaker="Brute force can lock the instance out of its own account.",
        remediation="Throttle per source address; do not permanently lock.",
        cwe=("CWE-307",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-GEN-002",
        category="OPEN_REDIRECT",
        title="Redirect target taken from the request",
        severity="low",
        pattern=_r(r"(?i)(?:redirect|sendRedirect|Location)\s*\(?[^)\n]{0,80}"
                   r"(?:request|params|query|referrer)"),
        languages=(".py", ".go", ".js", ".ts", ".php"),
        description="Phishing/credential-relay primitive; mostly noise for A/D but worth listing.",
        exploit="Craft a link that bounces participants to an attacker page.",
        breaker="None.",
        remediation="Validate redirect targets against an allow-list.",
        cwe=("CWE-601",),
        sources=(SOURCE_2019,),
    ),
    Rule(
        id="AD-GEN-003",
        category="MASS_ASSIGNMENT",
        title="Bulk model update from a request payload",
        severity="medium",
        pattern=_r(r"(?is)(?:update|save|create|insert)\s*\(\s*(?:\*\*|Object\.assign|"
                   r"req\.body|request\.(?:form|json|args))"),
        languages=(".js", ".ts", ".py"),
        description="Lets a team set fields the UI never exposes, including privilege fields.",
        exploit="Include extra keys in the JSON body.",
        breaker="None.",
        remediation="Assign an explicit field allow-list.",
        cwe=("CWE-915",),
        sources=(SOURCE_2019,),
    ),
]

RULES_BY_ID = {rule.id: rule for rule in RULES}

CATEGORIES: dict[str, str] = {}
for _rule in RULES:
    CATEGORIES.setdefault(_rule.category, _rule.title)


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity, 0)