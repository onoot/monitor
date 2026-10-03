/**
 * Detection rule pack.
 *
 * Every rule is traceable to a concrete pattern observed either in the current
 * AltayCTF services or in the public SharLike-CTF-Team corpora
 * (AltayCTF-2017 / 2018 / 2019). The `sources` field records the evidence so a
 * reviewer can confirm the rule is not speculative.
 *
 * Two independent axes matter for an A/D jury:
 *
 *   exploit   how a competing team can abuse this against the *service owner*
 *   breaker   how this makes the *checker* fail and cost the jury points
 *             (AltayCTF 2026 rules IV.5 - do not break the service,
 *              IV.7 - flags and service availability)
 *
 * Porting note: Python's inline flag prefixes (`(?i)`, `(?im)`, `(?is)`) are
 * rejected by the JS engine, so each rule declares its flags separately. Named
 * groups use JS syntax (`(?<name>...)` / `\k<name>`).
 */

export const SEVERITY_ORDER: Record<string, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface Rule {
  id: string;
  category: string;
  title: string;
  severity: string;
  /** Pattern source without flags. */
  source: string;
  /** JS regex flags, e.g. 'i' or 'ims'. */
  flags: string;
  languages: readonly string[];
  extensions: readonly string[];
  mustContain: readonly string[];
  mustNotContain: readonly string[];
  /**
   * Name of a post-match validator in sast.ts. Lets a rule reject matches that
   * look dangerous but are actually safe, e.g. bound SQL parameters.
   */
  post: string;
  description: string;
  exploit: string;
  breaker: string;
  remediation: string;
  cwe: readonly string[];
  sources: readonly string[];

  appliesTo(suffix: string): boolean;
  /** Fresh, stateless matcher. Never share a `g`-flagged RegExp across files. */
  matcher(extra?: string): RegExp;
}

export interface RuleInit {
  id: string;
  category: string;
  title: string;
  severity: string;
  source: string;
  flags?: string;
  languages?: readonly string[];
  extensions?: readonly string[];
  mustContain?: readonly string[];
  mustNotContain?: readonly string[];
  post?: string;
  description?: string;
  exploit?: string;
  breaker?: string;
  remediation?: string;
  cwe?: readonly string[];
  sources?: readonly string[];
}

function rule(init: RuleInit): Rule {
  return {
    id: init.id,
    category: init.category,
    title: init.title,
    severity: init.severity,
    source: init.source,
    flags: init.flags ?? '',
    languages: init.languages ?? [],
    extensions: init.extensions ?? [],
    mustContain: init.mustContain ?? [],
    mustNotContain: init.mustNotContain ?? [],
    post: init.post ?? '',
    description: init.description ?? '',
    exploit: init.exploit ?? '',
    breaker: init.breaker ?? '',
    remediation: init.remediation ?? '',
    cwe: init.cwe ?? [],
    sources: init.sources ?? [],
    appliesTo(suffix: string): boolean {
      if (this.extensions.length > 0 && !this.extensions.some((ext) => suffix.endsWith(ext))) {
        return false;
      }
      if (this.languages.length > 0 && !this.languages.some((ext) => suffix.endsWith(ext))) {
        return false;
      }
      return true;
    },
    matcher(extra = ''): RegExp {
      const flags = new Set(`${this.flags}${extra}`.split(''));
      flags.delete('g');
      flags.add('g');
      return new RegExp(this.source, [...flags].join(''));
    },
  };
}

export const SOURCE_LOCAL = 'local:AltayCoin/Curs/Magiclib/Omnyhub';
export const SOURCE_2019 = 'corpus:altayctf-2019';
export const SOURCE_2018 = 'corpus:AltayCTF-2018 checkers';

export const RULES: readonly Rule[] = [
  // ----------------------------------------------------------------- auth
  rule({
    id: 'AD-AUTH-001',
    category: 'AUTH_BYPASS',
    title: 'Password/secret never verified on a privileged path',
    severity: 'critical',
    source:
      String.raw`\b(pass(word)?|secret|token)\s*(==|!=|===|!==)\s*['"]{2}`,
    flags: 'i',
    languages: ['.py', '.js', '.ts', '.php', '.go', '.rb'],
    description:
      'A comparison against an empty literal, or the absence of any credential ' +
      'check on a handler that returns protected data, lets an unauthenticated ' +
      'team read another team\'s data.',
    exploit: 'Call the endpoint without credentials, or with an empty password.',
    breaker: 'None. The checker keeps working; the service owner silently leaks data.',
    remediation: 'Verify the credential server-side on every protected handler.',
    cwe: ['CWE-287', 'CWE-306'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-AUTH-002',
    category: 'AUTH_BYPASS',
    title: 'Handler declares no authentication requirement',
    severity: 'medium',
    source: String.raw`@(?:app|module|bp|router)\.(?:route|get|post|put|delete|patch)\b`,
    languages: ['.py', '.php', '.go', '.rb'],
    mustNotContain: [
      'login_required',
      'auth_required',
      '@permission',
      "middleware('auth')",
    ],
    description:
      'Route registration with no adjacent authentication decorator/middleware. ' +
      'Static hints only - must be confirmed at runtime.',
    exploit: 'Fetch the route unauthenticated.',
    breaker: 'None directly.',
    remediation: 'Apply an auth decorator/middleware to every non-public route.',
    cwe: ['CWE-306'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-AUTH-003',
    category: 'AUTH_BYPASS',
    title: 'Session/cookie store key hardcoded',
    severity: 'high',
    source: String.raw`(?:NewCookieStore|CookieStore|cookieSecret|SESSION_SECRET|SECRET_KEY)\s*\(?\s*\[?\s*["'][^"'\n]{4,}["']`,
    languages: ['.py', '.go', '.js', '.ts', '.php', '.env'],
    description:
      'A static signing key lets a team forge session cookies for arbitrary ' +
      'user ids, escalating privileges across the whole instance.',
    exploit: "Forge a session cookie carrying another user's id.",
    breaker: 'None for the checker, which uses real credentials.',
    remediation: 'Load the secret from the environment, rotate per deployment.',
    cwe: ['CWE-798', 'CWE-347'],
    sources: [SOURCE_2019],
  }),
  // ------------------------------------------------------- privilege / IDOR
  rule({
    id: 'AD-IDOR-001',
    category: 'IDOR',
    title: 'Object id taken from the request and used without ownership check',
    severity: 'high',
    source: String.raw`(?:findOrFail|find|get|select|find_by|objects)\s*\(\s*\$?\(?(?:request|id|params|user_id)`,
    languages: ['.py', '.php', '.js', '.ts', '.go'],
    description:
      'Entity lookup keyed directly on a client-supplied identifier. When the ' +
      'lookup is not intersected with the authenticated principal it becomes ' +
      'horizontal privilege escalation over another team\'s records.',
    exploit: "Swap the id in the URL/body for a victim's id.",
    breaker: 'None.',
    remediation: 'Scope every lookup by the authenticated owner id.',
    cwe: ['CWE-639', 'CWE-862'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-PRIV-001',
    category: 'PRIVILEGE_ESCALATION',
    title: 'Role / permission supplied by the client at registration or update',
    severity: 'critical',
    source: String.raw`\b(role|permission|isAdmin|is_admin|level|lvl|access)\s*(?:=|:)\s*(?:request|params|_GET|_POST|body|data|json|req)\b`,
    flags: 'i',
    languages: ['.py', '.php', '.js', '.ts', '.go'],
    description:
      'Privileged attributes are read straight from the request. A team that ' +
      'registers with an elevated role immediately owns the instance.',
    exploit: 'Register or update the profile sending role/permission=1.',
    breaker: 'None.',
    remediation: 'Ignore client-supplied privileged fields; derive them server-side.',
    cwe: ['CWE-269', 'CWE-915'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-PRIV-002',
    category: 'PRIVILEGE_ESCALATION',
    title: 'Authorisation decided from a client-controlled value',
    severity: 'high',
    source: String.raw`if\s*\(\s*['"]?(?:role|isAdmin|is_admin|permission|level)['"]?\s*(?:===|==|!=)\s*(?:['"]?(?:request|session|cookie|jwt|payload|token))`,
    flags: 'i',
    languages: ['.js', '.ts', '.py', '.php'],
    description:
      'A decoded token/session field decides access without a signature check.',
    exploit: 'Craft a token whose privilege claim is elevated.',
    breaker: 'None.',
    remediation: 'Verify the signature server-side before trusting any claim.',
    cwe: ['CWE-863'],
    sources: [SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-PRIV-004',
    category: 'PRIVILEGE_ESCALATION',
    title: 'Privilege flag copied straight out of an unverified token',
    severity: 'critical',
    source: String.raw`(?:is_?admin|isAdmin|role|permission|level|lvl|admin)\s*[:=]\s*(?:bool(?:ean)?\s*\(\s*)?(?:[A-Za-z_$\.]*\.)?(?:decoded|payload|claims|token|jwt|req\.auth|request\.auth)\b`,
    flags: 'i',
    languages: ['.js', '.ts', '.py', '.php', '.go'],
    description:
      "An administrative flag is taken from the request's own token payload. Combined with " +
      'a decode-only token check this is a full account takeover primitive: no secret is ' +
      'needed, only the ability to base64 a claim.',
    exploit:
      'Take any valid token, edit the isAdmin/role claim, re-base64 the payload and replay ' +
      'the request with the forged token.',
    breaker:
      'None. The checker uses tokens minted by the service, so it keeps working while teams ' +
      'escalate freely.',
    remediation:
      'Verify the signature and read privileges from the server-side user record, never ' +
      'from client-supplied token contents.',
    cwe: ['CWE-863', 'CWE-345'],
    sources: [SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-JWT-002',
    category: 'CRYPTOGRAPHY',
    title: 'Hardcoded JWT signing secret in the repository',
    severity: 'critical',
    source: String.raw`(?:jwt|jsonwebtoken|token)\s*\.\s*(?:sign|verify|decode)\s*\(\s*[A-Za-z_$\.\[\]]+\s*,\s*["'][^"'\n]{3,}["']|["']?(?:JWT_?SECRET|SECRET_?KEY|TOKEN_?SECRET)["']?\s*[:=]\s*["'][^"'\n]{3,}["']`,
    flags: 'i',
    languages: ['.js', '.ts', '.py', '.go', '.php', '.rb', '.env'],
    description:
      'A literal signing secret is embedded in the code, so it is identical for every ' +
      'deployment and readable by anyone with the source.',
    exploit:
      'Sign arbitrary tokens offline with the leaked secret. Every token forged this way ' +
      'passes verification, including admin claims.',
    breaker:
      'None. Checkers present genuine tokens, so scoring is unaffected while teams mint ' +
      'valid identities for any user.',
    remediation:
      'Load the secret from the environment, rotate it, and reject tokens signed with ' +
      'anything but the current secret.',
    cwe: ['CWE-798', 'CWE-321'],
    sources: [SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-AUTH-005',
    category: 'AUTH_BYPASS',
    title: 'Optional authentication: the permission flag defaults to permissive',
    severity: 'high',
    source: String.raw`(?:let|var|const)\s+(?<flag>\w*(?:is_?admin|is_?auth|authenticated|authorized|is_?valid|allowed|permitted)\w*)\s*=\s*(?:false|0|null|undefined)\s*;[\s\S]{0,400}?(?:if\s*\(\s*\w*(?:token|auth|header|session|jwt)\w*\s*\)[\s\S]{0,200}?\b\k<flag>\s*=\s*true|\k<flag>\s*=\s*(?:decoded|payload|claims|jwt)\b)`,
    flags: 'im',
    languages: ['.js', '.ts', '.py', '.go', '.php'],
    description:
      'The handler starts with the permissive value and only upgrades to the restrictive ' +
      'one when a valid token happens to be present. A request without any credential ' +
      'therefore proceeds down the privileged path instead of being rejected.',
    exploit:
      'Send the request with no Authorization header. The flag stays at its default and ' +
      'the response is still produced.',
    breaker:
      'Usually none: checkers authenticate properly, so the permissive default only ' +
      'affects teams.',
    remediation:
      'Fail closed: return 401/403 unless the credential validated, and compute the ' +
      'permission once instead of defaulting it.',
    cwe: ['CWE-287', 'CWE-636'],
    sources: [SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-PRIV-003',
    category: 'PRIVILEGE_ESCALATION',
    title: 'Target user id taken from the request instead of the session',
    severity: 'critical',
    source: String.raw`(?:Where|where)\s*\(\s*["']?(?:login|id|username)["']?\s*,\s*\$?request->get\s*\(|\$request->get\s*\(\s*["']login`,
    languages: ['.php', '.py', '.js', '.ts'],
    description:
      'A sensitive mutation is applied to whichever account the request names ' +
      'rather than the caller. Password change on an arbitrary account is a ' +
      'full takeover primitive.',
    exploit: "Send another user's login in the same request as your session cookie.",
    breaker: 'None.',
    remediation: 'Derive the subject from the authenticated session only.',
    cwe: ['CWE-639'],
    sources: [SOURCE_2019],
  }),
  // ------------------------------------------------------------------ jwt
  rule({
    id: 'AD-JWT-001',
    category: 'JWT_VERIFY_MISSING',
    title: 'JWT decoded without verifying the signature',
    severity: 'critical',
    source: String.raw`jwt\.decode\s*\(|\.decode\s*\(\s*["']HS256["']`,
    languages: ['.js', '.ts', '.py'],
    mustNotContain: ['jwt.verify', 'verify_signature', 'signature', 'cert='],
    description:
      'decode() only base64-parses the payload. Any team can mint an admin token ' +
      'without knowing the signing key.',
    exploit: 'Craft a token with an elevated claim and replay it.',
    breaker: 'None.',
    remediation: 'Call verify() with the algorithm pinned explicitly.',
    cwe: ['CWE-347', 'CWE-345'],
    sources: [SOURCE_LOCAL],
  }),
  // --------------------------------------------------------------- crypto
  rule({
    id: 'AD-CRYPTO-001',
    category: 'WEAK_CRYPTO',
    title: 'Fast hash used as a password hash',
    severity: 'high',
    source: String.raw`\b(?:md5|sha1)\s*\(?\s*(?:new\s*\(\s*\))?\s*\)?\s*[.\w\]]*(?:password|passwd|pwd|pass)`,
    flags: 'i',
    languages: ['.py', '.go', '.js', '.ts', '.php'],
    description:
      'Unsalted MD5/SHA1 password hashes are recoverable in bulk. A team that ' +
      'reads the database cracks every other team\'s password.',
    exploit: 'Crack the harvested hashes offline.',
    breaker: 'None.',
    remediation: 'Use bcrypt/argon2/scrypt with a per-user salt.',
    cwe: ['CWE-916', 'CWE-327'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-CRYPTO-002',
    category: 'WEAK_CRYPTO',
    title: 'Encoding or homebrew cipher used where confidentiality is claimed',
    severity: 'high',
    source: String.raw`\b(xor|arc4|rc4|base64|b64encode|codecs\.encode)\b[^\n]{0,40}\b(encrypt|decrypt|cipher|secret|password|passwd)\b`,
    flags: 'i',
    languages: ['.py', '.js', '.ts', '.go', '.php'],
    description:
      'base64/XOR/RC4 provide no confidentiality. Any value the service believes ' +
      'is secret is recoverable by any participant.',
    exploit: 'Decode the value; it is plaintext in disguise.',
    breaker: 'None.',
    remediation: 'Use authenticated encryption (AES-GCM/ChaCha20-Poly1305).',
    cwe: ['CWE-327', 'CWE-311'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-CRYPTO-003',
    category: 'WEAK_CRYPTO',
    title: 'Deterministic secret derived only from public data',
    severity: 'high',
    source: String.raw`(?:\.\s*(?:update|digest|hex|toString|encode)\s*\(\s*[^)\n]{0,40}(?:login|username|user_?name|email)|(?:md5|sha1|sha224|sha256|sha384|sha512|hash|digest)\s*\(\s*[^)\n]{0,24}?(?:login|username|user_?name|email)\s*\))`,
    flags: 'i',
    languages: ['.py', '.php', '.js', '.ts', '.go', '.rb'],
    description:
      'Invites, slugs, dialog tokens or session keys computed from the login alone are ' +
      'guessable by anyone who knows the victim\'s username.',
    exploit: 'Recompute the value for a known username and use it.',
    breaker:
      'A predictable format is a prerequisite for the checker, which scrapes such values ' +
      'out of responses. Changing the format silently breaks the checker; leaking the ' +
      'value to teams does not.',
    remediation: 'Issue unpredictable server-side random tokens.',
    cwe: ['CWE-330', 'CWE-640'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  // ------------------------------------------------------------------ sqli
  rule({
    id: 'AD-SQL-001',
    category: 'SQLI',
    title: 'SQL statement built by string formatting or concatenation',
    severity: 'critical',
    source: String.raw`(?:(?<![\w.])(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b[^\n]{0,220}?(?:%[sdvq](?![a-z])|\$\{|\{\s*[A-Za-z_$][\w.]*\}?|\+\s*[A-Za-z_$][\w.]*\s*\+)|(?:fmt\.Sprintf|String\.Format|sprintf|\.format\s*\(|%\s*\(|f["'])[^\n]{0,220}?(?<![\w.])(?:SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM)\b)`,
    flags: 'im',
    post: 'bound_sql',
    languages: ['.py', '.go', '.js', '.ts', '.php', '.java', '.rb'],
    description:
      'The statement is assembled from runtime values instead of bound parameters, so a ' +
      'team can read or rewrite any row.',
    exploit: 'Boolean, UNION or time based injection in the interpolated value.',
    breaker:
      'One malformed request from any participant can raise a fatal driver error and the ' +
      'instance stops scoring (IV.5).',
    remediation: 'Use parameterised queries exclusively; never interpolate.',
    cwe: ['CWE-89'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-SQL-002',
    category: 'SQLI',
    title: 'Sphinx/full-text query passed through with an injection filter',
    severity: 'high',
    source: String.raw`(?:sc\.Query|SetFilter|SetGroupBy)\s*\([^)]*\bquery\b|RemoveSpecialChars|rmSpecialChars`,
    flags: 'is',
    languages: ['.go', '.py'],
    description:
      'Strip-list sanitising of a search query is bypassable, and Sphinx\'s own ' +
      'syntax is often reachable through the same parameter.',
    exploit: 'Use operators the strip-list does not remove.',
    breaker: 'Malformed expressions can raise fatal errors server-side.',
    remediation: 'Parameterise and allow-list search syntax.',
    cwe: ['CWE-89'],
    sources: [SOURCE_2019],
  }),
  // ------------------------------------------------------------ injections
  rule({
    id: 'AD-DESER-001',
    category: 'DESERIALIZATION',
    title: 'Unsafe deserialisation of user-controlled data',
    severity: 'critical',
    source: String.raw`yaml\.load\s*\((?![^)]*Safe)|pickle\.loads?\s*\(|ObjectInputStream|Marshal\.load|unserialize\s*\(\s*\$`,
    languages: ['.py', '.php', '.java'],
    description:
      'Arbitrary object construction leads to RCE inside the service container.',
    exploit: 'Send a crafted payload; gain code execution on the instance.',
    breaker: 'A crafted payload can kill the worker process (IV.5).',
    remediation: 'yaml.safe_load; never unpickle untrusted input.',
    cwe: ['CWE-502'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-NOSQL-001',
    category: 'NOSQL_INJECTION',
    title: 'Request body used directly as a database query document',
    severity: 'high',
    source: String.raw`(?:find|findOne|find_one|update_one|delete_one)\s*\(\s*(?:req\.body|request\.json|params\.get|JSON\.parse|json\.loads)`,
    languages: ['.js', '.ts', '.py'],
    description:
      'Operator objects ($ne, $gt, $where) pass through untouched, so an ' +
      'authentication filter can be neutralised.',
    exploit: 'Send {"password": {"$ne": null}}.',
    breaker: 'None.',
    remediation: 'Validate types field-by-field before querying.',
    cwe: ['CWE-943'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-SSTI-001',
    category: 'TEMPLATE_INJECTION',
    title: 'Template source assembled from user input',
    severity: 'critical',
    source: String.raw`(?:template|render_template_string|Template)\s*\(\s*[^)\n]*(?:f["']|"\s*\+\s*\w|\{\{)|render_template_string\s*\(\s*(?:f?["'])`,
    flags: 'is',
    languages: ['.py', '.php', '.go'],
    description:
      'Server-side template injection yields code execution as the app user.',
    exploit: 'Submit {{7*7}} style payloads and read the evaluated result.',
    breaker: 'A crashing payload takes the instance down.',
    remediation: 'Never compile templates from request data.',
    cwe: ['CWE-1336'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-XSS-001',
    category: 'XSS',
    title: 'Auto-escaping disabled or manual HTML concatenation',
    severity: 'medium',
    source: String.raw`autoescape\s*(?:=|:)\s*False|\|\s*safe\b|mark_safe\s*\(|\.innerHTML\s*=|v-html|dangerouslySetInnerHTML|template\.HTML\s*\(\s*(?:fmt\.|f["'])`,
    flags: 'i',
    languages: ['.py', '.js', '.ts', '.vue', '.php', '.go'],
    description:
      'Stored XSS in a chat/profile surface executes in other teams\' browsers ' +
      'inside the shared checker/jury UI.',
    exploit: 'Post a payload that fires when a third party views the record.',
    breaker: "Payloads that re-enter the checker's session can corrupt it.",
    remediation: 'Escape on output; avoid raw HTML sinks.',
    cwe: ['CWE-79'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-PATH-001',
    category: 'PATH_TRAVERSAL',
    title: 'Filesystem path built from request data',
    severity: 'high',
    source: String.raw`(?:open|readFile|read_file|send_file|sendFile|file_get_contents|Path\(|\.join\s*\(|os\.path\.join)\s*\(?[^)\n]{0,80}(?:request|params|filename|file_?name|path\))`,
    languages: ['.py', '.js', '.ts', '.php', '.go'],
    description:
      'Directory escape lets a team read service source, flags on disk or /proc.',
    exploit: 'Use ../ sequences to escape the intended directory.',
    breaker: 'Accidental writes outside the tree corrupt the instance state.',
    remediation: 'Resolve and confine the path to an allow-listed root.',
    cwe: ['CWE-22'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-SSRF-001',
    category: 'SSRF',
    title: 'Outbound request to a URL taken from the request',
    severity: 'high',
    source: String.raw`(?:requests\.(?:get|post)|http\.(?:Get|Post)|urlopen|axios\.\w+|fetch|WebClient\.DownloadString)\s*\(\s*[^)\n]{0,60}(?:request|params|body|json|url|target|host)`,
    languages: ['.py', '.js', '.ts', '.php', '.go', '.cs'],
    description:
      'Internal addresses are reachable: cloud metadata, the instance\'s database ' +
      'and the sibling containers become targets.',
    exploit: 'Point the URL at 169.254.169.254 or the compose-internal DB host.',
    breaker: 'Hammering the DB stalls the instance.',
    remediation: 'Allow-list outbound destinations.',
    cwe: ['CWE-918'],
    sources: [SOURCE_2019],
  }),
  // ------------------------------------------------------- upload / files
  rule({
    id: 'AD-UPLOAD-001',
    category: 'FILE_UPLOAD',
    title: 'Upload filename derived predictably from the client-supplied name',
    severity: 'high',
    source: String.raw`(?:newFileName|file_?name|target)\s*=\s*.*(?:md5|sha1|hash|basename)\s*\(`,
    flags: 'i',
    languages: ['.py', '.php', '.js', '.ts'],
    description:
      'md5(originalName) as the stored name makes every upload path ' +
      'predictable, so a team overwrites another team\'s avatar or post image.',
    exploit: "Upload under the same original filename to overwrite a victim's file.",
    breaker: "Overwriting the checker's own asset breaks its read-back step.",
    remediation:
      'Random server-side names, store outside the web root or serve via a handler.',
    cwe: ['CWE-434', 'CWE-73'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-UPLOAD-002',
    category: 'FILE_UPLOAD',
    title: 'Upload stored inside the served document root',
    severity: 'high',
    source: String.raw`['"]img/uploads['"]|destinationPath\s*=\s*['"][\w/]*uploads['"]`,
    languages: ['.py', '.php', '.js', '.ts'],
    description:
      'Uploads become directly fetchable; combined with type confusion this is stored content injection.',
    exploit: 'Upload and then fetch the file back by its predictable path.',
    breaker: 'None.',
    remediation:
      'Serve uploads through a controller with content-type and disposition control.',
    cwe: ['CWE-434'],
    sources: [SOURCE_2019],
  }),
  // ------------------------------------------------------------ data leaks
  rule({
    id: 'AD-LEAK-001',
    category: 'INFO_LEAK',
    title: 'Debug flag or verbose error surface enabled',
    severity: 'medium',
    source: String.raw`DEBUG\s*=\s*True|app\.run\([^)]*debug\s*=\s*True|APP_DEBUG\s*=\s*true|display_errors\s*=\s*On|str\(err(?:or)?\)|traceback\.print_exc`,
    languages: ['.py', '.php', '.env'],
    description:
      'Stack traces and SQL fragments leak schema, paths and sometimes credentials.',
    exploit: 'Send malformed input and read the error body.',
    breaker: 'None.',
    remediation: 'Disable debug output in deployed configuration.',
    cwe: ['CWE-209'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-LEAK-002',
    category: 'INFO_LEAK',
    title: 'Wildcard CORS on a state-changing or authenticated endpoint',
    severity: 'medium',
    source: String.raw`Access-Control-Allow-Origin['"]?\s*[,:]\s*["']\*`,
    languages: ['.py', '.go', '.js', '.ts', '.php'],
    description:
      'Any origin may drive authenticated requests, widening cross-team attack surface.',
    exploit: "Host a page that calls the instance with the victim's cookies.",
    breaker: 'None.',
    remediation: 'Reflect only trusted origins.',
    cwe: ['CWE-942'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-LEAK-003',
    category: 'INFO_LEAK',
    title: 'Unscoped SELECT * returns credential-bearing rows',
    severity: 'high',
    source: String.raw`(?:User\.all\(\)|::all\(\)|\.all\(\)|SELECT \* FROM|\.find\(\{\s*\})`,
    languages: ['.php', '.py', '.js', '.ts', '.go'],
    description:
      "A listing endpoint without scoping hands over the whole user table in one request.",
    exploit: "GET the listing and enumerate every team's data.",
    breaker: 'Large result sets can time the instance out.',
    remediation: 'Paginate and scope listings to the caller.',
    cwe: ['CWE-200'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-LEAK-004',
    category: 'INFO_LEAK',
    title: 'Credentials hardcoded in image or config',
    severity: 'high',
    source: String.raw`(?:passwd|password|secret|apikey|api_key|token)\s*=\s*["'][^"'\n]{4,}["']`,
    flags: 'i',
    languages: [
      '.py',
      '.go',
      '.js',
      '.ts',
      '.php',
      '.yml',
      '.yaml',
      '.env',
      '.json',
    ],
    mustNotContain: ['os.environ', 'getenv', 'process.env', 'ENV[', 'config('],
    description:
      'Database or session credentials committed to the repository. Compose ' +
      'credentials also expose the datastore port to other participants.',
    exploit: 'Connect to the datastore directly and read every team\'s rows.',
    breaker: 'None.',
    remediation: 'Inject secrets at deploy time; rotate anything ever committed.',
    cwe: ['CWE-798', 'CWE-312'],
    sources: [SOURCE_2019, SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-LEAK-005',
    category: 'INFO_LEAK',
    title: 'Private key or seed material shipped in the repository',
    severity: 'critical',
    source: String.raw`BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY|APP_KEY\s*=\s*base64:|\bN\s*[:=]\s*\d{40,}`,
    languages: ['.key', '.pem', '.env', '.py', '.json'],
    description:
      'Published key material makes every signature/encryption step forgeable.',
    exploit: 'Derive keys and impersonate any user.',
    breaker: 'None.',
    remediation: 'Never commit key material; rotate immediately.',
    cwe: ['CWE-321', 'CWE-798'],
    sources: [SOURCE_2019],
  }),
  // ------------------------------------------------------------ flag flow
  rule({
    id: 'AD-FLAG-001',
    category: 'FLAG_EXPOSURE',
    title: 'Flag-shaped literal read from disk or database into a response',
    severity: 'high',
    source: String.raw`\bflag\b[^\n]{0,60}(?:open\(|read_text|select |findOne|find\(|\.get\(|res\.(?:send|write|json)|return\s+jsonify|response\.)`,
    flags: 'i',
    languages: ['.py', '.go', '.js', '.ts', '.php'],
    description:
      'Direct flag read path; establish who can reach it and what authorisation guards it.',
    exploit:
      'Follow the read path back to an unauthenticated or cross-team reachable sink.',
    breaker: 'Checker must keep seeing the flag after each round; audit caches here.',
    remediation: 'Guard every flag read with owner-scoped authorisation.',
    cwe: ['CWE-200'],
    sources: [SOURCE_LOCAL, SOURCE_2018],
  }),
  rule({
    id: 'AD-FLAG-002',
    category: 'FLAG_EXPOSURE',
    title: 'Flag path baked into the image/config',
    severity: 'medium',
    source: String.raw`FLAG_(?:PATH|FILE|DIR)\s*[=:]\s*[^\s"']+|/flag(?:s)?["']?\s*[,)]`,
    flags: 'i',
    languages: ['.py', '.go', '.js', '.ts', '.php', '.yml', '.yaml', '.env', '.json'],
    description:
      'Reveals where flags live; combined with traversal or file read it is directly abusable.',
    exploit: 'Traverse or request the revealed path.',
    breaker: 'None.',
    remediation: 'Keep the path unguessable and outside any served tree.',
    cwe: ['CWE-548'],
    sources: [SOURCE_LOCAL],
  }),
  rule({
    id: 'AD-FLAG-003',
    category: 'FLAG_EXPOSURE',
    title: 'Cache layer on the flag read path',
    severity: 'medium',
    source: String.raw`(?:@cache|cached\(|Cache-Control|redis|memcache|lru_cache|apcu)`,
    languages: ['.py', '.go', '.js', '.ts', '.php'],
    description:
      'A shared cache in front of per-team flag reads can serve one team\'s flag ' +
      'to another, and staleness can break the checker\'s read-back (IV.5).',
    exploit: 'Replay a request whose cache key omits the team scope.',
    breaker: 'Stale cache breaks the old-flag read.',
    remediation: 'Key every cached entry by owner and invalidate on write.',
    cwe: ['CWE-524'],
    sources: [SOURCE_2019],
  }),
  // --------------------------------------------------------------- checker
  rule({
    id: 'AD-CHK-001',
    category: 'CHECKER_BREAKING',
    title: 'Entity id only reachable by scraping a response',
    severity: 'medium',
    source: String.raw`re\.(?:findall|search|match|find)\s*\(`,
    flags: 'i',
    extensions: ['.py'],
    description:
      'Checkers in this series derive their own object id by regexing the ' +
      'registration response. Removing or renaming that fragment silently ' +
      'zeroes the score.',
    exploit: 'N/A - this is a jury-side compatibility warning.',
    breaker:
      'YES. Any response-shape change that drops the id fragment makes the ' +
      'checker abort at its first status report.',
    remediation:
      'Expose a stable, machine-readable id field (id/data-id/link) in the response.',
    cwe: ['CWE-1188'],
    sources: [SOURCE_2018],
  }),
  rule({
    id: 'AD-CHK-002',
    category: 'CHECKER_BREAKING',
    title: 'Shared mutable state between requests (global/thread-local user context)',
    severity: 'high',
    source: String.raw`\bthreading\.local\b|\bg\s*=\s*flask\.g\b|@app\.context_processor|global\s+current_user|static\s+\w*(?:user|session|client)\w*`,
    flags: 'i',
    languages: ['.py', '.go', '.js', '.ts'],
    description:
      "Cross-request state can leak one request's identity into another's " +
      "response, which both leaks flags and corrupts checker sessions.",
    exploit: "Interleave your requests with the checker's to capture its context.",
    breaker: 'YES. The checker reads another team\'s data and reports a false negative.',
    remediation: 'Keep request state strictly per-request.',
    cwe: ['CWE-362'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-CHK-003',
    category: 'CHECKER_BREAKING',
    title: 'Blocking or rate-limiting middleware on a checker-driven path',
    severity: 'medium',
    source: String.raw`rate_?limit|throttl|Limiter\s*\(|429|Too\s*Many\s*Requests`,
    flags: 'i',
    languages: ['.py', '.go', '.js', '.ts', '.php'],
    description:
      'Checker traffic bursts. A limiter tuned for humans can 429 the checker ' +
      'and cost the jury points.',
    exploit: 'N/A - jury-side.',
    breaker: 'YES if the limiter trips on the checker\'s burst pattern.',
    remediation:
      'Exclude the checker network from limiting, or allow-list its bursts.',
    cwe: ['CWE-770'],
    sources: [SOURCE_2018],
  }),
  rule({
    id: 'AD-CHK-004',
    category: 'CHECKER_BREAKING',
    title: 'Singleton/broken instance state between rounds',
    severity: 'medium',
    source: String.raw`memcached|singleton|static\s+(?:int|string|var)|OnceLock|sync\.Once|cache\.Set\(`,
    flags: 'i',
    languages: ['.go', '.cs', '.php'],
    description:
      "Checkers re-read last round's flag, so per-round state must persist " +
      'across the full contest duration.',
    exploit: 'N/A - jury-side.',
    breaker: 'YES. State evicted before the next round breaks the old-flag read.',
    remediation: 'Keep round-scoped state for the whole contest.',
    cwe: ['CWE-459'],
    sources: [SOURCE_2018],
  }),
  rule({
    id: 'AD-CHK-005',
    category: 'CHECKER_BREAKING',
    title: 'Registration-time uniqueness constraint on a per-round value',
    severity: 'medium',
    source: String.raw`unique\s*(?:\(|:)\s*(?:true|1)|UNIQUE\s+(?:KEY|INDEX)|unique:users|unique\s*=\s*True`,
    flags: 'i',
    languages: ['.php', '.py', '.js', '.ts', '.sql', '.go'],
    description:
      'If a checker-visible unique field collides between rounds (fixed login, ' +
      'fixed email, fixed slug) the second round cannot register.',
    exploit: 'N/A - jury-side.',
    breaker: 'YES. Round N+1 registration fails outright.',
    remediation: "Make the checker's random values part of the uniqueness scope.",
    cwe: ['CWE-1023'],
    sources: [SOURCE_2018],
  }),
  // --------------------------------------------------------------- generic
  rule({
    id: 'AD-GEN-001',
    category: 'RATE_LIMIT_MISSING',
    title: 'No rate limiting / lockout on an authentication endpoint',
    severity: 'low',
    source: String.raw`(?:@module\.route|@app\.(?:route|post|get))\s*\([^)\n]*(?:login|signin|sign_in|auth)`,
    flags: 'i',
    languages: ['.py', '.php', '.go'],
    description:
      'Allows credential stuffing against the checker-generated accounts.',
    exploit: "Brute-force the checker's random username/password pair.",
    breaker: 'Brute force can lock the instance out of its own account.',
    remediation: 'Throttle per source address; do not permanently lock.',
    cwe: ['CWE-307'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-GEN-002',
    category: 'OPEN_REDIRECT',
    title: 'Redirect target taken from the request',
    severity: 'low',
    source: String.raw`(?:redirect|sendRedirect|Location)\s*\(?[^)\n]{0,80}(?:request|params|query|referrer)`,
    flags: 'i',
    languages: ['.py', '.go', '.js', '.ts', '.php'],
    description:
      'Phishing/credential-relay primitive; mostly noise for A/D but worth listing.',
    exploit: 'Craft a link that bounces participants to an attacker page.',
    breaker: 'None.',
    remediation: 'Validate redirect targets against an allow-list.',
    cwe: ['CWE-601'],
    sources: [SOURCE_2019],
  }),
  rule({
    id: 'AD-GEN-003',
    category: 'MASS_ASSIGNMENT',
    title: 'Bulk model update from a request payload',
    severity: 'medium',
    source: String.raw`(?:update|save|create|insert)\s*\(\s*(?:\*\*|Object\.assign|req\.body|request\.(?:form|json|args))`,
    flags: 'is',
    languages: ['.js', '.ts', '.py'],
    description:
      'Lets a team set fields the UI never exposes, including privilege fields.',
    exploit: 'Include extra keys in the JSON body.',
    breaker: 'None.',
    remediation: 'Assign an explicit field allow-list.',
    cwe: ['CWE-915'],
    sources: [SOURCE_2019],
  }),
];

export const RULES_BY_ID: ReadonlyMap<string, Rule> = new Map(
  RULES.map((item) => [item.id, item]),
);

export const CATEGORIES: Record<string, string> = {};
for (const item of RULES) {
  if (!(item.category in CATEGORIES)) CATEGORIES[item.category] = item.title;
}

export function severityRank(severity: string): number {
  return SEVERITY_ORDER[severity] ?? 0;
}
