/**
 * What counts as an attack on the wire.
 *
 * Scope is the operator's call and the categories they named: denial of service,
 * injection attempts, and probes for things that should never be reachable --
 * `.git`, `.env`, `private`, backup files, and the like.
 *
 * Every rule returns a rule id and a human reason, because a block that cannot be
 * explained is indistinguishable from a bug, and an unexplainable block on a live
 * network is the fastest way to lose the operator's trust in the whole box.
 *
 * Signatures are matched against decoded text. A request is percent-encoded,
 * sometimes twice over, precisely to get these bytes past a filter, so matching
 * the raw target would miss the traffic that matters most. Decoding first means
 * `/..%2f.git/config` and `/../.git/config` are seen as the same probe, which is
 * what they are.
 */

export type RuleCategory = 'dos' | 'injection' | 'exposure' | 'protocol';

export interface RuleHit {
  id: string;
  category: RuleCategory;
  severity: 'low' | 'medium' | 'high' | 'critical';
  reason: string;
  /** Where in the request it was seen. */
  where: 'path' | 'query' | 'body' | 'headers';
}

export interface RuleContext {
  method: string;
  /** Path, still percent-encoded as it arrived. */
  path: string;
  query: string;
  body: string;
  headers: Record<string, string>;
  remoteIp: string;
  now: number;
  /** Requests per second and the peak second, from the history tracker. */
  perSecond: number;
  peakPerSecond: number;
}

export interface DetectionResult {
  hits: RuleHit[];
  /** True when the request should be refused rather than merely logged. */
  block: boolean;
}

interface Signature {
  id: string;
  category: RuleCategory;
  severity: RuleHit['severity'];
  reason: string;
  where: RuleHit['where'];
  pattern: RegExp;
}

/** Percent-decode repeatedly, so double encoding does not hide a payload. */
export function fullyDecode(value: string, rounds = 3): string {
  let out = value;
  for (let i = 0; i < rounds; i += 1) {
    let next: string;
    try {
      next = decodeURIComponent(out);
    } catch {
      // A malformed escape is either a broken client or a probe; keep the text
      // we have rather than dropping the whole request.
      return out;
    }
    if (next === out) break;
    out = next;
  }
  return out;
}

const SQL_INJECTION: RegExp[] = [
  /\bunion\b[\s/*]+\bselect\b/i,
  /\bselect\b[\s\S]{0,80}\bfrom\b/i,
  /\binsert\s+into\b/i,
  /\bdelete\s+from\b/i,
  /\bdrop\s+(?:table|database)\b/i,
  /\bupdate\b[\s\S]{0,40}\bset\b[\s\S]{0,40}=/i,
  /\bor\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i,
  /\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i,
  /\binformation_schema\b/i,
  /\bload_file\s*\(/i,
  /\binto\s+(?:out|dump)file\b/i,
  /'\s*(?:or|and)\s+'?\d/i,
  // A quote closed off by a comment marker is the classic terminator, and in a
  // form body the marker is followed by the next field rather than end of line,
  // so anchoring the comment to the end of the text would miss it.
  /['"]\s*(?:--|#)/,
  /(?:--|#|\/\*)\s*$/,
];

const COMMAND_INJECTION: RegExp[] = [
  /[;&|`]\s*(?:cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python\d?)\b/i,
  /\$\([^)]*\)/,
  /\|\s*(?:sh|bash)\b/i,
];

/**
 * Paths that should never answer on a public service.
 *
 * Anchored on a path segment so a request for `/api/config` is not flagged by the
 * `.env` signature, while `/private/x` and `/.git/config` are.
 */
/**
 * Paths that should never answer on a public service.
 *
 * Scope matters here. A concrete secret file -- `.git/config`, `.env`,
 * `id_rsa`, `backup.sql` -- is a probe wherever it appears, so it is checked in
 * the path, the query and the body. A bare segment name like `private` or
 * `admin` is only a probe in the path: query strings legitimately carry
 * filesystem-looking text, because `?next=/admin` is an ordinary redirect
 * parameter. Applying the segment rule to a query would block a normal login
 * redirect, which is the kind of false positive that costs a participant their
 * run.
 */
const EXPOSURE_PATTERNS: Array<{ re: RegExp; reason: string; scope: 'all' | 'path' }> = [
  { re: /(?:^|\/)\.git(?:\/|$|\.)/i, reason: 'git metadata directory', scope: 'all' },
  { re: /(?:^|\/)\.svn(?:\/|$)/i, reason: 'subversion metadata directory', scope: 'all' },
  { re: /(?:^|\/)\.hg(?:\/|$)/i, reason: 'mercurial metadata directory', scope: 'all' },
  { re: /(?:^|\/)\.env(?:\/|$|\.)/i, reason: 'dotenv file', scope: 'all' },
  { re: /(?:^|\/)\.aws\/credentials/i, reason: 'aws credentials', scope: 'all' },
  { re: /(?:^|\/)\.ssh\/id_[a-z0-9]+/i, reason: 'ssh private key', scope: 'all' },
  { re: /(?:^|\/)\.docker\/config\.json/i, reason: 'docker registry credentials', scope: 'all' },
  { re: /(?:^|\/)\.kube\/config/i, reason: 'kubeconfig', scope: 'all' },
  { re: /(?:^|\/)\.DS_Store$/i, reason: 'macos directory listing', scope: 'all' },
  { re: /(?:^|\/)\.well-known\/security\.txt$/i, reason: 'security.txt', scope: 'path' },
  { re: /(?:^|\/)(?:private|internal|admin|secret)(?:\/|$)/i, reason: 'private path segment', scope: 'path' },
  { re: /(?:^|\/)(?:wp-config\.php|configuration\.php|config\.php)$/i, reason: 'framework config file', scope: 'all' },
  { re: /\.(?:bak|old|orig|save|swp|swo)$/i, reason: 'editor backup file', scope: 'all' },
  { re: /\.(?:bak|old|orig|save|sql|sqlite|db|dump|tar\.gz|tgz|zip|7z|rar)$/i, reason: 'backup or archive file', scope: 'all' },
  { re: /(?:^|\/)(?:id_rsa|id_dsa|server\.key|privkey\.pem)$/i, reason: 'private key file', scope: 'all' },
  { re: /(?:^|\/)actuator(?:\/|$)/i, reason: 'spring actuator endpoint', scope: 'all' },
  { re: /(?:^|\/)(?:phpinfo\.php|info\.php)$/i, reason: 'php diagnostics page', scope: 'all' },
  { re: /(?:^|\/)(?:debug|trace|cgi-bin)(?:\/|$)/i, reason: 'debug or trace endpoint', scope: 'all' },
  { re: /(?:^|\/)WEB-INF\/web\.xml/i, reason: 'java deployment descriptor', scope: 'all' },
  { re: /(?:^|\/)telescope(?:\/|$)/i, reason: 'laravel telescope', scope: 'all' },
];

const TRAVERSAL: RegExp[] = [
  /(?:\.\.[\/\\]){2,}/,
  /\.\.%2f/i,
  /%2e%2e[\/\\%2f]/i,
  /\/etc\/passwd/i,
  /\/proc\/self\/environ/i,
  /boot\.ini|win\.ini/i,
  /\\windows\\system32/i,
];

const PROTOCOL: RegExp[] = [
  // Smuggling and desync primitives.
  /\r\n\r\n|\n\n|\\r\\n/i,
  /%0d%0a/i,
  /(?:%20){4,}/,
];

/**
 * Build the signature list.
 *
 * `rateLimitPerSecond` and `rateBurst` describe the only stateful rule, so they
 * are configuration rather than constants; the rate signatures themselves are
 * placeholders here because the rate is evaluated from the tracker in `detect`,
 * not from the request text.
 */
export function buildSignatures(): Signature[] {
  const signatures: Signature[] = [];

  const add = (
    category: RuleCategory,
    severity: RuleHit['severity'],
    where: RuleHit['where'],
    reason: string,
    patterns: RegExp[],
    idPrefix: string,
  ): void => {
    patterns.forEach((pattern, index) => {
      signatures.push({ id: `${idPrefix}-${index + 1}`, category, severity, reason, where, pattern });
    });
  };

  add('injection', 'high', 'query', 'sql injection syntax', SQL_INJECTION, 'sqli');
  add('injection', 'high', 'body', 'sql injection syntax', SQL_INJECTION, 'sqli-body');
  add('injection', 'high', 'path', 'sql injection syntax', SQL_INJECTION, 'sqli-path');
  add('injection', 'critical', 'query', 'command injection syntax', COMMAND_INJECTION, 'cmdi');
  add('injection', 'critical', 'body', 'command injection syntax', COMMAND_INJECTION, 'cmdi-body');

  return signatures;
}

export interface DetectOptions {
  rateLimitPerSecond: number;
  rateBurst: number;
}

/**
 * The three places a payload can hide, kept separate.
 *
 * They are deliberately not concatenated: the exposure patterns anchor on `$` to
 * mean "the end of the file name", and joining path and query with a space would
 * put a character after every target and silently disable them.
 */
function haystacks(ctx: RuleContext): Array<{ where: RuleHit['where']; text: string }> {
  return [
    { where: 'path', text: fullyDecode(ctx.path) },
    { where: 'query', text: fullyDecode(ctx.query) },
    { where: 'body', text: fullyDecode(ctx.body) },
  ];
}

/**
 * Score one request.
 *
 * Blocking is decided per category rather than per hit, because a single probe
 * should not be enough to take a participant's traffic down on its own. Two
 * signals from the same category, or one critical one, block; a lone low-signal
 * hit is recorded and let through so the analyst can see it.
 */
export function detect(ctx: RuleContext, options: DetectOptions): DetectionResult {
  const signatures = buildSignatures();
  const hits: RuleHit[] = [];

  // Rate is evaluated from the tracker, not from the request text.
  if (ctx.perSecond > options.rateLimitPerSecond) {
    hits.push({
      id: 'dos-rate',
      category: 'dos',
      severity: 'high',
      reason: `sustained rate above ${options.rateLimitPerSecond}/s`,
      where: 'path',
    });
  }
  if (ctx.peakPerSecond > options.rateBurst) {
    hits.push({
      id: 'dos-burst',
      category: 'dos',
      severity: 'medium',
      reason: `burst above ${options.rateBurst} requests in one second`,
      where: 'path',
    });
  }

  for (const item of haystacks(ctx)) {
    for (const signature of signatures) {
      if (signature.where !== item.where) continue;
      if (signature.pattern.test(item.text)) {
        hits.push({
          id: signature.id,
          category: signature.category,
          severity: signature.severity,
          reason: signature.reason,
          where: item.where,
        });
      }
    }
  }

  for (const probe of EXPOSURE_PATTERNS) {
    for (const item of haystacks(ctx)) {
      if (probe.scope === 'path' && item.where !== 'path') continue;
      if (probe.re.test(item.text)) {
        hits.push({
          id: `exposure-${slug(probe.reason)}`,
          category: 'exposure',
          severity: 'high',
          reason: probe.reason,
          where: item.where,
        });
      }
    }
  }

  for (const pattern of TRAVERSAL) {
    for (const item of haystacks(ctx)) {
      if (pattern.test(item.text)) {
        hits.push({
          id: 'traversal',
          category: 'exposure',
          severity: 'high',
          reason: 'path traversal attempt',
          where: item.where,
        });
      }
    }
  }

  for (const pattern of PROTOCOL) {
    if (pattern.test(`${ctx.path} ${ctx.query}`)) {
      hits.push({
        id: 'protocol-smuggle',
        category: 'protocol',
        severity: 'medium',
        reason: 'request smuggling or desync primitive',
        where: 'path',
      });
    }
  }

  return { hits, block: shouldBlock(hits) };
}

function slug(reason: string): string {
  return reason.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

/**
 * Decide whether the recorded hits justify refusing the request.
 *
 * The threshold rules are deliberately stricter than the pattern rules. A rate
 * above an operator-set number, or a probe for `.git` or a private path, is not a
 * heuristic guess -- the operator drew the line, so crossing it is grounds to stop
 * the request. Pattern matches are noisier, so a lone one is recorded and let
 * through, and only corroboration (two signals in the same category) or a critical
 * finding is enough to act on them. Blocking a participant's ordinary traffic on
 * one ambiguous match is the failure mode that would cost the operator the run.
 */
export function shouldBlock(hits: readonly RuleHit[]): boolean {
  if (hits.length === 0) return false;
  if (hits.some((hit) => hit.severity === 'critical')) return true;
  if (hits.some((hit) => hit.category === 'dos')) return true;
  if (hits.some((hit) => hit.category === 'exposure' && hit.severity === 'high')) return true;
  const byCategory = new Map<RuleCategory, number>();
  for (const hit of hits) {
    byCategory.set(hit.category, (byCategory.get(hit.category) ?? 0) + 1);
  }
  for (const count of byCategory.values()) if (count >= 2) return true;
  return false;
}
