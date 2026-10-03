/**
 * Static analysis engine.
 *
 * Deliberately dependency-free: regex rules over source text, plus light
 * structural extraction of routes and flag-related sinks. Every finding carries
 * file, line, snippet and the rule's exploit/breaker rationale so a reviewer can
 * confirm or discard it without rerunning anything.
 */

import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import * as semantics from './semantics.js';
import {
  collapseWhitespace,
  evidence,
  finding,
  fingerprint,
  lineOf,
  severityRank,
  sortFindings,
} from './models.js';
import type { Finding } from './models.js';
import { RULES, type Rule } from './rules.js';

export const LOCAL_SOURCE = ['local:AltayCoin/Curs/Magiclib/Omnyhub'];

export const TEXT_SUFFIXES = new Set([
  '.py', '.go', '.js', '.ts', '.tsx', '.jsx', '.vue', '.php', '.rb', '.java',
  '.kt', '.cs', '.c', '.cpp', '.h', '.yml', '.yaml', '.json', '.env', '.sql',
  '.html', '.tpl', '.twig', '.conf', '.ini', '.toml', '.txt', '.sh', '.lua',
]);

/**
 * Each entry names the HTTP verb (or `ANY`) in its own source so the verb comes
 * from the declaration rather than being guessed. Python used group names, which
 * JS cannot reuse for that, hence the numbered group.
 */
const ROUTE_PATTERNS: readonly { source: string; method: string }[] = [
  // Flask / FastAPI / aiohttp
  { method: 'ANY', source: String.raw`@\w+\.(?:route|get|post|put|delete|patch|websocket)\(\s*["'](?<p>[^"']+)["']` },
  // Laravel / Slim / Symfony routes
  { method: 'ANY', source: String.raw`Route::(?:get|post|put|delete|patch|any|match|resource)\s*\(\s*["'](?<p>[^"']+)["']` },
  // Express / Koa / Nest
  { method: 'ANY', source: String.raw`\b(?:app|router|r)\.(?:get|post|put|delete|patch|all|use)\s*\(\s*["'](?<p>[^"']+)["']` },
  // Gin / Echo / chi / gorilla
  { method: 'ANY', source: String.raw`\b\w+\.(?:GET|POST|PUT|DELETE|PATCH|Any|HandleFunc)\s*\(\s*["'](?<p>[^"']+)["']` },
  { method: 'ANY', source: String.raw`(?:Handle|HandleFunc)\s*\(\s*["'](?<p>[^"']+)["']` },
  // Spring / Axum
  { method: 'ANY', source: String.raw`@(?:Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*)?["'](?<p>[^"']+)["']` },
  // Nest / Angular / Adonis style decorators (no `Mapping` suffix)
  { method: 'ANY', source: String.raw`@(?:Get|Post|Put|Delete|Patch)\s*\(\s*["']?(?<p>[^"',)]{1,80})["']?\s*\)` },
];

const FLAG_TOKENS =
  /\b(flag|flags|flag_path|flag_file|getflag|setflag|putflag|ctf_?flag)\b/i;

const PROTECTED_HINT = new RegExp(
  String.raw`(?:chec?k_?auth|autch|authenticat|authguard|authmiddleware|@useguards|` +
    String.raw`\bauth\b|login|session|password|passwd|admin|role|permission|owner|secret|` +
    String.raw`verify|token|credential|require_?auth|login_?required|jwt|bearer)`,
  'i',
);

export const CREDENTIAL_FIELDS = [
  'password', 'passwd', 'pass', 'pwd', 'secret', 'secretkey', 'secret_key',
  'token', 'authorization', 'auth', 'apikey', 'api_key', 'session', 'cookie',
];

export interface Route {
  path: string;
  method: string;
  file: string;
  line: number;
  guarded: boolean;
  idParam: boolean;
  key(): string;
  toDict(): Record<string, unknown>;
}

export interface ScanResult {
  findings: Finding[];
  routes: Route[];
  filesScanned: number;
  filesSkipped: number;
  bySeverity(severity: string): Finding[];
  sortedFindings(): Finding[];
  toDict(): Record<string, unknown>;
}

export function makeRoute(init: {
  path: string;
  method: string;
  file: string;
  line: number;
  guarded?: boolean;
  idParam?: boolean;
}): Route {
  const route: Route = {
    path: init.path,
    method: init.method,
    file: init.file,
    line: init.line,
    guarded: init.guarded ?? false,
    idParam: init.idParam ?? false,
    key(): string {
      return `${this.method} ${this.path}`;
    },
    toDict(): Record<string, unknown> {
      return {
        path: this.path,
        method: this.method,
        file: this.file,
        line: this.line,
        guarded: this.guarded,
        id_param: this.idParam,
      };
    },
  };
  return route;
}

function makeScanResult(init: Partial<ScanResult> = {}): ScanResult {
  const result: ScanResult = {
    findings: init.findings ?? [],
    routes: init.routes ?? [],
    filesScanned: init.filesScanned ?? 0,
    filesSkipped: init.filesSkipped ?? 0,
    bySeverity(severity: string): Finding[] {
      return this.findings.filter((item) => item.severity === severity);
    },
    sortedFindings(): Finding[] {
      return sortFindings(this.findings);
    },
    toDict(): Record<string, unknown> {
      return {
        files_scanned: this.filesScanned,
        files_skipped: this.filesSkipped,
        routes: this.routes.map((route) => route.toDict()),
        findings: this.sortedFindings().map((item) => ({
          rule_id: item.ruleId,
          category: item.category,
          title: item.title,
          severity: item.severity,
          confidence: item.confidence,
          evidence: item.evidence,
        })),
      };
    },
  };
  return result;
}

export function createScanResult(init: Partial<ScanResult> = {}): ScanResult {
  return makeScanResult(init);
}

/**
 * Exclusion matching, ported from a hand-rolled `fnmatch` + directory-segment
 * scheme. Directory patterns match on any contiguous run of segments, so
 * `**\//storage/framework/**` excludes `a/storage/framework/views/x.php`.
 */
function excluded(relPosix: string, name: string, patterns: readonly string[]): boolean {
  for (const pattern of patterns) {
    let candidate = pattern.replace(/\\/g, '/');
    if (candidate.startsWith('**/')) candidate = candidate.slice(3);
    if (candidate.includes('/')) {
      // Directory-style exclusion: any path containing the segment run.
      const segments = candidate
        .replace(/\*\*+$/, '')
        .replace(/^\/+|\/+$/g, '')
        .split('/')
        .filter((part) => part && part !== '**');
      const parts = relPosix.split('/').slice(0, -1);
      if (segments.length > 0) {
        for (let i = 0; i + segments.length <= parts.length; i += 1) {
          if (segments.every((segment, offset) => parts[i + offset] === segment)) {
            return true;
          }
        }
      }
      if (
        pattern.includes('**') &&
        relPosix.replace(/\/+$/, '').endsWith(segments.join('/'))
      ) {
        return true;
      }
      continue;
    }
    // Bare filename/glob: match against the file name.
    if (globBasename(candidate, name)) return true;
  }
  return false;
}

/** `fnmatch` with shell-style `*`, `?` and `[...]` over a single name. */
function globBasename(pattern: string, name: string): boolean {
  let out = '';
  for (let i = 0; i < pattern.length; i += 1) {
    const char = pattern[i] as string;
    if (char === '*') {
      out += '.*';
    } else if (char === '?') {
      out += '.';
    } else if (char === '[') {
      const close = pattern.indexOf(']', i + 1);
      if (close === -1) {
        out += '\\[';
      } else {
        out += `[${pattern.slice(i + 1, close)}]`;
        i = close;
      }
    } else if ('\\^$.|+()'.includes(char)) {
      out += `\\${char}`;
    } else {
      out += char;
    }
  }
  return new RegExp(`^${out}$`).test(name);
}

interface SourceFile {
  absolute: string;
  rel: string;
  name: string;
}

function iterSourceFiles(
  roots: readonly string[],
  patterns: readonly string[],
): { files: SourceFile[]; skipped: number } {
  const files: SourceFile[] = [];
  const seen = new Set<string>();
  let skipped = 0;

  const push = (absolute: string, rel: string): void => {
    if (seen.has(absolute)) return;
    const name = path.basename(absolute);
    if (excluded(rel, name, patterns)) {
      skipped += 1;
      return;
    }
    const suffix = path.extname(absolute).toLowerCase();
    if (!TEXT_SUFFIXES.has(suffix) && !name.startsWith('.env')) {
      skipped += 1;
      return;
    }
    seen.add(absolute);
    files.push({ absolute, rel, name });
  };

  for (const root of roots) {
    let stat;
    try {
      stat = statSync(root);
    } catch {
      continue;
    }
    if (stat.isFile()) {
      push(root, path.basename(root));
      continue;
    }
    const walk = (dir: string, prefix: string): void => {
      let entries: string[];
      try {
        entries = readdirSync(dir).sort();
      } catch {
        return;
      }
      for (const entry of entries) {
        const absolute = path.join(dir, entry);
        const rel = prefix ? `${prefix}/${entry}` : entry;
        let child;
        try {
          child = statSync(absolute);
        } catch {
          continue;
        }
        if (child.isDirectory()) walk(absolute, rel);
        else if (child.isFile()) push(absolute, rel);
      }
    };
    walk(root, '');
  }
  return { files, skipped };
}

/**
 * After the SQL literal: a binding argument list means the statement is safe.
 *
 * Windows: a `g` RegExp carries `lastIndex` between calls, so each use builds a
 * fresh instance from a shared source instead of mutating a module-level object.
 */
const BOUND_PARAMS_SOURCE = String.raw`(?:["']\s*,\s*\(|["']\s*%\s*\(|["']\s*\.\s*format\s*\(|,\s*\(\s*\w)`;

const POST_FILTERS: Record<
  string,
  (text: string, start: number, end: number) => boolean
> = {
  bound_sql: (text, start, end) => {
    const window = text.slice(start, Math.min(text.length, end + 240));
    return new RegExp(BOUND_PARAMS_SOURCE).test(window);
  },
};

function relativePath(absolute: string, roots: readonly string[]): string {
  for (const root of roots) {
    const rel = path.relative(root, absolute);
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
      return rel.split(path.sep).join('/');
    }
  }
  return path.basename(absolute);
}

function contextWindow(text: string, start: number, end: number, radius = 220): string {
  const left = Math.max(0, start - radius);
  const right = Math.min(text.length, end + radius);
  return collapseWhitespace(text.slice(left, right).trim()).slice(0, 500);
}

export function scan(
  roots: readonly string[],
  excludedGlobs: readonly string[],
  maxBytes = 2_000_000,
): ScanResult {
  const { files, skipped } = iterSourceFiles(roots, excludedGlobs);
  const result = makeScanResult({ filesSkipped: skipped });
  const seenKeys = new Set<string>();
  const texts = new Map<string, string>();

  for (const file of files) {
    let text: string;
    try {
      if (statSync(file.absolute).size > maxBytes) continue;
      // Strip a BOM: VS Code and Notepad add one, and it would otherwise end up
      // glued to the first line of the snippet.
      text = readFileSync(file.absolute, 'utf8').replace(/^\uFEFF/, '');
    } catch {
      continue;
    }
    if (!text.trim()) continue;
    result.filesScanned += 1;
    const rel = relativePath(file.absolute, roots);

    result.routes.push(...extractRoutes(text, rel));
    texts.set(rel, text);
    applyRules(text, rel, result, seenKeys);
    result.findings.push(
      ...semantics.runAll(
        text,
        rel,
        path.extname(rel).toLowerCase(),
        LOCAL_SOURCE,
      ),
    );
  }

  result.routes = dedupeRoutes(result.routes);
  result.findings.push(...unguardedRouteFindings(result.routes, texts));
  return result;
}

/** `app.get("/x", Handler.name)` -> the handler symbol on the declaration line. */
const HANDLER_REF = /,\s*([A-Za-z_$][\w$]*(?:\.\w+)*)\s*\)?\s*[;)]?\s*$/;

/**
 * Return true / false when the handler resolves to exactly one definition, or
 * null when the symbol is ambiguous, so the caller lowers confidence instead of
 * guessing.
 */
export function handlerIsGuarded(
  texts: ReadonlyMap<string, string>,
  route: Route,
): boolean | null {
  const source = texts.get(route.file) ?? '';
  const sourceLines = source.split(/\r?\n/);
  if (sourceLines.length === 0 || route.line > sourceLines.length) return null;
  const match = HANDLER_REF.exec((sourceLines[route.line - 1] ?? '').trimEnd());
  if (!match) return null;
  const ref = match[1] ?? '';
  const name = ref.split('.').pop() ?? '';
  if (!name) return null;

  const definitionRe = new RegExp(
    String.raw`(?:export\s+)?(?:const|let|var|async\s+function|function)\s+${escapeRegExp(name)}\b`,
  );
  let owners = [...texts.entries()]
    .filter(([, text]) => definitionRe.test(text))
    .map(([key]) => key)
    .filter((key) => key !== route.file);
  if (owners.length === 0) return null;
  if (owners.length > 1) {
    // Ambiguous name: only trust it when the file name echoes the module ref.
    const module = ref.includes('.') ? (ref.split('.').at(-2) ?? '').toLowerCase() : '';
    const narrowed = owners.filter((key) => {
      const stem = path.basename(key, path.extname(key)).toLowerCase();
      return module.length >= 4 && stem.includes(module.slice(0, 4));
    });
    if (narrowed.length !== 1) return null;
    owners = narrowed;
  }
  const bodySource = texts.get(owners[0] as string) ?? '';
  const found = definitionRe.exec(bodySource);
  if (!found) return null;
  const body = bodySource.slice(found.index, found.index + 1800);
  return PROTECTED_HINT.test(body);
}

/** Data-bearing routes with no authentication check at the route or in the handler. */
export function unguardedRouteFindings(
  routes: readonly Route[],
  texts: ReadonlyMap<string, string>,
): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();
  for (const route of routes) {
    if (route.guarded || seen.has(route.key())) continue;
    if (PUBLIC_HINT.test(route.path) || !SENSITIVE_HINT.test(route.path)) continue;
    const handled = handlerIsGuarded(texts, route);
    if (handled) continue;
    const confidence = handled === null ? 'low' : 'medium';
    seen.add(route.key());
    out.push(
      finding({
        ruleId: 'AD-AUTH-002',
        category: 'AUTH_BYPASS',
        title: `Unauthenticated ${route.method} ${route.path}`,
        severity: 'high',
        confidence,
        evidence: evidence({
          file: route.file,
          line: route.line,
          snippet: route.key(),
          fingerprint: fingerprint(route.key()),
        }),
        description:
          'The route declaration has no authentication decorator, middleware or ' +
          'session check in its surrounding lines, while the path points at per-user ' +
          'or global data.',
        exploit: 'Call the endpoint directly without any session or token.',
        breaker:
          'Usually none: checkers keep using authenticated endpoints, so teams read ' +
          'the data freely while scoring continues.',
        remediation: 'Apply the same auth guard used by the neighbouring routes.',
        cwe: ['CWE-306'],
        sources: LOCAL_SOURCE,
      }),
    );
  }
  return out;
}

const CONFIDENCE_HIGH = /(?:request|params|body|input|argv|query)/i;
const CONFIDENCE_LOW = /(?:TODO|FIXME|example\.com|localhost|127\.0\.0\.1|test)/i;

function confidenceOf(rule: Rule, snippet: string): 'low' | 'medium' | 'high' {
  if (rule.category === 'CHECKER_BREAKING' || rule.breaker.startsWith('YES')) {
    return 'high';
  }
  if (CONFIDENCE_HIGH.test(snippet)) return 'high';
  if (CONFIDENCE_LOW.test(snippet)) return 'low';
  return 'medium';
}

export function applyRules(
  text: string,
  rel: string,
  result: ScanResult,
  seenKeys: Set<string>,
): Set<string> {
  const suffix = path.extname(rel).toLowerCase();
  for (const rule of RULES) {
    if (!rule.appliesTo(suffix)) continue;
    const low = text.toLowerCase();

    // File-level gate first. The same tokens are re-checked against each match
    // window below, so a neighbouring `jwt.verify` or `process.env` mention
    // cannot veto an unrelated match.
    if (rule.mustContain.length > 0) {
      if (!rule.mustContain.every((token) => low.includes(token.toLowerCase()))) continue;
    }
    if (rule.mustNotContain.length > 0) {
      if (rule.mustNotContain.some((token) => low.includes(token.toLowerCase()))) continue;
    }

    for (const match of text.matchAll(rule.matcher())) {
      const start = match.index;
      const end = start + match[0].length;
      const post = rule.post ? POST_FILTERS[rule.post] : undefined;
      if (post && post(text, start, end)) continue;

      if (rule.mustNotContain.length > 0) {
        const windowStart = Math.max(0, start - 400);
        const window = text.slice(windowStart, end + 400).toLowerCase();
        if (rule.mustNotContain.some((token) => window.includes(token.toLowerCase()))) {
          continue;
        }
      }

      const line = lineOf(text, start);
      const snippet = contextWindow(text, start, end);
      const key = `${rule.id}|${rel}:${fingerprint(snippet)}`;
      if (seenKeys.has(key)) continue;
      seenKeys.add(key);

      result.findings.push(
        finding({
          ruleId: rule.id,
          category: rule.category,
          title: rule.title,
          severity: rule.severity,
          confidence: confidenceOf(rule, snippet),
          evidence: evidence({ file: rel, line, snippet }),
          description: rule.description,
          exploit: rule.exploit,
          breaker: rule.breaker,
          remediation: rule.remediation,
          cwe: rule.cwe,
          sources: rule.sources,
        }),
      );
    }
  }
  return seenKeys;
}

export function dedupeRoutes(routes: readonly Route[]): Route[] {
  const seen = new Set<string>();
  const out: Route[] = [];
  for (const route of [...routes].sort((a, b) =>
    a.path === b.path ? a.method.localeCompare(b.method) : a.path < b.path ? -1 : 1,
  )) {
    const key = `${route.method} ${route.path}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(route);
  }
  return out;
}

const HTTP_VERBS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'];

const METHOD_LIST = /methods?\s*[:=]\s*\[(?<list>[^\]]*)\]/i;
const QUOTED_WORD = /["']([A-Za-z]+)["']/g;

function methodsFor(patternMethod: string, token: string, tail: string): string[] {
  if (patternMethod !== 'ANY') return [patternMethod];
  const listed = METHOD_LIST.exec(tail);
  if (listed) {
    const verbs: string[] = [];
    for (const item of (listed.groups?.list ?? '').matchAll(QUOTED_WORD)) {
      const verb = (item[1] ?? '').toUpperCase();
      if (HTTP_VERBS.includes(verb) && !verbs.includes(verb)) verbs.push(verb);
    }
    if (verbs.length > 0) return verbs;
  }
  const low = token.toLowerCase();
  if (/\bany\b|\.use\b|\.all\b|\bresource\b/.test(low)) return ['ANY'];
  for (const verb of ['get', 'post', 'put', 'delete', 'patch', 'options', 'head']) {
    if (low.includes(`.${verb}`) || low.includes(`"${verb}"`)) return [verb.toUpperCase()];
  }
  // Flask defaults to GET when the declaration omits `methods`.
  return ['GET'];
}

export function extractRoutes(text: string, rel: string): Route[] {
  const lines = text.split(/\r?\n/);
  interface Raw {
    line: number;
    path: string;
    token: string;
    tail: string;
    method: string;
  }
  const raw: Raw[] = [];
  for (const pattern of ROUTE_PATTERNS) {
    const regex = new RegExp(pattern.source, 'g');
    for (const match of text.matchAll(regex)) {
      raw.push({
        line: lineOf(text, match.index),
        path: match.groups?.p ?? '',
        token: match[0],
        tail: text.slice(match.index + match[0].length, match.index + match[0].length + 200),
        method: pattern.method,
      });
    }
  }
  raw.sort((a, b) => a.line - b.line);

  const routes: Route[] = [];
  for (let index = 0; index < raw.length; index += 1) {
    const entry = raw[index] as Raw;
    // A route owns the lines up to the next route declaration, so an adjacent
    // route's @UseGuards cannot mask a missing one.
    const nextLine = raw[index + 1]?.line ?? entry.line + 12;
    const from = Math.max(0, entry.line - 1);
    const to = Math.max(entry.line + 1, nextLine);
    const block = lines.slice(from, to).join('\n');
    const guarded = PROTECTED_HINT.test(block);
    const idParam = /\{[^}]*id[^}]*\}|:\w*id\b|<int:/i.test(entry.path);
    for (const method of methodsFor(entry.method, entry.token, entry.tail)) {
      routes.push(makeRoute({
        path: entry.path,
        method,
        file: rel,
        line: entry.line,
        guarded,
        idParam,
      }));
    }
  }
  return routes;
}

export const PUBLIC_HINT = new RegExp(
  String.raw`(?:^/|\.)(?:login|logout|register|signup|signin|sign-in|sign_up|` +
    String.raw`static|assets?|public|favicon|robots|sitemap|health|ping|ready|livez|readyz|` +
    String.raw`docs?|swagger|openapi|redoc)(?:/|\.|$)|auth(?:/|$)`,
  'i',
);

export const SENSITIVE_HINT = new RegExp(
  String.raw`(?:user|account|profile|admin|dashboard|wallet|balance|coin|score|` +
    String.raw`flag|me\b|self\b|orders?|transactions?|invoice|history|all\b|list|table|info)`,
  'i',
);

/** Routes taking an object id with no authentication hint nearby. */
export function unguardedIdRoutes(routes: readonly Route[]): Route[] {
  return routes.filter((route) => route.idParam && !route.guarded);
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export { FLAG_TOKENS, PROTECTED_HINT, POST_FILTERS, severityRank };
