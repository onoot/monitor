/**
 * Lightweight semantic passes.
 *
 * Regex rules miss the single most common A/D bug in this family of services: a
 * login handler that reads the submitted password and then never checks it. The
 * handlers look perfectly ordinary, so this pass extracts function bodies and
 * answers a concrete question:
 *
 *     is a credential read from the request actually consumed inside the same
 *     function scope?
 *
 * It also catches request data reaching an HTML sink, and plaintext password
 * storage, which need a small amount of local dataflow to see.
 */

import {
  collapseWhitespace,
  evidence,
  finding,
  fingerprint as fingerprintOf,
  lineOf,
  snippetOf,
} from './models.js';
import type { Finding } from './models.js';

const CREDENTIAL_NAMES = [
  'password',
  'passwd',
  'pwd',
  'pass',
  'secret',
  'magicword',
  'magic_word',
];

/** Reads of a credential from the request. */
const CREDENTIAL_READ = new RegExp(
  String.raw`\b(?<var>[A-Za-z_]\w*)\s*(?::=|=)\s*(?:` +
    String.raw`request\.(?:form|args|json|data)\.?(?:get)?\s*[(\[.]\s*['"](?<k1>[^'"]+)['"]` +
    String.raw`|c\.PostForm\s*\(\s*['"](?<k2>[^'"]+)['"]` +
    String.raw`|c\.PostFormArray\s*\(\s*['"](?<k3>[^'"]+)['"]` +
    String.raw`|req\.(?:body|query|params)\s*(?:\.|\[\s*['"])(?<k4>[^'"\]\.]+)['"]?\s*\]?` +
    String.raw`|r\.(?:Form|PostForm|FormValue)\.Get\s*\(\s*['"](?<k5>[^'"]+)['"]` +
    String.raw`|\$_POST\s*\[\s*['"](?<k6>[^'"]+)['"]` +
    String.raw`|\$_REQUEST\s*\[\s*['"](?<k7>[^'"]+)['"]` +
    String.raw`|\$_GET\s*\[\s*['"](?<k8>[^'"]+)['"]` +
    String.raw`|params\.(?:get|query)\s*\(\s*['"](?<k9>[^'"]+)['"]` +
    String.raw`|request\.GET\s*\(\s*['"](?<k10>[^'"]+)['"]` +
    String.raw`)`,
  'gi',
);

/** Anything that consumes a credential: comparison, hashing, verification, lookup. */
const CREDENTIAL_CONSUMED = new RegExp(
  String.raw`(?:==|===|!=|!==|compare|verify|check_?password|generate_password_hash|` +
    String.raw`password_hash|bcrypt|argon|scrypt|pbkdf|hmac|constant_time|` +
    String.raw`sha(?:1|256|512)|md5\s*\(|SELECT\s+[^\n]{0,80}password|UPDATE\s+[^\n]{0,80}password)`,
  'i',
);

const HTML_SINK = new RegExp(
  String.raw`(?:fmt\.Sprintf|String\.Format|\.format\(|f["']|\+\s*\w|innerHTML|` +
    String.raw`outerHTML|document\.write|render_template_string|c\.` +
    String.raw`(?:HTML|String)|jsonify\s*\(|json\.dumps\s*\()`,
  'i',
);

const HTML_TAG =
  /<(?:div|span|script|img|a|p|html|body|input|textarea)\b/i;

const PASSWORD_STORAGE = new RegExp(
  String.raw`INSERT\s+INTO\s+[\w.]*\w*(?:users?|accounts?|members?|auth)\w*[^;\n]{0,120}password` +
    String.raw`|\b(?:create|add|register|signup|insert)_?user\b[^)\n]{0,120}password`,
  'i',
);

const HASH_NEARBY = new RegExp(
  String.raw`(?:generate_password_hash|Hash::make|password_hash|bcrypt|argon|scrypt|` +
    String.raw`createHash|sha256?|md5\s*\(|pbkdf2)`,
  'i',
);

/**
 * Persisting a credential is a legitimate use during registration, so it counts
 * as consumption. The weakness there is storage, not verification, and that is
 * reported separately by AD-CRYPTO-004.
 */
const STORAGE_SINK = new RegExp(
  String.raw`(?:INSERT\s+INTO|\b(?:insert|add|create|register|signup|save)_?user\b|` +
    String.raw`\.create\s*\(|\.save\s*\(|\.insert\s*\()`,
  'i',
);

const TAINED_ASSIGN = /\b([A-Za-z_]\w*)\s*=\s*(?:request|req|params|input)/gi;
const IDENTIFIER = /\b([A-Za-z_]\w*)\b/g;

export interface Scope {
  name: string;
  start: number;
  end: number;
  body: string;
}

const BRACE_LANGS = new Set([
  '.go',
  '.js',
  '.ts',
  '.tsx',
  '.jsx',
  '.php',
  '.java',
  '.cs',
  '.kt',
  '.rs',
  '.c',
  '.cpp',
]);

const FUNC_START = new RegExp(
  String.raw`^\s*(?:async\s+)?(?:def|function|func|fn|sub)\s+(?<name>\w+)\s*\(` +
    String.raw`|^\s*(?<name2>\w+)\s*=\s*(?:async\s*)?(?:function\s*)?\(?[^=\n]*\)?\s*=>\s*\{` +
    String.raw`|^\s*(?<name3>\w+)\s*:\s*function\s*\(` +
    String.raw`|^\s*public\s+function\s+(?<name4>\w+)\s*\(`,
);

const PY_DEF = /^(\s*)(?:async\s+)?def\s+(\w+)\s*\(/;

function splitLines(text: string): string[] {
  return text.split(/\r?\n/);
}

export function extractScopes(text: string, suffix: string): Scope[] {
  if (suffix === '.py') return pythonScopes(text);
  return braceScopes(text);
}

function pythonScopes(text: string): Scope[] {
  const lines = splitLines(text);
  const scopes: Scope[] = [];
  const starts: { index: number; indent: number; name: string }[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    if (line.trim().startsWith('#')) continue;
    const match = PY_DEF.exec(line);
    if (match) {
      starts.push({
        index,
        indent: (match[1] ?? '').length,
        name: match[2] ?? '',
      });
    }
  }
  for (let position = 0; position < starts.length; position += 1) {
    const start = starts[position] as { index: number; indent: number; name: string };
    let end = lines.length;
    for (let next = position + 1; next < starts.length; next += 1) {
      const candidate = starts[next] as { index: number; indent: number };
      if (candidate.indent <= start.indent) {
        end = candidate.index;
        break;
      }
    }
    scopes.push({
      name: start.name,
      start: start.index + 1,
      end,
      body: lines.slice(start.index, end).join('\n'),
    });
  }
  return scopes;
}

function braceScopes(text: string): Scope[] {
  const scopes: Scope[] = [];
  const lines = splitLines(text);
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index] ?? '';
    const match = FUNC_START.exec(line);
    if (!match) continue;
    const groups = match.groups ?? {};
    const name =
      groups.name ?? groups.name2 ?? groups.name3 ?? groups.name4 ?? 'anonymous';
    const openAt = line.indexOf('{');
    if (openAt === -1) continue;

    // Walk forward until brace depth returns to zero. Anything left open at EOF
    // is treated as running to the last line, which is what the Python pass did.
    let depth = 0;
    let end = index;
    let closed = false;
    outer: for (let cursor = index; cursor < lines.length; cursor += 1) {
      const segment = lines[cursor] ?? '';
      for (const char of segment) {
        if (char === '{') {
          depth += 1;
        } else if (char === '}') {
          depth -= 1;
          if (depth === 0) {
            end = cursor;
            closed = true;
            break outer;
          }
        }
      }
      if (depth === 0) {
        end = cursor;
        closed = true;
        break;
      }
    }
    if (!closed) end = lines.length - 1;

    scopes.push({
      name,
      start: index + 1,
      end: end + 1,
      body: lines.slice(index, end + 1).join('\n'),
    });
  }
  return scopes;
}

function firstKey(groups: Record<string, string | undefined>): string | null {
  for (let i = 1; i <= 10; i += 1) {
    const value = groups[`k${i}`];
    if (value) return value;
  }
  return null;
}

function isCredentialKey(key: string): boolean {
  const lower = key.toLowerCase();
  return CREDENTIAL_NAMES.some((name) => lower.includes(name));
}

export function checkUnusedCredentials(
  scopes: readonly Scope[],
  rel: string,
  sources: readonly string[],
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const reader = new RegExp(CREDENTIAL_READ.source, CREDENTIAL_READ.flags);
  for (const scope of scopes) {
    const body = scope.body;
    for (const match of body.matchAll(reader)) {
      const groups = match.groups ?? {};
      const key = firstKey(groups);
      if (!key || !isCredentialKey(key)) continue;
      const varName = groups.var;
      if (!varName) continue;

      // Consume every later mention of the variable, excluding the read itself.
      // No mention at all is the strongest form of the bug.
      const tail = body.slice(match.index + match[0].length);
      let used = false;
      const mentionRe = new RegExp(String.raw`\b${escapeRegExp(varName)}\b`, 'g');
      for (const mention of tail.matchAll(mentionRe)) {
        const from = Math.max(0, mention.index - 60);
        const window = tail.slice(from, mention.index + mention[0].length + 60);
        if (CREDENTIAL_CONSUMED.test(window)) {
          used = true;
          break;
        }
      }
      // Registration paths legitimately persist the credential.
      if (!used && STORAGE_SINK.test(body)) used = true;
      if (used) continue;

      const line = scope.start + lineOf(body, match.index) - 1;
      const snippet = snippetOf(body);
      const fp = fingerprintOf(`${scope.name}:${varName}:${snippet}`);
      if (seen.has(fp)) continue;
      seen.add(fp);
      findings.push(
        finding({
          ruleId: 'AD-AUTH-001',
          category: 'AUTH_BYPASS',
          title: 'Credential read from the request and never verified',
          severity: 'critical',
          confidence: 'high',
          evidence: evidence({ file: rel, line, snippet, fingerprint: fp }),
          description:
            `\`${varName}\` is populated from the submitted ` +
            `\`${key}\` field in \`${scope.name}()\` and is never compared, hashed ` +
            'or looked up. Authentication therefore succeeds for any password.',
          exploit:
            `Log in as any existing username with an arbitrary password. ` +
            `The instance grants \`${scope.name}()\`'s full session.`,
          breaker:
            'None. The checker authenticates with its real credentials, so this ' +
            'invisible to scoring and must be found by review.',
          remediation: 'Verify the submitted credential against a stored hash.',
          cwe: ['CWE-287', 'CWE-308'],
          sources,
        }),
      );
    }
  }
  return findings;
}

export function checkRequestToHtml(
  scopes: readonly Scope[],
  rel: string,
  sources: readonly string[],
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const reader = new RegExp(CREDENTIAL_READ.source, CREDENTIAL_READ.flags);
  for (const scope of scopes) {
    const body = scope.body;
    const sink = HTML_SINK.exec(body);
    const tag = HTML_TAG.exec(body);
    if (!sink || !tag) continue;

    const tainted = new Set<string>();
    for (const match of body.matchAll(reader)) {
      const varName = (match.groups ?? {}).var;
      if (varName) tainted.add(varName);
    }
    for (const match of body.matchAll(TAINED_ASSIGN)) {
      const name = match[1];
      if (name) tainted.add(name);
    }
    const window = body.slice(sink.index + sink[0].length, sink.index + sink[0].length + 200);
    const formatted = new Set<string>();
    for (const match of window.matchAll(IDENTIFIER)) {
      const name = match[1];
      if (name) formatted.add(name);
    }
    let overlap = false;
    for (const name of tainted) {
      if (formatted.has(name)) {
        overlap = true;
        break;
      }
    }
    if (!overlap) continue;

    const line = scope.start + Math.min(lineOf(body, sink.index), 1) - 1;
    const snippet = snippetOf(body);
    const fp = fingerprintOf(`html:${scope.name}:${snippet}`);
    if (seen.has(fp)) continue;
    seen.add(fp);
    findings.push(
      finding({
        ruleId: 'AD-XSS-002',
        category: 'XSS',
        title: 'Request-controlled value rendered into an HTML response',
        severity: 'high',
        confidence: 'medium',
        evidence: evidence({ file: rel, line, snippet, fingerprint: fp }),
        description:
          `\`${scope.name}()\` builds HTML by string formatting and feeds it request ` +
          'data. No escaping is applied on this path.',
        exploit:
          'Submit a payload such as `<script>...</script>` or an event handler; it is ' +
          "reflected verbatim in the victim's session.",
        breaker:
          "A payload that re-enters the checker's session can corrupt its state; a " +
          'malformed payload that raises an exception stops the instance (IV.5).',
        remediation:
          "Escape on output, or render through the template engine's escaping.",
        cwe: ['CWE-79'],
        sources,
      }),
    );
  }
  return findings;
}

export function checkPlaintextPasswordStorage(
  scopes: readonly Scope[],
  rel: string,
  sources: readonly string[],
): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const scope of scopes) {
    const body = scope.body;
    if (!PASSWORD_STORAGE.test(body)) continue;
    if (HASH_NEARBY.test(body)) continue;
    const snippet = snippetOf(body);
    const fp = fingerprintOf(`plain:${scope.name}:${snippet}`);
    if (seen.has(fp)) continue;
    seen.add(fp);
    findings.push(
      finding({
        ruleId: 'AD-CRYPTO-004',
        category: 'WEAK_CRYPTO',
        title: 'Password persisted without a hash',
        severity: 'critical',
        confidence: 'high',
        evidence: evidence({
          file: rel,
          line: scope.start,
          snippet,
          fingerprint: fp,
        }),
        description:
          `\`${scope.name}()\` writes a password column with no hashing call in scope. ` +
          'Anyone who reaches the datastore - directly, via SQLi or via traversal - ' +
          "reads every team's plaintext credentials.",
        exploit: 'Reach the datastore, dump the table, log in as any team.',
        breaker:
          'None for the checker, which uses correct credentials. But combined with any ' +
          'read primitive this is a total compromise of the instance.',
        remediation:
          'Hash with bcrypt/argon2/scrypt and a per-user salt before storing.',
        cwe: ['CWE-256', 'CWE-312'],
        sources,
      }),
    );
  }
  return findings;
}

export function runAll(
  text: string,
  rel: string,
  suffix: string,
  sources: readonly string[],
): Finding[] {
  const scopes = extractScopes(text, suffix);
  return [
    ...checkUnusedCredentials(scopes, rel, sources),
    ...checkRequestToHtml(scopes, rel, sources),
    ...checkPlaintextPasswordStorage(scopes, rel, sources),
  ];
}

export { BRACE_LANGS, collapseWhitespace, CREDENTIAL_NAMES };

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
