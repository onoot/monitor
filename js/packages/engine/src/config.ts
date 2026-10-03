/**
 * Configuration for the A/D toolkit.
 *
 * Everything the tool treats as ground truth comes from a config file, never
 * from guessing. Unknown values stay unknown.
 */

import { readFileSync, existsSync, statSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { xegerTokens } from './flags.js';

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigError';
  }
}

export interface TeamNetwork {
  /** One team's isolated instance. */
  label: string;
  cidr: string;
  source: string;
  contains(ip: string): boolean;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let out = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const value = Number.parseInt(part, 10);
    if (value > 255) return null;
    out = out * 256 + value;
  }
  return out;
}

function ipv6ToBigInt(ip: string): bigint | null {
  let text = ip;
  // Strip a zone id such as `fe80::1%eth0`.
  const zone = text.indexOf('%');
  if (zone !== -1) text = text.slice(0, zone);
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);

  // An embedded IPv4 tail (`::ffff:127.0.0.1`) becomes two hextets.
  const v4 = ipv4ToInt(text.slice(text.lastIndexOf(':') + 1));
  if (v4 !== null && text.includes('.')) {
    const hi = (v4 >>> 16).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    text = `${text.slice(0, text.lastIndexOf(':') + 1)}${hi}:${lo}`;
  }
  if (!text.includes(':')) return null;
  if (!/^[0-9a-fA-F:]+$/.test(text)) return null;

  const segments = text.split('::');
  if (segments.length > 2) return null;
  const head = segments[0] ?? '';
  const tail = segments[1];
  const headParts = head === '' ? [] : head.split(':');
  const tailParts = tail === undefined ? [] : tail === '' ? [] : tail.split(':');
  const fill = 8 - headParts.length - tailParts.length;
  if (tail === undefined) {
    if (headParts.length !== 8) return null;
  } else if (fill < 0) {
    return null;
  }
  const groups = [...headParts, ...Array<string>(fill).fill('0'), ...tailParts];
  if (groups.length !== 8) return null;
  let out = 0n;
  for (const group of groups) {
    out = (out << 16n) | BigInt(Number.parseInt(group || '0', 16));
  }
  return out;
}

export function parseIp(ip: string): bigint | null {
  const text = ip.trim();
  if (text.includes(':')) return ipv6ToBigInt(text);
  const v4 = ipv4ToInt(text);
  return v4 === null ? null : BigInt(v4);
}

/**
 * Parse a CIDR into its network prefix and prefix length, normalised to a bigint
 * so v4 and v6 share one comparison path.
 *
 * `base` is the address already shifted right by `maxBits - bits`, so membership
 * is a single equality test against `(value >> shift)`.
 */
export function parseCidr(
  cidr: string,
): { base: bigint; bits: number; family: 4 | 6 } | null {
  const slash = cidr.lastIndexOf('/');
  const addr = slash === -1 ? cidr : cidr.slice(0, slash);
  const family: 4 | 6 = addr.includes(':') ? 6 : 4;
  const value = parseIp(addr);
  if (value === null) return null;
  const maxBits = family === 4 ? 32 : 128;
  const bits = slash === -1 ? maxBits : Number.parseInt(cidr.slice(slash + 1), 10);
  if (Number.isNaN(bits) || bits < 0 || bits > maxBits) return null;
  const shift = BigInt(maxBits - bits);
  return { base: value >> shift, bits, family };
}

export function makeNetworkForTest(cidr: string): TeamNetwork {
  return makeNetwork(cidr, cidr, 'test');
}

function makeNetwork(label: string, cidr: string, source: string): TeamNetwork {
  const parsed = parseCidr(cidr);
  return {
    label,
    cidr,
    source,
    contains(ip: string): boolean {
      const value = parseIp(ip);
      if (value === null || parsed === null) return false;
      if ((ip.includes('.') ? 4 : 6) !== parsed.family) return false;
      const maxBits = parsed.family === 4 ? 32 : 128;
      if (parsed.bits === 0) return true;
      const shift = BigInt(maxBits - parsed.bits);
      return (value >> shift) === parsed.base;
    },
  };
}

export interface FlagFormat {
  /** Pattern + charset used for partial poisoning. */
  pattern: string;
  prefix: string;
  suffix: string;
  bodyAlphabet: string;
  minLength: number;
  known(): boolean;
  literalMask(): string | null;
}

export function makeFlagFormat(init: {
  pattern?: string;
  prefix?: string;
  suffix?: string;
  bodyAlphabet?: string;
  minLength?: number;
}): FlagFormat {
  const pattern = init.pattern ?? '';
  const format: FlagFormat = {
    pattern,
    prefix: init.prefix ?? '',
    suffix: init.suffix ?? '',
    bodyAlphabet: init.bodyAlphabet ?? '',
    minLength: init.minLength ?? 0,
    known: () => pattern.length > 0,
    /**
     * Convert an xeger-style pattern into a literal template:
     * `alctf{[a-z0-9_]{16}}` -> `alctf{________________}`. Returns null when the
     * pattern contains constructs we cannot express as a mask.
     */
    literalMask: (): string | null => {
      if (!pattern) return null;
      const items = xegerTokens(pattern);
      if (items === null) return null;
      const out: string[] = [];
      for (const item of items) {
        if (item.kind === 'lit') {
          out.push(item.value);
        } else {
          const filler = item.value.includes('_') ? '_' : 'a';
          out.push(filler.repeat(item.width ?? 1));
        }
      }
      return out.join('');
    },
  };
  return format;
}

export const DEFAULT_EXCLUDED_GLOBS = [
  '**/node_modules/**',
  '**/vendor/**',
  '**/.git/**',
  '**/__pycache__/**',
  '**/dist/**',
  '**/build/**',
  '**/storage/framework/**',
  '**/*.min.js',
  '**/*.min.css',
  '**/composer.lock',
  '**/package-lock.json',
  '**/yarn.lock',
];

export interface Config {
  serviceName: string;
  sourceRoots: string[];
  excludedGlobs: string[];
  /** Explicit team networks. `unknown` is never a checker. */
  teamNetworks: TeamNetwork[];
  checkerNetworks: TeamNetwork[];
  checkerIpPattern: string;
  /** Literal flag values observed for this service, if the operator supplied them. */
  knownFlags: string[];
  flagFormat: FlagFormat;
  /** Runtime capture files (JSONL / JSON arrays / access logs). */
  requestLogs: string[];
  outputDir: string;
  notes: string;
  /**
   * Return 'checker', 'team' or 'unknown'.
   *
   * Precedence matters: an explicit team list wins over inference so that a
   * mis-detected checker subnet can never cause the checker to be poisoned.
   */
  classifyIp(ip: string): 'checker' | 'team' | 'unknown';
  hasFlagFormat(): boolean;
}

function parseNetworks(raw: unknown, source: string): TeamNetwork[] {
  const nets: TeamNetwork[] = [];
  for (const item of (raw ?? []) as unknown[]) {
    let cidr: string;
    let label: string;
    if (typeof item === 'string') {
      cidr = item;
      label = item;
    } else if (item && typeof item === 'object') {
      const record = item as Record<string, unknown>;
      cidr = String(record.cidr ?? '');
      label = String(record.label ?? cidr);
    } else {
      continue;
    }
    if (parseCidr(cidr) === null) {
      throw new ConfigError(`bad cidr ${JSON.stringify(cidr)}`);
    }
    nets.push(makeNetwork(label, cidr, source));
  }
  return nets;
}

function parseFlagFormat(raw: unknown): FlagFormat {
  if (!raw || typeof raw !== 'object') return makeFlagFormat({ pattern: '' });
  const record = raw as Record<string, unknown>;
  const pattern = String(record.pattern ?? '');
  let prefix = String(record.prefix ?? '');
  const suffix = String(record.suffix ?? '');
  if (!prefix && pattern.includes('{')) prefix = pattern.split('{')[0] ?? '';
  return makeFlagFormat({
    pattern,
    prefix,
    suffix,
    bodyAlphabet: String(record.body_alphabet ?? ''),
    minLength: Number(record.min_length ?? 0),
  });
}

/** Expand a glob supporting `**`, `*` and `?` into a single RegExp. */
export function globToRegExp(glob: string): RegExp {
  let out = '';
  for (let i = 0; i < glob.length; i += 1) {
    const char = glob[i];
    if (char === '*') {
      if (glob[i + 1] === '*') {
        // `**/` matches any number of directories including none.
        if (glob[i + 2] === '/') {
          out += '(?:.*/)?';
          i += 2;
        } else {
          out += '.*';
          i += 1;
        }
      } else {
        out += '[^/]*';
      }
    } else if (char === '?') {
      out += '[^/]';
    } else if ('\\^$.|+()[]{}'.includes(char as string)) {
      out += `\\${char}`;
    } else {
      out += char;
    }
  }
  return new RegExp(`^${out}$`);
}

function globMatcher(globs: readonly string[]): (relPath: string) => boolean {
  const compiled = globs.map((glob) => globToRegExp(glob));
  return (relPath: string) => {
    const normalised = relPath.replace(/\\/g, '/');
    return compiled.some((regex) => regex.test(normalised));
  };
}

export function isExcluded(
  relPath: string,
  globs: readonly string[] = DEFAULT_EXCLUDED_GLOBS,
): boolean {
  return globMatcher(globs)(relPath);
}

/**
 * Glob `request_logs` entries. Non-glob paths that do not exist are skipped, and
 * glob patterns that match nothing are skipped too, so a config can list a
 * capture directory that is only populated during a live run.
 */
function expandLogPattern(base: string, raw: string): string[] {
  if (!raw.includes('*')) {
    const candidate = path.resolve(base, raw);
    return existsSync(candidate) ? [candidate] : [];
  }
  const segments = raw.replace(/\\/g, '/').split('/');
  let current = path.resolve(base);
  for (let i = 0; i < segments.length; i += 1) {
    const segment = segments[i] as string;
    if (!segment.includes('*')) {
      current = path.join(current, segment);
      continue;
    }
    let entries: string[];
    try {
      entries = readdirSync(current);
    } catch {
      return [];
    }
    const regex = globToRegExp(segment);
    const matched = entries.filter((entry) => regex.test(entry)).sort();
    if (i === segments.length - 1) return matched.map((entry) => path.join(current, entry));
    const next: string[] = [];
    for (const matchedPath of matched) {
      const stat = statSync(path.join(current, matchedPath));
      if (stat.isDirectory()) next.push(...expandLogPattern(path.join(current, matchedPath), segments.slice(i + 1).join('/')));
    }
    return next;
  }
  return [];
}

export function loadConfig(configPath: string): Config {
  // Strip a BOM: operators edit these in Notepad/VS Code, which may add one.
  const raw = readFileSync(configPath, 'utf8').replace(/^\uFEFF/, '');
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(raw) as Record<string, unknown>;
  } catch (error) {
    throw new ConfigError(`invalid JSON in ${configPath}: ${(error as Error).message}`);
  }

  const base = path.dirname(path.resolve(configPath));
  const roots: string[] = [];
  for (const raw of (data.source_roots ?? ['.']) as string[]) {
    const root = path.resolve(base, raw);
    if (!existsSync(root)) throw new ConfigError(`source root does not exist: ${root}`);
    roots.push(root);
  }

  const logs: string[] = [];
  for (const raw of (data.request_logs ?? []) as string[]) {
    logs.push(...expandLogPattern(base, raw));
  }

  const service = String(data.service_name ?? path.basename(base));
  let out = String(data.output_dir ?? 'reports');
  if (!path.isAbsolute(out)) out = path.resolve(base, out);

  const teamNetworks = parseNetworks(data.team_networks, 'config');
  const checkerNetworks = parseNetworks(data.checker_networks, 'config');
  const checkerIpPattern = String(data.checker_ip_pattern ?? '');
  const flagFormat = parseFlagFormat(data.flag_format);

  const config: Config = {
    serviceName: service,
    sourceRoots: roots,
    excludedGlobs: (data.excluded_globs ?? DEFAULT_EXCLUDED_GLOBS) as string[],
    teamNetworks,
    checkerNetworks,
    checkerIpPattern,
    knownFlags: [...((data.known_flags ?? []) as string[])],
    flagFormat,
    requestLogs: logs,
    outputDir: out,
    notes: String(data.notes ?? ''),
    classifyIp(ip: string): 'checker' | 'team' | 'unknown' {
      for (const net of teamNetworks) if (net.contains(ip)) return 'team';
      for (const net of checkerNetworks) if (net.contains(ip)) return 'checker';
      return 'unknown';
    },
    hasFlagFormat: () => flagFormat.known(),
  };
  return config;
}
