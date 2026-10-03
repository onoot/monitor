/**
 * Flag detection and flag-flow inference.
 *
 * Flag patterns are never guessed. Resolution order:
 *
 *   1. `flagFormat.pattern` from config (xeger syntax, as checkers emit it)
 *   2. `knownFlags` supplied by the operator
 *   3. a conservative built-in heuristic, reported as UNCONFIRMED and never
 *      used for an automatic poisoning decision
 *
 * The third source exists only so the tool can tell an operator "no flag pattern
 * configured, put/get behaviour cannot be verified" instead of silently doing
 * nothing.
 */

import { collapseWhitespace } from './models.js';
import type { Config } from './config.js';

/** Conservative: requires a flag-shaped wrapper, so ordinary prose does not match. */
export const HEURISTIC_FLAG = /\b[A-Za-z][A-Za-z0-9_]{1,24}\{[^{}]{4,120}\}/g;

/** Mean "the pattern is embedded regex, not xeger output". */
const UNSUPPORTED_LITERAL = /[\\|()]|\(\?/;

/** Character class body we accept: ranges, digits and `_`. */
const CLASS_BODY = /^(?:[a-zA-Z0-9]|[a-zA-Z0-9]-[a-zA-Z0-9]|_)+$/;

const CLASS_TOKEN = /\[([^\]\n]*)\](\{\d+(?:,\d*)?\})?/g;

export interface XegerItem {
  kind: 'lit' | 'class';
  value: string;
  width: number | null;
}

export interface FlagMatch {
  value: string;
  source: string;
  confirmed: boolean;
}

export interface FlagFlowNode {
  kind: string;
  detail: string;
  file: string;
  line: number;
}

export interface FlagFlow {
  patternKnown: boolean;
  patternSource: string;
  mask: string | null;
  prefix: string;
  putPoints: FlagFlowNode[];
  getPoints: FlagFlowNode[];
  storageHints: FlagFlowNode[];
  exposureHints: FlagFlowNode[];
  observedCheckerReads: string[];
  observedTeamReads: string[];
  warnings: string[];
}

export interface RuntimeRouteLike {
  method?: string;
  path?: string;
}

/** Distinct flag-shaped strings in a payload. */
export function detectFlags(blob: string, query = ''): string[] {
  if (!blob && !query) return [];
  const haystack = `${blob}\n${query}`;
  const found: string[] = [];
  const seen = new Set<string>();
  for (const match of haystack.matchAll(HEURISTIC_FLAG)) {
    const value = match[0];
    if (!seen.has(value)) {
      seen.add(value);
      found.push(value);
    }
  }
  return found;
}

function classBody(chars: string): string | null {
  if (!chars || !CLASS_BODY.test(chars)) return null;
  // A trailing dash denotes an open-ended range, which we refuse.
  if (chars.endsWith('-')) return null;
  return chars;
}

function quantifier(quant: string | undefined): number | null {
  if (!quant) return 1;
  const inner = quant.slice(1, -1);
  if (inner.includes(',')) {
    const low = inner.slice(0, inner.indexOf(','));
    const parsed = Number.parseInt(low, 10);
    return Number.isNaN(parsed) ? null : parsed;
  }
  const parsed = Number.parseInt(inner, 10);
  return Number.isNaN(parsed) ? null : parsed;
}

/**
 * Split a pattern into literal and character-class items.
 *
 * Returns null when the pattern uses anything outside the subset checkers
 * actually emit, so callers refuse instead of producing a wrong regex.
 */
export function xegerTokens(pattern: string): XegerItem[] | null {
  const items: XegerItem[] = [];
  const regex = new RegExp(CLASS_TOKEN.source, 'g');
  let pos = 0;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(pattern)) !== null) {
    const literal = pattern.slice(pos, match.index);
    if (literal) {
      if (UNSUPPORTED_LITERAL.test(literal)) return null;
      items.push({ kind: 'lit', value: literal, width: null });
    }
    const body = classBody(match[1] ?? '');
    const width = quantifier(match[2]);
    if (body === null || width === null) return null;
    items.push({ kind: 'class', value: body, width });
    pos = match.index + match[0].length;
  }
  const tail = pattern.slice(pos);
  if (tail) {
    if (UNSUPPORTED_LITERAL.test(tail)) return null;
    items.push({ kind: 'lit', value: tail, width: null });
  }
  return items;
}

function escapeRegex(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Translate the restricted xeger subset checkers use into an anchored regex.
 *
 * Escapes every literal character by hand rather than reusing a library, because
 * the literal part must be matched exactly and JS `RegExp` escaping differs from
 * Python's `re.escape` for the characters checkers emit.
 */
export function xegerToRegex(pattern: string): RegExp | null {
  const items = xegerTokens(pattern);
  if (items === null) return null;
  const out: string[] = ['^'];
  for (const item of items) {
    if (item.kind === 'lit') {
      out.push(escapeRegex(item.value));
    } else {
      const body = `[${item.value}]`;
      out.push(item.width === 1 ? body : `${body}{${item.width}}`);
    }
  }
  out.push('$');
  return new RegExp(out.join(''));
}

/**
 * Return the literal (prefix, suffix) around the variable part of a pattern.
 *
 * Poisoning replaces only the variable span, so `alctf{[a-z]{16}}` keeps its
 * `alctf{` and `}` and only the middle 16 characters change.
 */
export function splitEnvelope(pattern: string): [string, string] {
  const items = xegerTokens(pattern);
  if (!items || items.length === 0) return ['', ''];
  const prefix = items[0]?.kind === 'lit' ? items[0].value : '';
  const last = items[items.length - 1];
  const suffix = last && last.kind === 'lit' && items.length > 1 ? last.value : '';
  return [prefix, suffix];
}

/** Detect flags using configured sources only. No heuristic here. */
export function detectKnown(
  blob: string,
  cfg?: Config | null,
  known?: readonly string[],
): FlagMatch[] {
  if (!blob) return [];
  const knownList = known ?? (cfg ? cfg.knownFlags : []);
  const matches: FlagMatch[] = [];
  const seen = new Set<string>();

  if (cfg?.flagFormat.known()) {
    const regex = xegerToRegex(cfg.flagFormat.pattern);
    if (regex) {
      for (const value of blob.match(regex) ?? []) {
        if (!seen.has(value)) {
          seen.add(value);
          matches.push({ value, source: 'config_pattern', confirmed: true });
        }
      }
    }
  }

  for (const value of knownList) {
    if (value && blob.includes(value) && !seen.has(value)) {
      seen.add(value);
      matches.push({ value, source: 'known_flag', confirmed: true });
    }
  }
  return matches;
}

function node(kind: string, detail: string, file = '', line = 0): FlagFlowNode {
  return { kind, detail, file, line };
}

const WRITE_HINTS =
  /\b(?:set_?flag|put_?flag|save_?flag|create_?flag|insert_?flag|add_?flag|write_?flag|flags?\s*=\s*request|flags?\s*=\s*params|notes?form|flag.*(?:insert|update|create|save))\b/i;

const READ_HINTS =
  /\b(?:get_?flag|read_?flag|find_?flag|fetch_?flag|load_?flag|show_?flag|flag.*(?:select|find|read|open)|\/flags?\b)\b/i;

const STORAGE_HINTS =
  /(?:\/flags?\b|flag\.txt|readFile|open\(|yaml\.dump|json\.dump|INSERT\s+INTO\s+\w*flag|UPDATE\s+\w*flag|flags?\s*[:=]\s*self\.)/i;

const SINK_HINTS = /(?:innerHTML|safe\b|jsonify|res\.send|echo\s+\$|v-html)/i;

/** Infer where flags are written, read, stored and potentially exposed. */
export function inferFlow(
  cfg: Config,
  sourceTexts: ReadonlyMap<string, string> | Record<string, string>,
  runtimeRoutes: Record<string, RuntimeRouteLike[]> = {},
): FlagFlow {
  const patternKnown = cfg.flagFormat.known() || cfg.knownFlags.length > 0;
  const patternSource = cfg.flagFormat.known()
    ? 'config_pattern'
    : cfg.knownFlags.length > 0
      ? 'known_flag'
      : 'unconfirmed_heuristic';

  const flow: FlagFlow = {
    patternKnown,
    patternSource,
    mask: cfg.flagFormat.literalMask(),
    prefix: cfg.flagFormat.prefix,
    putPoints: [],
    getPoints: [],
    storageHints: [],
    exposureHints: [],
    observedCheckerReads: [],
    observedTeamReads: [],
    warnings: [],
  };

  if (!patternKnown) {
    flow.warnings.push(
      'No flag pattern configured. Flag put/get verification is unavailable and ' +
        'poisoning stays disabled. Set flagFormat.pattern (xeger syntax) or ' +
        'knownFlags in the service config.',
    );
  }

  const entries =
    sourceTexts instanceof Map ? [...sourceTexts.entries()] : Object.entries(sourceTexts);

  for (const [rel, text] of entries) {
    const lines = text.split(/\r?\n/);
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index] ?? '';
      const trimmed = line.trim();
      if (trimmed.length < 4) continue;
      const detail = collapseWhitespace(trimmed).slice(0, 200);
      const lineNo = index + 1;
      if (WRITE_HINTS.test(line)) flow.putPoints.push(node('put_candidate', detail, rel, lineNo));
      if (READ_HINTS.test(line)) flow.getPoints.push(node('get_candidate', detail, rel, lineNo));
      if (STORAGE_HINTS.test(line)) flow.storageHints.push(node('storage', detail, rel, lineNo));
      if (SINK_HINTS.test(line) && /flag/i.test(line)) {
        flow.exposureHints.push(node('exposure', detail, rel, lineNo));
      }
    }
  }

  for (const route of runtimeRoutes.__all__ ?? []) {
    const key = `${route.method ?? '?'} ${route.path ?? '?'}`;
    if (/flag/i.test(key)) flow.exposureHints.push(node('route_named_flag', key));
  }

  if (flow.putPoints.length === 0) {
    flow.warnings.push('No flag write path identified in source; confirm the put flow manually.');
  }
  if (flow.getPoints.length === 0) {
    flow.warnings.push('No flag read path identified in source; confirm the get flow manually.');
  }
  return flow;
}

export function flagFlowToDict(flow: FlagFlow): Record<string, unknown> {
  return {
    pattern_known: flow.patternKnown,
    pattern_source: flow.patternSource,
    mask: flow.mask,
    prefix: flow.prefix,
    put_points: flow.putPoints,
    get_points: flow.getPoints,
    storage_hints: flow.storageHints,
    exposure_hints: flow.exposureHints,
    observed_checker_flag_reads: flow.observedCheckerReads,
    observed_team_flag_reads: flow.observedTeamReads,
    warnings: flow.warnings,
  };
}