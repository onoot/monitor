/**
 * Runtime request analysis.
 *
 * Accepts, per service:
 *   * JSONL / JSON array captures with fields (ts, client_ip, method, path, status, body, headers)
 *   * nginx/Apache combined access logs
 *   * gin's default access log format
 *   * tcpdump-style "what requests came in" dumps pasted into a .log
 *
 * Everything is normalised into `ObservedRequest` and then attributed to an actor
 * (checker / team / unknown) using the configured networks. The output answers
 * the question the jury actually asks: which requests did the checker make, which
 * did teams make, and did the two ever see each other's data.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';
import type { Config } from './config.js';
import { detectFlags } from './flags.js';

const COMBINED_LOG = new RegExp(
  String.raw`^(?<client>\S+)\s+\S+\s+\S+\s+\[(?<ts>[^\]]+)\]\s+` +
    String.raw`"(?<method>[A-Z]+)\s+(?<path>\S+)(?:\s+(?<proto>[^"]*))?"\s+` +
    String.raw`(?<status>\d{3})\s+(?<size>\S+)` +
    String.raw`(?:\s+"(?<ref>[^"]*)"\s+"(?<ua>[^"]*)")?`,
);

/**
 * Gin's default access logger.
 *
 *   [GIN] 2026/10/02 - 04:28:12 | 200 | 365.216µs | 172.23.0.1 | GET  "/"
 *
 * The fields sit in a different order from a combined log and the timestamp is
 * not bracketed, so a Go service produced no runtime records at all before this
 * pattern existed. The body of a request is never in the line, which is why
 * flag writes stay undetectable from this format alone.
 */
const GIN_LOG = new RegExp(
  String.raw`^\[GIN\]\s+(?<ts>\d{4}/\d{2}/\d{2}\s+-\s+\d{2}:\d{2}:\d{2})\s*\|\s*` +
    String.raw`(?<status>\d{3})\s*\|\s*(?<latency>[^|]*?)\s*\|\s*` +
    String.raw`(?<client>\S+)\s*\|\s*(?<method>[A-Z]+)\s+"(?<path>[^"]*)"`,
);

/**
 * Turn gin's `2026/10/02 - 04:28:12` into the same shape the combined parser
 * yields, so both formats sort and group the same way.
 *
 * The line carries no zone, so the result is naive. That is deliberate: inventing
 * an offset would make two records look further apart in time than the log can
 * actually prove, and the engine only uses timestamps for ordering.
 */
export function normaliseGinTs(raw: string): string {
  const match = /^(\d{4})\/(\d{2})\/(\d{2})\s+-\s+(\d{2}):(\d{2}):(\d{2})$/.exec(raw.trim());
  if (!match) return raw.trim();
  const [, year, month, day, hour, minute, second] = match as unknown as string[];
  return `${year}-${month}-${day}T${hour}:${minute}:${second}`;
}

export type Actor = 'checker' | 'team' | 'unknown';

export interface ObservedRequest {
  ts: string;
  clientIp: string;
  actor: Actor | string;
  method: string;
  path: string;
  status: number | null;
  query: string;
  body: string;
  response: string;
  headers: Record<string, string>;
  source: string;
  routeKey(): string;
  toDict(): Record<string, unknown>;
}

export function makeObservedRequest(init: {
  ts?: string;
  clientIp: string;
  actor?: string;
  method: string;
  path: string;
  status?: number | null;
  query?: string;
  body?: string;
  response?: string;
  headers?: Record<string, string>;
  source?: string;
}): ObservedRequest {
  const request: ObservedRequest = {
    ts: init.ts ?? '',
    clientIp: init.clientIp,
    actor: init.actor ?? 'unknown',
    method: init.method,
    path: init.path,
    status: init.status ?? null,
    query: init.query ?? '',
    body: init.body ?? '',
    response: init.response ?? '',
    headers: init.headers ?? {},
    source: init.source ?? '',
    routeKey(): string {
      return `${this.method} ${this.path}`;
    },
    toDict(): Record<string, unknown> {
      return {
        ts: this.ts,
        client_ip: this.clientIp,
        actor: this.actor,
        method: this.method,
        path: this.path,
        query: this.query,
        status: this.status,
        request_body: this.body,
        response_body: this.response,
        headers: this.headers,
        flags_in_response: detectFlags(this.response, this.query),
        flags_in_request: detectFlags(this.body),
        source: this.source,
      };
    },
  };
  return request;
}

export interface ActorProfile {
  actor: string;
  ips: Set<string>;
  requests: number;
  routes: Map<string, number>;
  statuses: Map<number, number>;
  credentialPairs: Set<string>;
  /**
   * Reads and writes are separate signals: a checker PUT hands a flag in, a team
   * GET pulls it out. Collapsing them hides exactly the transition the flag-flow
   * analysis depends on.
   */
  flagReads: number;
  flagWrites: number;
  toDict(): Record<string, unknown>;
}

function makeActorProfile(actor: string): ActorProfile {
  return {
    actor,
    ips: new Set<string>(),
    requests: 0,
    routes: new Map<string, number>(),
    statuses: new Map<number, number>(),
    credentialPairs: new Set<string>(),
    flagReads: 0,
    flagWrites: 0,
    toDict(): Record<string, unknown> {
      return {
        actor: this.actor,
        ips: [...this.ips].sort(),
        request_count: this.requests,
        distinct_routes: this.routes.size,
        routes: Object.fromEntries(
          [...this.routes.entries()].sort((a, b) => b[1] - a[1]),
        ),
        status_counts: Object.fromEntries(
          [...this.statuses.entries()].sort((a, b) => a[0] - b[0]),
        ),
        credential_pairs_seen: [...this.credentialPairs].sort(),
        flag_reads: this.flagReads,
        flag_writes: this.flagWrites,
      };
    },
  };
}

export interface RouteMatrixRow {
  route: string;
  actors: Record<
    string,
    { count: number; flag_reads: number; flag_writes: number; ips: string[] }
  >;
}

export interface RuntimeReport {
  requests: ObservedRequest[];
  profiles: Map<string, ActorProfile>;
  parserNotes: string[];
  crossActorFindings: string[];
  /** Rebuild every derived aggregate after actors have been reassigned. */
  recompute(): void;
  /**
   * Assign actors to records still marked unknown, then recompute.
   *
   * Returns the IP -> actor mapping that was applied. Recomputing here keeps the
   * profiles and cross-actor findings consistent with the new labels; mutating
   * `actor` on its own would silently leave both stale.
   */
  classifyUnknown(cfg: Config): Record<string, string>;
  routeMatrix(): RouteMatrixRow[];
  toDict(): Record<string, unknown>;
}

export function createRuntimeReport(
  init: Partial<{
    requests: ObservedRequest[];
    parserNotes: string[];
  }> = {},
): RuntimeReport {
  const report: RuntimeReport = {
    requests: init.requests ?? [],
    profiles: new Map<string, ActorProfile>(),
    parserNotes: init.parserNotes ?? [],
    crossActorFindings: [],
    recompute(): void {
      this.profiles = profileRequests(this.requests);
      this.crossActorFindings = crossActor(this);
    },
    classifyUnknown(cfg: Config): Record<string, string> {
      const applied: Record<string, string> = {};
      for (const request of this.requests) {
        if (request.actor !== 'unknown') continue;
        const actor = cfg.classifyIp(request.clientIp);
        request.actor = actor;
        if (!(request.clientIp in applied)) applied[request.clientIp] = actor;
      }
      this.recompute();
      return applied;
    },
    routeMatrix(): RouteMatrixRow[] {
      const routes = new Map<
        string,
        Map<
          string,
          { count: number; flag_reads: number; flag_writes: number; ips: Set<string> }
        >
      >();
      for (const request of this.requests) {
        let actors = routes.get(request.routeKey());
        if (!actors) {
          actors = new Map();
          routes.set(request.routeKey(), actors);
        }
        let entry = actors.get(request.actor);
        if (!entry) {
          entry = { count: 0, flag_reads: 0, flag_writes: 0, ips: new Set<string>() };
          actors.set(request.actor, entry);
        }
        entry.count += 1;
        entry.ips.add(request.clientIp);
        if (detectFlags(request.response, request.query).length > 0) {
          entry.flag_reads += 1;
        }
        if (WRITE_METHODS.has(request.method) && detectFlags(request.body).length > 0) {
          entry.flag_writes += 1;
        }
      }
      return [...routes.entries()]
        .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
        .map(([route, actors]) => ({
          route,
          actors: Object.fromEntries(
            [...actors.entries()]
              .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0))
              .map(([name, data]) => [
                name,
                {
                  count: data.count,
                  flag_reads: data.flag_reads,
                  flag_writes: data.flag_writes,
                  ips: [...data.ips].sort(),
                },
              ]),
          ),
        }));
    },
    toDict(): Record<string, unknown> {
      return {
        request_count: this.requests.length,
        parser_notes: this.parserNotes,
        profiles: Object.fromEntries(
          [...this.profiles.entries()].map(([key, value]) => [key, value.toDict()]),
        ),
        route_matrix: this.routeMatrix(),
        cross_actor_findings: this.crossActorFindings,
      };
    },
  };
  return report;
}

const CREDENTIAL_KEYS = [
  'login', 'username', 'user', 'email', 'password', 'passwd', 'pass', 'pwd',
];

export const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH']);

export function loadRequests(paths: readonly string[], cfg: Config): RuntimeReport {
  const report = createRuntimeReport();
  for (const file of paths) {
    // utf-8-sig: captures edited on Windows may carry a BOM.
    const text = readFileSync(file, 'utf8').replace(/^\uFEFF/, '');
    if (!text.trim()) continue;
    if (!tryJson(text, file, report)) parseLines(text, file, cfg, report);
  }
  report.recompute();
  return report;
}

function tryJson(text: string, file: string, report: RuntimeReport): boolean {
  // A gin log opens with `[GIN]`, which looks like a JSON array to the sniffer
  // below. Recognise a supported line format first so Go services do not get a
  // "not valid JSON" note on every report.
  const first = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .find((line) => line && !line.startsWith('#'));
  if (first && (COMBINED_LOG.test(first) || GIN_LOG.test(first))) return false;

  const stripped = text.trimStart();
  if (!stripped.startsWith('[') && !stripped.startsWith('{')) return false;
  let data: unknown;
  try {
    data = JSON.parse(stripped);
  } catch {
    report.parserNotes.push(
      `${path.basename(file)}: not valid JSON, fell back to line parser`,
    );
    return false;
  }
  const records = Array.isArray(data)
    ? data
    : ((data as Record<string, unknown>).requests as unknown[]) ?? [];
  if (!Array.isArray(records)) return false;
  for (const record of records) {
    if (record && typeof record === 'object' && !Array.isArray(record)) {
      report.requests.push(fromDict(record as Record<string, unknown>, file));
    }
  }
  report.parserNotes.push(
    `${path.basename(file)}: ${records.length} requests (JSON)`,
  );
  return true;
}

/** Deterministic serialisation: sorted keys, so runs diff cleanly. */
function stringify(value: unknown): string {
  if (value === null || value === undefined) return '';
  if (typeof value === 'object') {
    return JSON.stringify(value, (_key, inner) => {
      if (inner && typeof inner === 'object' && !Array.isArray(inner)) {
        return Object.fromEntries(
          Object.entries(inner as Record<string, unknown>).sort(([a], [b]) =>
            a < b ? -1 : a > b ? 1 : 0,
          ),
        );
      }
      return inner;
    });
  }
  return String(value);
}

function fromDict(record: Record<string, unknown>, file: string): ObservedRequest {
  const pick = (...keys: string[]): string => {
    for (const key of keys) {
      const value = record[key];
      if (value !== undefined && value !== null && value !== '') return String(value);
    }
    return '';
  };

  let pathValue = pick('path', 'url', 'uri') || '/';
  let query = pick('query', 'query_string');
  if (pathValue.includes('?') && !query) {
    const at = pathValue.indexOf('?');
    query = pathValue.slice(at + 1);
    pathValue = pathValue.slice(0, at);
  }

  const rawHeaders = record.headers;
  const headers: Record<string, string> = {};
  if (rawHeaders && typeof rawHeaders === 'object' && !Array.isArray(rawHeaders)) {
    for (const [key, value] of Object.entries(rawHeaders as Record<string, unknown>)) {
      headers[key] = String(value);
    }
  }

  const rawStatus = record.status ?? record.status_code;
  const statusText = rawStatus === undefined || rawStatus === null ? '' : String(rawStatus);
  const status = /^\d+$/.test(statusText) ? Number.parseInt(statusText, 10) : null;

  return makeObservedRequest({
    ts: pick('ts', 'time', 'timestamp'),
    clientIp: pick('client_ip', 'ip', 'remote_addr') || '0.0.0.0',
    actor: pick('actor') || 'unknown',
    method: (pick('method') || 'GET').toUpperCase(),
    path: pathValue,
    status,
    query,
    body: stringify(record.body ?? record.request_body ?? ''),
    response: stringify(
      record.response ?? record.response_body ?? record.body_out ?? '',
    ),
    headers,
    source: path.basename(file),
  });
}

function parseLines(
  text: string,
  file: string,
  _cfg: Config,
  report: RuntimeReport,
): void {
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const match = COMBINED_LOG.exec(line) ?? GIN_LOG.exec(line);
    if (!match) {
      report.parserNotes.push(
        `${path.basename(file)}: unparsed line: ${line.slice(0, 120)}`,
      );
      continue;
    }
    const groups = match.groups ?? {};
    let target = groups.path ?? '';
    let query = '';
    if (target.includes('?')) {
      const at = target.indexOf('?');
      query = target.slice(at + 1);
      target = target.slice(0, at);
    }
    // Gin's timestamp is `2006/01/02 - 15:04:05`; the combined form is already
    // bracketed and left alone.
    const rawTs = groups.ts ?? '';
    const ts = rawTs.includes('/') ? normaliseGinTs(rawTs) : rawTs;
    report.requests.push(
      makeObservedRequest({
        ts,
        clientIp: groups.client ?? '',
        actor: 'unknown',
        method: groups.method ?? 'GET',
        path: target,
        status: Number.parseInt(groups.status ?? '0', 10),
        query,
        body: '',
        response: '',
        headers: { 'user-agent': groups.ua ?? '' },
        source: path.basename(file),
      }),
    );
  }
}

function profileRequests(requests: readonly ObservedRequest[]): Map<string, ActorProfile> {
  const profiles = new Map<string, ActorProfile>();
  for (const request of requests) {
    let profile = profiles.get(request.actor);
    if (!profile) {
      profile = makeActorProfile(request.actor);
      profiles.set(request.actor, profile);
    }
    profile.ips.add(request.clientIp);
    profile.requests += 1;
    const key = request.routeKey();
    profile.routes.set(key, (profile.routes.get(key) ?? 0) + 1);
    if (request.status !== null) {
      profile.statuses.set(request.status, (profile.statuses.get(request.status) ?? 0) + 1);
    }
    if (detectFlags(request.response, request.query).length > 0) {
      profile.flagReads += 1;
    }
    if (WRITE_METHODS.has(request.method) && detectFlags(request.body).length > 0) {
      profile.flagWrites += 1;
    }
    const pair = credentialPair(request);
    if (pair) profile.credentialPairs.add(pair);
  }
  return profiles;
}

function credentialPair(request: ObservedRequest): string | null {
  if (!WRITE_METHODS.has(request.method)) return null;
  const blob = `${request.body} ${request.query}`;
  if (!blob.includes('=')) return null;
  const lowered = blob.toLowerCase();
  if (!CREDENTIAL_KEYS.some((key) => lowered.includes(key))) return null;

  const values = new Map<string, string>();
  try {
    const parsed: unknown = JSON.parse(request.body);
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      for (const [key, value] of Object.entries(flatten(parsed))) {
        if (typeof value === 'string' || typeof value === 'number') {
          values.set(key.toLowerCase(), String(value));
        }
      }
    } else {
      throw new TypeError('not an object');
    }
  } catch {
    for (const chunk of blob.split('&')) {
      if (!chunk.includes('=')) continue;
      const at = chunk.indexOf('=');
      values.set(chunk.slice(0, at).trim().toLowerCase(), chunk.slice(at + 1).trim());
    }
  }

  let user: string | undefined;
  for (const key of ['login', 'username', 'user', 'email']) {
    const value = values.get(key);
    if (value) {
      user = value;
      break;
    }
  }
  let password: string | undefined;
  for (const key of ['password', 'passwd', 'pass', 'pwd']) {
    const value = values.get(key);
    if (value) {
      password = value;
      break;
    }
  }
  if (user && password) return `${user}:${password}`;
  return null;
}

function flatten(value: unknown, prefix = ''): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      Object.assign(out, flatten(item, `${prefix}.${index}`));
    });
  } else if (value && typeof value === 'object') {
    for (const [key, inner] of Object.entries(value as Record<string, unknown>)) {
      const name = prefix ? `${prefix}.${key}` : key;
      Object.assign(out, flatten(inner, name));
    }
  } else {
    out[prefix] = value;
  }
  return out;
}

/** Routes touched by more than one actor class - the interesting surface. */
function crossActor(report: RuntimeReport): string[] {
  const notes: string[] = [];
  const byRoute = new Map<string, Map<string, number>>();
  const flagByRoute = new Map<string, Map<string, number>>();

  const bump = (map: Map<string, Map<string, number>>, key: string, actor: string) => {
    let inner = map.get(key);
    if (!inner) {
      inner = new Map<string, number>();
      map.set(key, inner);
    }
    inner.set(actor, (inner.get(actor) ?? 0) + 1);
  };

  for (const request of report.requests) {
    bump(byRoute, request.routeKey(), request.actor);
    if (detectFlags(request.response, request.query).length > 0) {
      bump(flagByRoute, request.routeKey(), request.actor);
    }
  }

  for (const [routeKey, actors] of [...byRoute.entries()].sort((a, b) =>
    a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0,
  )) {
    const classes = [...actors.keys()].sort();
    if (classes.length > 1) {
      notes.push(
        `${routeKey}: reached by ${classes.map((a) => `${a}(${actors.get(a)})`).join(', ')}`,
      );
    }
    const flags = flagByRoute.get(routeKey);
    if (flags && flags.has('checker') && flags.has('team')) {
      notes.push(
        `${routeKey}: flag-shaped data observed for BOTH checker and team traffic - ` +
          'verify the authorisation boundary',
      );
    }
  }
  return notes;
}

function csvCell(value: string): string {
  if (/[",\n\r]/.test(value)) return `"${value.replace(/"/g, '""')}"`;
  return value;
}

export function writeRequestsCsv(report: RuntimeReport, outPath: string): void {
  mkdirSync(path.dirname(outPath), { recursive: true });
  const rows: string[] = [
    [
      'ts', 'actor', 'client_ip', 'method', 'path', 'query', 'status',
      'request_body', 'response_body', 'flags_in_request', 'flags_in_response',
    ].join(','),
  ];
  for (const request of report.requests) {
    rows.push(
      [
        request.ts,
        request.actor,
        request.clientIp,
        request.method,
        request.path,
        request.query,
        request.status === null ? '' : String(request.status),
        request.body.slice(0, 2000),
        request.response.slice(0, 2000),
        detectFlags(request.body).join('|'),
        detectFlags(request.response, request.query).join('|'),
      ]
        .map((cell) => csvCell(String(cell)))
        .join(','),
    );
  }
  writeFileSync(outPath, `${rows.join('\n')}\n`, 'utf8');
}
