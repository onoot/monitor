/**
 * The analytics surface: the dashboard and the API behind it.
 *
 * This listener is where the operator's own data lives, so it is the surface that
 * refuses strangers outright. A refused peer gets its connection destroyed with no
 * response at all, which is what a client reports as `ERR_CONNECTION_REFUSED` --
 * deliberately indistinguishable from a port that is not listening, so a scan of
 * the emulated network learns nothing about what is behind it.
 *
 * The same allowlist governs this listener as the ingress, with one addition:
 * write endpoints require the admin role rather than merely being on the list,
 * because "on the list" is a network fact and "may change the network" is a
 * decision, and only an operator should get to make it.
 */

import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import nodePath from 'node:path';
import { SignJWT, jwtVerify } from 'jose';
import type { Socket } from 'node:net';

import type { GatewayConfig } from './config.js';
import type { AccountStore } from './accounts.js';
import { discoverServices, type DiscoveryCandidate } from './discovery.js';
import type { Gateway } from './gateway.js';
import { RequestHistory } from './history.js';
import { launchService, listServiceProjects, serviceStatus, stopService, type Exec } from './launcher.js';
import { buildTopology, topologyToYaml } from './topology.js';
import {
  emptyGraphLayout,
  loadGraphLayout,
  normalizeGraphLayout,
  saveGraphLayout,
  type GraphLayout,
} from './graphLayout.js';
import { normaliseRemoteAddress, type NetworkMap, type Principal, type PrincipalSource } from './network.js';
import {
  loadLabels,
  loadServices,
  saveLabels,
  saveServices,
  type LabelOverride,
  type ServiceEntry,
} from './state.js';
import { UI_HTML } from './ui.js';

export interface Role {
  kind: 'admin' | 'team';
  team: string | null;
  login: string;
}

export interface Session {
  token: string;
  role: Role;
  createdAt: number;
}

export interface AuthOptions {
  /**
   * Verify a login. May be async, because a real check costs a deliberate
   * password-hashing delay.
   *
   * The default accepts nothing, so an unconfigured surface is closed rather
   * than open.
   */
  verify?(login: string, password: string): Role | null | Promise<Role | null>;
  sessionTtlMs?: number;
  /**
   * Sign sessions as JWTs (HS256) instead of holding them in memory. A token
   * then survives a restart of the surface as long as the secret is stable,
   * which is the whole point of an operator dashboard: a rebuild of the
   * container must not log the operator out. The flip side is that a token is
   * valid until its `exp`, so logout keeps a local denylist until then.
   */
  jwtSecret?: Uint8Array;
  /**
   * Directory for the operator's own state (`labels.json`, `services.json`).
   * When omitted the endpoints still work but nothing is persisted across a
   * restart.
   */
  stateDir?: string;
  /**
   * Where the UI's auto-detection scans for `docker-compose` and `.env` files.
   * The API lets the operator pass a different directory per scan.
   */
  discoveryDir?: string;
  /** Top-level folders of the discovery root that are not team services. */
  discoverSkip?: Set<string>;
  /**
   * Directory the launch/stop endpoints run `docker compose` in. Defaults to
   * `discoveryDir`, because on a host one directory both names the services and
   * holds their compose files. On a stand it is the mount the services folder is
   * also scanned through.
   */
  launchDir?: string;
  /** Container name this process runs as, so it can join a launched network. */
  selfContainer?: string;
  /** Injectable docker runner for launch/stop/status; tests pass a fake. */
  launchRun?: Exec;
  /** Capture root (`/data`); the clean-stand endpoint empties it. */
  dataDir?: string;
  /**
   * Read-only root of the generated analysis reports (`reports/<service>/`).
   * The Reports tab lists the services found here and serves `report.md` and
   * `report.json` unchanged; generation happens outside the gateway (the ad
   * scanner), so this surface only reads.
   */
  reportsDir?: string;
  /**
   * The writable account store behind `/api/accounts`. When present, an admin
   * can list, create, edit and remove logins from the dashboard, and any
   * signed-in user can change their own password. When absent the endpoints
   * answer 503 and only the injected `verify` authenticates.
   */
  accounts?: AccountStore;
}

export class AuthError extends Error {
  readonly status: number;
  constructor(message: string, status = 401) {
    super(message);
    this.name = 'AuthError';
    this.status = status;
  }
}

const SESSIONS = new Map<string, Session>();

/** Constant-time compare, so a wrong password cannot be found by timing. */
function safeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function randomToken(): string {
  return randomBytes(32).toString('hex');
}

/**
 * A session store, owned by one analytics server.
 *
 * Deliberately not module-level: two surfaces in the same process must not be
 * able to present each other's tokens, and a global would make that happen.
 */
export class SessionStore {
  private readonly sessions = new Map<string, Session>();
  private readonly ttl: number;

  constructor(ttlMs: number) {
    this.ttl = ttlMs;
  }

  issue(role: Role, now: number): Session {
    const token = randomToken();
    const session: Session = { token, role, createdAt: now };
    this.sessions.set(token, session);
    return session;
  }

  get(token: string, now: number): Session {
    const session = this.sessions.get(token);
    if (session === undefined) throw new AuthError('no such session');
    if (now - session.createdAt > this.ttl) {
      this.sessions.delete(token);
      throw new AuthError('session expired');
    }
    return session;
  }

  drop(token: string): void {
    this.sessions.delete(token);
  }

  get size(): number {
    return this.sessions.size;
  }
}

/**
 * Exchange a login and password for a role.
 *
 * Throws when no account store is configured, so a surface that was started
 * without credentials is closed rather than quietly open to anyone on the list.
 */
export async function verifyCredentials(
  loginName: string,
  password: string,
  options: AuthOptions,
): Promise<Role> {
  const verify = options.verify;
  if (verify === undefined) {
    throw new AuthError('no accounts configured; the analytics surface is closed', 503);
  }
  const role = await verify(loginName, password);
  if (role === null || !safeEqual(role.login, loginName)) {
    // One message for a wrong login and a wrong password, so the response does
    // not confirm which accounts exist.
    throw new AuthError('invalid login or password');
  }
  return role;
}

export function requireAdmin(session: Session): void {
  if (session.role.kind !== 'admin') {
    throw new AuthError('admin role required', 403);
  }
}

function dropConnection(socket: Socket): void {
  socket.resetAndDestroy();
}

/** The address labels the operator placed, plus the config ranges. */
export interface LabelsApi {
  overrides: LabelOverride[];
  /** Everything the map now classifies, config and labels together. */
  effective: ReturnType<NetworkMap['describe']>;
  /** Team names the UI can offer when labelling an address. */
  teams: string[];
  /** Team names marked as the operator's own, for the "наша" groupings. */
  ownTeams: string[];
  /** The config's `own_team`, once the operator names one. */
  ownTeam: string | null;
}

function labelsView(ingress: Gateway, overrides: LabelOverride[], ownTeam: string | null): LabelsApi {
  const configTeams = new Set<string>();
  const ownTeams = new Set<string>();
  if (ownTeam !== null) ownTeams.add(ownTeam);
  for (const range of (ingress.network.describe())) {
    if (range.kind !== 'team') continue;
    if (range.team !== undefined) configTeams.add(range.team);
    if (range.own === true && range.team !== undefined) ownTeams.add(range.team);
  }
  for (const entry of overrides) {
    if (entry.kind === 'team' && entry.team !== undefined) configTeams.add(entry.team);
  }
  return {
    overrides,
    effective: ingress.network.describe(),
    teams: [...configTeams],
    ownTeams: [...ownTeams],
    ownTeam,
  };
}

function isLabelKind(kind: unknown): kind is Principal {
  return kind === 'checker' || kind === 'admin' || kind === 'team' || kind === 'unknown';
}

/** A service folder name that is safe to join under the reports root. */
const REPORT_NAME = /^[A-Za-z0-9._-]+$/;

export interface ReportSummary {
  service: string;
  generatedUtc: string | null;
  filesScanned: number | null;
  findings: number | null;
  warnings: number | null;
}

function readJsonFile(file: string): Record<string, unknown> | null {
  try {
    return JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/**
 * The per-service report folders under the reports root.
 *
 * A folder is a report only when it holds a parseable `report.json`; anything
 * else is skipped, so a stray directory never shows up as a service. The
 * summary keeps the fields the Reports tab needs without shipping the whole
 * report into the list response.
 */
export function listReports(dir: string): ReportSummary[] {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return [];
  }
  const out: ReportSummary[] = [];
  for (const name of entries) {
    const base = nodePath.join(dir, name);
    try {
      if (!statSync(base).isDirectory()) continue;
    } catch {
      continue;
    }
    const report = readJsonFile(nodePath.join(base, 'report.json'));
    if (report === null) continue;
    const meta = (report.meta ?? {}) as Record<string, unknown>;
    out.push({
      service: typeof meta.service === 'string' ? meta.service : name,
      generatedUtc: typeof meta.generated_utc === 'string' ? meta.generated_utc : null,
      filesScanned: typeof meta.files_scanned === 'number' ? meta.files_scanned : null,
      findings: Array.isArray(report.findings) ? report.findings.length : null,
      warnings: Array.isArray(report.warnings) ? report.warnings.length : null,
    });
  }
  return out.sort((a, b) => a.service.localeCompare(b.service));
}

/**
 * A compact, machine-readable snapshot of everything the monitor has seen.
 *
 * This is the payload an analysis agent consumes when it cannot read the JSONL
 * files itself: aggregate counts by principal/outcome/service/team, every flag
 * still in memory, the artifacts, and an index of the reports on disk. The
 * in-memory window is the live view; the per-service `report.json` files (listed
 * under `reports`) carry the full history.
 */
export function buildDigest(
  history: RequestHistory,
  reportsDir: string | undefined,
  limit = 200,
): Record<string, unknown> {
  const stats = history.stats();
  return {
    schema: 'ad-monitor-digest/1',
    generated_at: new Date().toISOString(),
    window: { kind: 'in-memory', attempts: stats.attempts, dropped: stats.dropped },
    totals: {
      per_principal: stats.perPrincipal,
      per_outcome: stats.perOutcome,
      per_service: stats.perService,
      per_team: stats.perTeam,
    },
    flags: history.recentFlags(limit).map((flag) => ({
      value: flag.value,
      at: flag.at,
      ip: flag.ip,
      principal: flag.principal,
      team: flag.team,
      service: flag.service ?? null,
      method: flag.method,
      target: flag.target,
      outcome: flag.outcome,
    })),
    artifacts: history.recentArtifacts(limit).map((artifact) => ({
      type: artifact.type,
      value: artifact.value,
      at: artifact.at,
      principal: artifact.principal,
      service: artifact.service ?? null,
      method: artifact.method,
      target: artifact.target,
      outcome: artifact.outcome,
    })),
    reports: reportsDir === undefined ? [] : listReports(reportsDir),
  };
}

/** The digest as Markdown, for pasting straight into an agent prompt. */
export function digestMarkdown(digest: Record<string, unknown>): string {
  const window = digest.window as { attempts: number; dropped: number };
  const totals = digest.totals as {
    per_principal: Record<string, number>;
    per_outcome: Record<string, number>;
    per_service: Record<string, number>;
    per_team: Record<string, number>;
  };
  const flags = digest.flags as {
    value: string;
    at: string;
    principal: string;
    team: string | null;
    method: string;
    target: string;
    outcome: string;
  }[];
  const reports = digest.reports as ReportSummary[];
  const lines: string[] = [];
  lines.push('# Monitoring digest');
  lines.push('');
  lines.push(`- Generated: ${String(digest.generated_at)}`);
  lines.push(`- Window: in-memory, ${window.attempts} attempts (${window.dropped} evicted)`);
  lines.push('');
  const section = (title: string, counts: Record<string, number>): void => {
    lines.push(`## ${title}`);
    const keys = Object.keys(counts);
    if (keys.length === 0) {
      lines.push('- (none)');
      lines.push('');
      return;
    }
    for (const key of keys.sort((a, b) => (counts[b] ?? 0) - (counts[a] ?? 0))) {
      lines.push(`- ${key}: ${counts[key]}`);
    }
    lines.push('');
  };
  section('By principal', totals.per_principal);
  section('By outcome', totals.per_outcome);
  section('By service', totals.per_service);
  section('By team', totals.per_team);
  lines.push('## Flags observed');
  if (flags.length === 0) lines.push('- (none)');
  else {
    for (const flag of flags) {
      const who = flag.team === null ? flag.principal : `${flag.principal}/${flag.team}`;
      lines.push(`- \`${flag.value}\` - ${who} ${flag.method} ${flag.target} (${flag.outcome}) at ${flag.at}`);
    }
  }
  lines.push('');
  lines.push('## Reports on disk');
  if (reports.length === 0) lines.push('- (none)');
  else {
    for (const report of reports) {
      lines.push(
        `- ${report.service}: ${report.findings ?? '?'} findings, ${report.warnings ?? '?'} warnings` +
          `, generated ${report.generatedUtc ?? '?'}`,
      );
    }
  }
  lines.push('');
  return lines.join('\n');
}

function readJsonBody(req: http.IncomingMessage, cap = 64 * 1024): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > cap) {
        reject(new AuthError('body too large', 413));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      const text = Buffer.concat(chunks).toString('utf8').trim();
      if (text.length === 0) return resolve({});
      try {
        resolve(JSON.parse(text));
      } catch {
        reject(new AuthError('body is not valid JSON', 400));
      }
    });
    req.on('error', reject);
  });
}

function bearer(req: http.IncomingMessage): string | undefined {
  const header = req.headers.authorization;
  if (typeof header !== 'string') return undefined;
  const match = /^Bearer\s+(.+)$/i.exec(header.trim());
  return match?.[1];
}

export interface AnalyticsServer {
  server: http.Server;
  sessions: SessionStore | null;
  listen(): Promise<number>;
  /** Apply the persisted services to the ingress; see the entry point. */
  bootstrap(): Promise<{ ok: boolean; error?: string }>;
  close(): Promise<void>;
}

export function createAnalyticsServer(
  config: GatewayConfig,
  ingress: Gateway,
  options: AuthOptions = {},
): AnalyticsServer {
  const history: RequestHistory = ingress.history;
  const sessionTtl = options.sessionTtlMs ?? 12 * 60 * 60 * 1000;
  const jwtSecret = options.jwtSecret;
  // A stable issuer anchors a token to this surface family without breaking
  // across restarts: a rebuilt container is still the same gateway, so its
  // operator's token must survive. The shared secret is the real gate; the
  // issuer just keeps the claim set honest.
  const jwtIssuer = 'ad-gateway';
  // With stateless JWTs a logout cannot delete a token on the client's hard
  // drive, so the surface remembers the exact revoked tokens until the time
  // they would have expired anyway.
  const denied = new Map<string, number>();
  const sessions = jwtSecret === undefined ? new SessionStore(sessionTtl) : null;

  async function issueSession(role: Role, now = Date.now()): Promise<Session> {
    if (jwtSecret !== undefined) {
      const token = await new SignJWT({ role })
        .setProtectedHeader({ alg: 'HS256' })
        .setIssuedAt(Math.floor(now / 1000))
        .setExpirationTime(Math.floor((now + sessionTtl) / 1000))
        .setIssuer(jwtIssuer)
        // Same account, same second: without a jti the two logins would be the
        // very same string, so revoking one logout would kill the other.
        .setJti(randomBytes(8).toString('hex'))
        .sign(jwtSecret);
      return { token, role, createdAt: now };
    }
    return (sessions as SessionStore).issue(role, now);
  }

  async function readSession(token: string): Promise<Session> {
    if (jwtSecret === undefined) {
      return (sessions as SessionStore).get(token, Date.now());
    }
    const now = Date.now();
    for (const [dead, until] of denied) {
      if (until < now) denied.delete(dead);
    }
    if (denied.has(token)) throw new AuthError('no such session');
    let payload: unknown;
    try {
      payload = (await jwtVerify(token, jwtSecret, { issuer: jwtIssuer })).payload;
    } catch {
      throw new AuthError('no such session');
    }
    const role = (payload as { role?: unknown }).role as Role | undefined;
    if (typeof role?.kind !== 'string') throw new AuthError('no such session');
    return { token, role, createdAt: now };
  }

  function revokeSession(token: string): void {
    if (jwtSecret !== undefined) {
      denied.set(token, Date.now() + sessionTtl);
      return;
    }
    (sessions as SessionStore).drop(token);
  }
  /** Addresses added at runtime, on top of the config file. */
  const added = new Map<string, { kind: Principal; team: string | null }>();

  // The operator's state: loaded once at construction and rewritten by the
  // write endpoints. Nothing here can take the surface down; a corrupt state
  // file is treated as empty.
  const stateDir = options.stateDir;
  const reportsDir = options.reportsDir;
  let labels: LabelOverride[] = stateDir === undefined ? [] : loadLabels(stateDir);
  let services: ServiceEntry[] = stateDir === undefined ? [] : loadServices(stateDir);
  let graphLayout: GraphLayout = stateDir === undefined ? emptyGraphLayout() : loadGraphLayout(stateDir);
  ingress.applySourceOverrides(labels.map((entry) => ({
    kind: entry.kind,
    cidr: entry.cidr,
    ...(entry.team === undefined ? {} : { team: entry.team }),
    ...(entry.kind === 'team' && entry.own === true ? { own: true } : {}),
    ...(entry.note === undefined ? {} : { note: entry.note }),
  })));

  function persistLabels(next: LabelOverride[]): void {
    labels = next;
    if (stateDir !== undefined) saveLabels(stateDir, next);
    ingress.applySourceOverrides(next.map((entry) => ({
      kind: entry.kind,
      cidr: entry.cidr,
      ...(entry.team === undefined ? {} : { team: entry.team }),
      ...(entry.kind === 'team' && entry.own === true ? { own: true } : {}),
      ...(entry.note === undefined ? {} : { note: entry.note }),
    })));
  }

  async function syncServices(next: ServiceEntry[]): Promise<{ ok: boolean; error?: string }> {
    // Bring the gateway's listeners in line with the desired list. A binding
    // failure (port in use) is reported and keeps the rest applied, so one bad
    // candidate cannot stop the operator from finishing the list.
    const desired = new Map<number, ServiceEntry>();
    for (const entry of next) desired.set(entry.port, entry);
    const current = new Map<number, ServiceEntry>();
    for (const entry of services) current.set(entry.port, entry);
    for (const port of current.keys()) {
      if (desired.has(port)) continue;
      const result = await ingress.removeIngressPort(port);
      if (!result.ok && services.some((s) => s.port === port)) {
        return { ok: false, error: `could not unroute port ${port}: ${result.error}` };
      }
    }
    for (const entry of next) {
      if (current.has(entry.port)) continue;
      const result = await ingress.addIngressPort(entry.port, entry.service, entry.upstream);
      if (!result.ok) return { ok: false, error: `could not route port ${entry.port}: ${result.error}` };
    }
    services = next;
    if (stateDir !== undefined) saveServices(stateDir, next);
    return { ok: true };
  }

  const server = http.createServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      if (err instanceof AuthError) {
        send(res, err.status, { error: err.message });
        return;
      }
      send(res, 500, { error: (err as Error).message });
    });
  });
  server.headersTimeout = 20_000;
  server.requestTimeout = 60_000;

  function send(res: http.ServerResponse, status: number, body: unknown): void {
    const text = JSON.stringify(body);
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(text);
  }

  /** Send a raw body with an explicit content type (Markdown reports, digest). */
  function sendText(res: http.ServerResponse, status: number, text: string, contentType: string): void {
    res.writeHead(status, { 'content-type': contentType });
    res.end(text);
  }

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const ip = normaliseRemoteAddress(req.socket.remoteAddress ?? '');
    // The live network map, so an address labelled in the UI is classified the
    // same way here as it is on the proxy ingress.
    const decision = ingress.network.decide(ip, { requireAllowlist: true });

    // Step 1: a stranger is cut off before the request is read.
    if (decision.refuse && !added.has(ip)) {
      // The address is still recorded, so the operator can see who is knocking.
      history.add({
        id: `${Date.now().toString(36)}${Math.floor(Math.random() * 46656).toString(36)}${Math.floor(Math.random() * 46656).toString(36)}`,
        at: new Date().toISOString(),
        ip,
        principal: 'unknown',
        team: null,
        host: null,
        method: req.method ?? 'GET',
        target: req.url ?? '/',
        outcome: 'refused',
        reason: 'analytics surface: not on the allowlist',
        status: null,
        bytes: 0,
        durationMs: 0,
        rules: [],
      });
      dropConnection(req.socket);
      return;
    }

    const path = (req.url ?? '/').split('?')[0] ?? '/';
    const method = req.method ?? 'GET';

    // Health answers before the session gate: the operator has to be able to
    // see whether the surface is up without already holding a token.
    if (path === '/api/health' && method === 'GET') {
      send(res, 200, {
        ok: true,
        attempts: history.size,
        dropped: history.dropped,
        storage: ingress.storage?.stats() ?? null,
      });
      return;
    }

    // The operator's dashboard is a static page with no data in it; the data
    // only arrives through the session-gated API below. Serving the page before
    // the session gate is what lets the login form render at all.
    if ((path === '/' || path === '/index.html') && method === 'GET') {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
      res.end(UI_HTML);
      return;
    }
    if (path === '/favicon.ico' && method === 'GET') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (path === '/api/login' && method === 'POST') {
      const body = (await readJsonBody(req)) as { login?: unknown; password?: unknown };
      const role = await verifyCredentials(
        typeof body.login === 'string' ? body.login : '',
        typeof body.password === 'string' ? body.password : '',
        options,
      );
      const session = await issueSession(role);
      send(res, 200, { token: session.token, role: session.role });
      return;
    }

    // Step 2: every other endpoint needs a session, even from an allowed
    // address. Being on the allowlist is not an identity.
    const session = await readSession(bearer(req) ?? '');

    if (path === '/api/logout' && method === 'POST') {
      revokeSession(session.token);
      send(res, 200, { ok: true });
      return;
    }

    if (path === '/api/me' && method === 'GET') {
      send(res, 200, session.role);
      return;
    }

    if (path === '/api/accounts' && method === 'GET') {
      // The list the dashboard shows. Hashes never leave the process; the store
      // returns logins, roles and teams only.
      requireAdmin(session);
      send(res, 200, { accounts: options.accounts?.list() ?? [] });
      return;
    }

    if (path === '/api/accounts' && method === 'POST') {
      // Create or update a login. Admin only: only an operator decides who may
      // sign in. A missing password keeps the existing one on an update, so the
      // dashboard can change a role without resetting the password.
      requireAdmin(session);
      const store = options.accounts;
      if (store === undefined) throw new AuthError('account store is not configured', 503);
      const body = (await readJsonBody(req)) as {
        login?: unknown;
        password?: unknown;
        role?: unknown;
        team?: unknown;
      };
      try {
        const account = await store.upsert(body);
        send(res, 200, { ok: true, account });
      } catch (err) {
        throw new AuthError((err as Error).message, 400);
      }
      return;
    }

    if (path === '/api/accounts' && method === 'DELETE') {
      requireAdmin(session);
      const store = options.accounts;
      if (store === undefined) throw new AuthError('account store is not configured', 503);
      const login = new URL(req.url ?? '/', 'http://placeholder').searchParams.get('login') ?? '';
      if (login.length === 0) throw new AuthError('login is required', 400);
      try {
        const existed = store.remove(login);
        send(res, existed ? 200 : 404, { ok: existed, login });
      } catch (err) {
        throw new AuthError((err as Error).message, 400);
      }
      return;
    }

    if (path === '/api/account/password' && method === 'POST') {
      // Any signed-in user may rotate their own password; the current one is
      // required so a stolen token alone cannot lock the owner out.
      const store = options.accounts;
      if (store === undefined) throw new AuthError('account store is not configured', 503);
      const body = (await readJsonBody(req)) as { current?: unknown; password?: unknown };
      try {
        await store.setPassword(session.role.login, body.current, body.password);
        send(res, 200, { ok: true });
      } catch (err) {
        throw new AuthError((err as Error).message, 400);
      }
      return;
    }

    if (path === '/api/network' && method === 'GET') {
      const effectiveRoutes = [...config.routes.values()].map((route) => ({
        host: route.host,
        service: route.service,
        upstream: route.upstream,
      }));
      const portRoutes = ingress.activeIngressPorts.map((route) => ({
        port: route.publicPort,
        service: route.service,
        upstream: route.upstream,
      }));
      const protectedPorts = [...config.protectedPorts].map(([port, note]) => ({ port, note }));
      send(res, 200, {
        ...labelsView(ingress, labels, config.ownTeam),
        routes: effectiveRoutes,
        ingressPorts: portRoutes,
        protectedPorts,
        allowProtectedPorts: config.allowProtectedPorts,
        redirectOffset: config.redirectOffset,
        runtime: [...added.entries()].map(([addr, info]) => ({ ip: addr, ...info })),
        requireAllowlist: true,
      });
      return;
    }

    if (path === '/api/history' && method === 'GET') {
      const url = new URL(req.url ?? '/', 'http://placeholder');
      const limit = Number.parseInt(url.searchParams.get('limit') ?? '200', 10);
      const ownParam = url.searchParams.get('own');
      send(res, 200, {
        attempts: history.filter(
          {
            service: url.searchParams.get('service') ?? undefined,
            principal: url.searchParams.get('principal') ?? undefined,
            outcome: url.searchParams.get('outcome') ?? undefined,
            team: url.searchParams.get('team') ?? undefined,
            ...(ownParam === 'true' ? { own: true } : ownParam === 'false' ? { own: false } : {}),
          },
          Number.isInteger(limit) ? Math.min(limit, 1000) : 200,
        ),
        size: history.size,
        dropped: history.dropped,
      });
      return;
    }

    if (path === '/api/attempt' && method === 'GET') {
      requireAdmin(session);
      const id = new URL(req.url ?? '/', 'http://placeholder').searchParams.get('id') ?? '';
      if (id.length === 0) throw new AuthError('id is required', 400);
      const attempt = history.attemptById(id);
      if (attempt === null) throw new AuthError('attempt not found', 404);
      send(res, 200, { attempt });
      return;
    }

    if (path === '/api/routes' && method === 'DELETE') {
      // Delete a config route (host -> service) at runtime. The config file is
      // mounted read-only, so this is an in-memory change: it takes effect now
      // and is reset by a restart. Nothing here modifies the file behind the
      // mount.
      requireAdmin(session);
      const host = new URL(req.url ?? '/', 'http://placeholder').searchParams.get('host') ?? '';
      if (host.length === 0) throw new AuthError('host is required', 400);
      const existed = config.routes.delete(host);
      if (!existed) throw new AuthError('route not found', 404);
      send(res, 200, { ok: true, host });
      return;
    }

    if (path === '/api/checker' && method === 'GET') {
      // The grader's own traffic, in its own view. The network map decides who
      // is the checker, so no every-request filter hides an address here.
      requireAdmin(session);
      const limit = Number.parseInt(new URL(req.url ?? '/', 'http://placeholder').searchParams.get('limit') ?? '200', 10);
      send(res, 200, {
        attempts: history.principalRecent('checker', Number.isInteger(limit) ? Math.min(limit, 1000) : 200),
      });
      return;
    }

    if (path === '/api/flags' && method === 'GET') {
      requireAdmin(session);
      const url = new URL(req.url ?? '/', 'http://placeholder');
      const limit = Number.parseInt(url.searchParams.get('limit') ?? '200', 10);
      send(res, 200, {
        flags: history.recentFlags(Number.isInteger(limit) ? Math.min(limit, 1000) : 200),
      });
      return;
    }

    if (path === '/api/artifacts' && method === 'GET') {
      requireAdmin(session);
      const url = new URL(req.url ?? '/', 'http://placeholder');
      const limit = Math.min(Number.parseInt(url.searchParams.get('limit') ?? '200', 10) || 200, 1000);
      const type = url.searchParams.get('type');
      let artifacts = history.recentArtifacts(limit);
      if (type) artifacts = artifacts.filter((a) => a.type === type);
      send(res, 200, { artifacts });
      return;
    }

    if (path === '/api/stats' && method === 'GET') {
      requireAdmin(session);
      send(res, 200, {
        history: history.stats(),
        storage: ingress.storage?.stats() ?? null,
      });
      return;
    }

    // The reports the operator generated from the stand (`reports/<service>/`).
    // Read-only: the gateway serves what the scanner wrote, it never builds a
    // report itself, so the analysis stays a deliberate host step.
    if (path === '/api/reports' && method === 'GET') {
      requireAdmin(session);
      send(res, 200, { reports: reportsDir === undefined ? [] : listReports(reportsDir) });
      return;
    }

    if (path.startsWith('/api/reports/') && method === 'GET') {
      requireAdmin(session);
      const rest = path.slice('/api/reports/'.length);
      const wantMarkdown = rest.endsWith('.md');
      const name = wantMarkdown ? rest.slice(0, -3) : rest;
      // A traversing name would escape the reports root; the name is validated
      // rather than merely joined.
      if (!REPORT_NAME.test(name) || name === '.' || name === '..') {
        throw new AuthError('report name is invalid', 400);
      }
      if (reportsDir === undefined) throw new AuthError('reports are not configured', 404);
      const file = nodePath.join(reportsDir, name, wantMarkdown ? 'report.md' : 'report.json');
      if (!existsSync(file)) throw new AuthError('report not found', 404);
      sendText(
        res,
        200,
        readFileSync(file, 'utf8'),
        wantMarkdown ? 'text/markdown; charset=utf-8' : 'application/json; charset=utf-8',
      );
      return;
    }

    // The stand-wide digest, for a neural-net agent that cannot read the JSONL.
    if (path === '/api/digest' && method === 'GET') {
      requireAdmin(session);
      send(res, 200, buildDigest(history, reportsDir));
      return;
    }

    if (path === '/api/digest.md' && method === 'GET') {
      requireAdmin(session);
      sendText(res, 200, digestMarkdown(buildDigest(history, reportsDir)), 'text/markdown; charset=utf-8');
      return;
    }

    if (path === '/api/ips' && method === 'GET') {
      send(res, 200, { byIp: history.byIp(200) });
      return;
    }

    if (path === '/api/candidates' && method === 'GET') {
      // The addresses an operator still has to decide about.
      send(res, 200, { candidates: history.unknownCandidates(100) });
      return;
    }

    if (path === '/api/labels' && method === 'GET') {
      send(res, 200, labelsView(ingress, labels, config.ownTeam));
      return;
    }

    if (path === '/api/labels' && method === 'POST') {
      requireAdmin(session);
      const body = (await readJsonBody(req)) as { cidr?: unknown; kind?: unknown; team?: unknown; own?: unknown; note?: unknown };
      if (typeof body.cidr !== 'string' || body.cidr.trim().length === 0) {
        throw new AuthError('cidr is required', 400);
      }
      if (!isLabelKind(body.kind)) {
        throw new AuthError('kind must be checker, admin, team or unknown', 400);
      }
      const cidr = body.cidr.trim();
      const next = labels.filter((entry) => entry.cidr !== cidr);
      next.push({
        cidr,
        kind: body.kind as Principal,
        ...(typeof body.team === 'string' && body.team.length > 0 ? { team: body.team } : {}),
        ...(body.kind === 'team' && body.own === true ? { own: true } : {}),
        ...(typeof body.note === 'string' && body.note.length > 0 ? { note: body.note } : {}),
      });
      persistLabels(next);
      send(res, 200, {
        ok: true,
        cidr,
        kind: body.kind,
        team: typeof body.team === 'string' ? body.team : null,
        own: body.kind === 'team' && body.own === true,
      });
      return;
    }

    if (path === '/api/labels' && method === 'DELETE') {
      requireAdmin(session);
      const url = new URL(req.url ?? '/', 'http://placeholder');
      const cidr = url.searchParams.get('cidr') ?? '';
      const existed = labels.some((entry) => entry.cidr === cidr);
      persistLabels(labels.filter((entry) => entry.cidr !== cidr));
      send(res, existed ? 200 : 404, { ok: existed, cidr });
      return;
    }

    if (path === '/api/services' && method === 'GET') {
      requireAdmin(session);
      send(res, 200, {
        services: services.map((entry) => ({ ...entry })),
        routes: [...config.routes.values()].map((route) => ({
          host: route.host,
          service: route.service,
          upstream: route.upstream,
        })),
      });
      return;
    }

    if (path === '/api/services' && method === 'POST') {
      requireAdmin(session);
      const body = (await readJsonBody(req)) as { port?: unknown; service?: unknown; upstream?: unknown };
      const port = Number(body.port);
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new AuthError('port is required and must be a valid port number', 400);
      }
      if (typeof body.service !== 'string' || body.service.trim().length === 0) {
        throw new AuthError('service is required', 400);
      }
      const next = services.filter((entry) => entry.port !== port);
      next.push({
        port,
        service: body.service.trim(),
        ...(typeof body.upstream === 'string' && body.upstream.length > 0 ? { upstream: body.upstream } : {}),
      });
      const result = await syncServices(next);
      if (!result.ok) throw new AuthError(result.error ?? 'could not apply services', 400);
      send(res, 200, { ok: true, port, service: body.service.trim() });
      return;
    }

    if (path === '/api/services' && method === 'DELETE') {
      requireAdmin(session);
      const url = new URL(req.url ?? '/', 'http://placeholder');
      const port = Number(url.searchParams.get('port'));
      if (!Number.isInteger(port) || port < 1 || port > 65535) {
        throw new AuthError('port is required and must be a valid port number', 400);
      }
      const existed = services.some((entry) => entry.port === port);
      const result = await syncServices(services.filter((entry) => entry.port !== port));
      if (!result.ok) throw new AuthError(result.error ?? 'could not unroute services', 400);
      send(res, existed ? 200 : 404, { ok: existed, port });
      return;
    }

    if (path === '/api/services/status' && method === 'GET') {
      // Per-folder "is it running", so the dashboard can show a badge instead of
      // leaving the operator guessing after a launch. Advisory: a docker error
      // reads as "not running" rather than failing the page.
      requireAdmin(session);
      const root = options.launchDir ?? options.discoveryDir;
      if (root === undefined) {
        send(res, 200, { groups: [] });
        return;
      }
      const groups = await Promise.all(
        listServiceProjects(root)
          .filter((project) => options.discoverSkip === undefined || !options.discoverSkip.has(project.group))
          .map((project) => serviceStatus(root, project.group, { run: options.launchRun })),
      );
      send(res, 200, { groups });
      return;
    }

    if (path === '/api/services/launch' && method === 'POST') {
      // One click: run the project's own compose file, join the networks it
      // created, and route the ports it publishes. The scan and the launch read
      // the same directory, so what the operator saw on the card is what starts.
      requireAdmin(session);
      const body = (await readJsonBody(req)) as { group?: unknown; build?: unknown };
      const group = typeof body.group === 'string' ? body.group.trim() : '';
      if (group.length === 0) throw new AuthError('group is required', 400);
      const root = options.launchDir ?? options.discoveryDir;
      if (root === undefined) {
        throw new AuthError('no services directory configured; set AD_SERVICES_DIR', 400);
      }
      const result = await launchService(root, group, {
        self: options.selfContainer ?? 'ad-monitoring',
        build: body.build !== false,
        run: options.launchRun,
        publishPorts: true,
      });
      if (!result.ok) throw new AuthError(result.error ?? 'launch failed', 400);
      const found = discoverServices(root, options.discoverSkip).candidates.filter(
        (candidate) => candidate.group === group,
      );
      const merged = [...services];
      const routed: number[] = [];
      for (const candidate of found) {
        const entry: ServiceEntry = {
          port: candidate.publicPort,
          service: candidate.service,
          upstream: candidate.upstream,
        };
        const existing = merged.findIndex((item) => item.port === candidate.publicPort);
        if (existing >= 0) merged[existing] = entry;
        else merged.push(entry);
        routed.push(candidate.publicPort);
      }
      if (routed.length > 0) {
        const applied = await syncServices(merged);
        if (!applied.ok) throw new AuthError(applied.error ?? 'could not route launched ports', 400);
      }
      send(res, 200, { ...result, routed });
      return;
    }

    if (path === '/api/services/stop' && method === 'POST') {
      requireAdmin(session);
      const body = (await readJsonBody(req)) as { group?: unknown };
      const group = typeof body.group === 'string' ? body.group.trim() : '';
      if (group.length === 0) throw new AuthError('group is required', 400);
      const root = options.launchDir ?? options.discoveryDir;
      if (root === undefined) {
        throw new AuthError('no services directory configured; set AD_SERVICES_DIR', 400);
      }
      const result = await stopService(root, group, {
        self: options.selfContainer ?? 'ad-monitoring',
        run: options.launchRun,
      });
      if (!result.ok) throw new AuthError(result.error ?? 'stop failed', 400);
      // Symmetry with launch: the ports the project published are unrouted too,
      // so a stopped service does not leave a route pointing at a dead upstream.
      const stoppedPorts = new Set(
        discoverServices(root, options.discoverSkip)
          .candidates.filter((candidate) => candidate.group === group)
          .map((candidate) => candidate.publicPort),
      );
      if (stoppedPorts.size > 0 && services.some((entry) => stoppedPorts.has(entry.port))) {
        const applied = await syncServices(services.filter((entry) => !stoppedPorts.has(entry.port)));
        if (!applied.ok) throw new AuthError(applied.error ?? 'could not unroute stopped ports', 400);
      }
      send(res, 200, result);
      return;
    }

    if (path === '/api/history' && method === 'DELETE') {
      // Wipe only the captured traffic: the live feed, the counters and the
      // per-service JSONL files. Routes, address labels and graph edits stay,
      // so a running service keeps answering while the operator starts a fresh
      // test run.
      requireAdmin(session);
      history.clear();
      ingress.storage?.reset();
      if (options.dataDir !== undefined) {
        try {
          for (const name of readdirSync(options.dataDir)) {
            if (name === 'state') continue;
            rmSync(nodePath.join(options.dataDir, name), { recursive: true, force: true });
          }
        } catch {
          /* a capture file that will not delete must not fail the reset */
        }
      }
      send(res, 200, { ok: true });
      return;
    }

    if (path === '/api/state' && method === 'DELETE') {
      // Switch the stand back to factory: drop every route, label, graph edit
      // and captured file, and clear the in-memory history and counters, as if
      // the container had just been started. The operator's session survives.
      requireAdmin(session);
      await syncServices([]);
      persistLabels([]);
      graphLayout = emptyGraphLayout();
      if (stateDir !== undefined) {
        try {
          saveGraphLayout(stateDir, graphLayout);
        } catch {
          /* best effort */
        }
      }
      added.clear();
      history.clear();
      ingress.storage?.reset();
      if (options.dataDir !== undefined) {
        try {
          for (const name of readdirSync(options.dataDir)) {
            rmSync(nodePath.join(options.dataDir, name), { recursive: true, force: true });
          }
        } catch {
          /* a capture file that will not delete must not fail the reset */
        }
      }
      // The state files went with the rest; write the empty ones back so a
      // restart reads an empty stand instead of finding nothing.
      persistLabels([]);
      if (stateDir !== undefined) {
        try {
          saveGraphLayout(stateDir, emptyGraphLayout());
        } catch {
          /* best effort */
        }
      }
      await syncServices([]);
      send(res, 200, { ok: true });
      return;
    }

    if (path === '/api/discover' && method === 'POST') {
      requireAdmin(session);
      const body = (await readJsonBody(req)) as { dir?: unknown };
      const dir = typeof body.dir === 'string' && body.dir.length > 0 ? body.dir : (options.discoveryDir ?? '');
      if (dir === '') {
        throw new AuthError('no directory to scan; pass dir or set AD_DISCOVER_DIR', 400);
      }
      send(res, 200, discoverServices(dir, options.discoverSkip));
      return;
    }

    if ((path === '/api/graph' || path === '/api/graph.yaml') && method === 'GET') {
      // The paths as the gateway will actually take them: actors from the
      // network map, host routes from the config, occupied ports from the live
      // listeners. Discovery is opt-in (?discover=1) because it touches the
      // filesystem; without it the graph is the same on every call.
      requireAdmin(session);
      const url = new URL(req.url ?? '/', 'http://placeholder');
      let candidates: DiscoveryCandidate[] = [];
      if (url.searchParams.get('discover') === '1' && options.discoveryDir !== undefined) {
        candidates = discoverServices(options.discoveryDir, options.discoverSkip).candidates;
      }
      const topology = buildTopology({
        config,
        ingress,
        services: ingress.activeIngressPorts,
        candidates,
      });
      if (path === '/api/graph') {
        send(res, 200, topology);
        return;
      }
      const yaml = topologyToYaml(topology);
      // The file is the artifact: written next to the labels so the operator can
      // read and diff it without the dashboard. A write failure does not fail
      // the request -- the served YAML is the same bytes either way.
      if (options.stateDir !== undefined) {
        try {
          writeFileSync(nodePath.join(options.stateDir, 'graph.yaml'), yaml, 'utf8');
        } catch {
          /* best effort: the response is still the generated document */
        }
      }
      res.writeHead(200, { 'content-type': 'text/yaml; charset=utf-8' });
      res.end(yaml);
      return;
    }

    if (path === '/api/graph/layout' && method === 'GET') {
      // The manual overlay is separate from the generated graph, so a client can
      // always fetch the pristine paths and re-apply the operator's edits.
      requireAdmin(session);
      send(res, 200, graphLayout);
      return;
    }

    if (path === '/api/graph/layout' && method === 'POST') {
      requireAdmin(session);
      const body = await readJsonBody(req, 256 * 1024);
      let next: GraphLayout;
      try {
        next = normalizeGraphLayout(body);
      } catch (err) {
        throw new AuthError((err as Error).message, 400);
      }
      graphLayout = next;
      if (stateDir !== undefined) {
        try {
          saveGraphLayout(stateDir, next);
        } catch {
          /* best effort: the in-memory overlay still applies this session */
        }
      }
      send(res, 200, {
        ok: true,
        positions: Object.keys(next.positions).length,
        removed: next.removed.length,
        added: next.added.length,
      });
      return;
    }

    if (path === '/api/graph/layout' && method === 'DELETE') {
      requireAdmin(session);
      graphLayout = emptyGraphLayout();
      if (stateDir !== undefined) {
        try {
          saveGraphLayout(stateDir, graphLayout);
        } catch {
          /* best effort */
        }
      }
      send(res, 200, { ok: true });
      return;
    }

    if (path === '/api/allowlist' && method === 'POST') {
      requireAdmin(session);
      const body = (await readJsonBody(req)) as { ip?: unknown; kind?: unknown; team?: unknown };
      if (typeof body.ip !== 'string' || body.ip.trim().length === 0) {
        throw new AuthError('ip is required', 400);
      }
      const candidate = body.ip.trim();
      const kind = body.kind === 'team' || body.kind === 'admin' ? body.kind : 'team';
      const team = typeof body.team === 'string' ? body.team : null;
      added.set(candidate, { kind, team });
      send(res, 200, { ok: true, ip: candidate, kind, team });
      return;
    }

    if (path === '/api/allowlist' && method === 'DELETE') {
      requireAdmin(session);
      const url = new URL(req.url ?? '/', 'http://placeholder');
      const candidate = url.searchParams.get('ip') ?? '';
      const existed = added.delete(candidate);
      send(res, existed ? 200 : 404, { ok: existed, ip: candidate });
      return;
    }

    if (path === '/api/health' && method === 'HEAD') {
      res.writeHead(200);
      res.end();
      return;
    }

    send(res, 404, { error: 'no such endpoint', path });
  }

  return {
    server,
    sessions,
    listen(): Promise<number> {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(config.analyticsListen.port, config.analyticsListen.host, () => {
          const address = server.address();
          resolve(typeof address === 'object' && address !== null ? address.port : 0);
        });
      });
    },
    /**
     * Apply the services persisted on disk to the ingress listeners. Called by
     * the entry point once both servers are up; the write endpoints keep live
     * edits in line themselves.
     */
    async bootstrap(): Promise<{ ok: boolean; error?: string }> {
      // The saved list is the desired state, and boot is the only moment the
      // in-memory list has not been applied yet, so comparing it with itself
      // (as the write endpoints do) would never bind anything. Compare against
      // the gateway's actual listeners instead and add only what is missing.
      const routed = new Set(ingress.activeIngressPorts.map((r) => r.publicPort));
      const pending = services.filter((entry) => !routed.has(entry.port));
      for (const entry of pending) {
        const result = await ingress.addIngressPort(entry.port, entry.service, entry.upstream);
        if (!result.ok) {
          return { ok: false, error: `could not route port ${entry.port}: ${result.error}` };
        }
      }
      return { ok: true };
    },
    close(): Promise<void> {
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

