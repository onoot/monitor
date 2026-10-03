import assert from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';

import { createAnalyticsServer, requireAdmin, SessionStore, verifyCredentials, AuthError } from '../src/analytics.js';
import { parseGatewayConfig } from '../src/config.js';
import { Gateway } from '../src/gateway.js';
import { loadLabels, loadServices, saveLabels, saveServices } from '../src/state.js';
import { parseTopologyYaml } from '../src/topology.js';
import { emptyGraphLayout, saveGraphLayout } from '../src/graphLayout.js';
import { hashPassword, verifyPassword } from '../src/password.js';

const ACCOUNTS = [
  { login: 'ops', password: 'hunter2', role: { kind: 'admin', team: null, login: 'ops' } },
  { login: 'alpha', password: 'alpha-pass', role: { kind: 'team', team: 'alpha', login: 'alpha' } },
];

function verify(login: string, password: string) {
  return ACCOUNTS.find((a) => a.login === login && a.password === password)?.role ?? null;
}

/** A verifier backed by real hashes, as the entry point uses. */
async function hashVerify(login: string, password: string) {
  const entry = ACCOUNTS.find((a) => a.login === login);
  if (entry === undefined) return null;
  const stored = HASHES[entry.login] as string;
  return (await verifyPassword(password, stored)).ok ? entry.role : null;
}

const HASHES: Record<string, string> = {
  ops: await hashPassword('hunter2'),
  alpha: await hashPassword('alpha-pass'),
};

let analytics: ReturnType<typeof createAnalyticsServer>;
let ingress: Gateway;
let port: number;
let token = '';

function call(
  pathname: string,
  init: { method?: string; body?: unknown; as?: string | null } = {},
): Promise<{ status: number; body: Record<string, unknown>; error: string | null }> {
  return new Promise((resolve) => {
    const headers: Record<string, string> = {};
    if (init.body !== undefined) headers['content-type'] = 'application/json';
    if (init.as) headers.authorization = `Bearer ${init.as}`;
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: pathname,
        method: init.method ?? (init.body === undefined ? 'GET' : 'POST'),
        headers,
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString('utf8');
          let body: Record<string, unknown> = {};
          try {
            body = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {};
          } catch {
            body = { raw: text };
          }
          resolve({ status: res.statusCode ?? 0, body, error: null });
        });
      },
    );
    req.on('error', (e: Error) => resolve({ status: 0, body: {}, error: e.code ?? e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: {}, error: 'TIMEOUT' }); });
    if (init.body !== undefined) req.write(JSON.stringify(init.body));
    req.end();
  });
}

before(async () => {
  const config = parseGatewayConfig(
    JSON.stringify({
      listen: { host: '127.0.0.1', port: 0 },
      analytics_listen: { host: '127.0.0.1', port: 0 },
      checker: [{ cidr: '127.0.0.9' }],
      admin: [{ cidr: '127.0.0.1' }],
      teams: [{ cidr: '127.0.0.9' }],
      routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:1' } },
    }),
  );
  ingress = new Gateway(config, { rateLimitPerSecond: 100, rateBurst: 100 });
  await ingress.listen();
  analytics = createAnalyticsServer(config, ingress, { verify });
  port = await analytics.listen();
});

after(async () => {
  // The ingress server holds the event loop open, so both have to be closed or
  // the test process never exits.
  await analytics.close();
  await ingress.close();
});

describe('analytics auth', () => {
  it('rejects a wrong password', async () => {
    await assert.rejects(() => verifyCredentials('ops', 'wrong', { verify }), AuthError);
  });

  it('rejects an unknown login', async () => {
    await assert.rejects(() => verifyCredentials('nobody', 'hunter2', { verify }), AuthError);
  });

  it('is closed when no account store is configured', async () => {
    // Fail-closed: with no way to verify anyone, everyone is refused rather than
    // everyone being let in.
    await assert.rejects(() => verifyCredentials('ops', 'hunter2', {}), /closed/);
  });

  it('accepts a correct password through a hash-backed verifier', async () => {
    // The real path: the config holds a hash, and the async check is awaited.
    const role = await verifyCredentials('ops', 'hunter2', { verify: hashVerify });
    assert.equal(role.kind, 'admin');
  });

  it('rejects a wrong password through a hash-backed verifier', async () => {
    await assert.rejects(() => verifyCredentials('ops', 'not-it', { verify: hashVerify }), AuthError);
  });

  it('issues a token for a correct password', async () => {
    const res = await call('/api/login', { body: { login: 'ops', password: 'hunter2' } });
    assert.equal(res.status, 200);
    assert.equal(typeof res.body.token, 'string');
    token = res.body.token as string;
  });

  it('does not confirm whether a login exists', async () => {
    const wrongPassword = await call('/api/login', { body: { login: 'ops', password: 'nope' } });
    const wrongLogin = await call('/api/login', { body: { login: 'ghost', password: 'nope' } });
    assert.equal(wrongPassword.status, 401);
    assert.equal(wrongLogin.status, 401);
    assert.equal(wrongPassword.body.error, wrongLogin.body.error);
  });

  it('requires a session for the api', async () => {
    assert.equal((await call('/api/me')).status, 401);
  });

  it('rejects a made-up token', async () => {
    const res = await call('/api/me', { as: 'f'.repeat(64) });
    assert.equal(res.status, 401);
  });

  it('reports the caller role', async () => {
    const res = await call('/api/me', { as: token });
    assert.equal(res.status, 200);
    assert.equal(res.body.kind, 'admin');
  });

  it('invalidates a token on logout', async () => {
    const loginRes = await call('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    const alphaToken = loginRes.body.token as string;
    assert.equal((await call('/api/me', { as: alphaToken })).status, 200);
    assert.equal((await call('/api/logout', { as: alphaToken, method: 'POST' })).status, 200);
    assert.equal((await call('/api/me', { as: alphaToken })).status, 401);
  });

  it('expires a session past its ttl', () => {
    const store = new SessionStore(1000);
    const session = store.issue({ kind: 'team', team: 'alpha', login: 'alpha' }, 0);
    assert.equal(store.get(session.token, 500).token, session.token);
    assert.throws(() => store.get(session.token, 5000), /expired/);
  });

  it('keeps session stores separate between surfaces', () => {
    // Two surfaces in one process must not accept each other's tokens.
    const a = new SessionStore(1000);
    const b = new SessionStore(1000);
    const session = a.issue({ kind: 'admin', team: null, login: 'ops' }, 0);
    assert.throws(() => b.get(session.token, 0));
  });
});

describe('analytics roles', () => {
  let teamToken = '';
  it('logs a team in', async () => {
    const res = await call('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    assert.equal(res.status, 200);
    teamToken = res.body.token as string;
  });

  it('stops a team from changing the allowlist', async () => {
    const res = await call('/api/allowlist', { as: teamToken, body: { ip: '10.0.0.5', kind: 'team', team: 'alpha' } });
    assert.equal(res.status, 403);
  });

  it('stops an admin check from letting a team through', () => {
    const session = { token: 't', role: { kind: 'team', team: 'alpha', login: 'alpha' }, createdAt: 0 };
    assert.throws(() => requireAdmin(session), /admin role required/);
  });

  it('lets an admin add an address', async () => {
    const res = await call('/api/allowlist', { as: token, body: { ip: '10.0.0.5', kind: 'team', team: 'alpha' } });
    assert.equal(res.status, 200);
    const network = await call('/api/network', { as: token });
    const runtime = network.body.runtime as Array<{ ip: string }>;
    assert.ok(runtime.some((r) => r.ip === '10.0.0.5'));
  });

  it('removes an address again', async () => {
    assert.equal((await call('/api/allowlist?ip=10.0.0.5', { as: token, method: 'DELETE' })).status, 200);
    assert.equal((await call('/api/allowlist?ip=10.0.0.5', { as: token, method: 'DELETE' })).status, 404);  });

  it('rejects an allowlist entry with no address', async () => {
    assert.equal((await call('/api/allowlist', { as: token, body: { kind: 'team' } })).status, 400);
  });
});

describe('analytics api', () => {
  it('serves the configured network', async () => {
    const res = await call('/api/network', { as: token });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.effective));
    assert.ok(Array.isArray(res.body.overrides));
  });

  it('serves history and ip aggregates', async () => {
    assert.equal((await call('/api/history?limit=5', { as: token })).status, 200);
    assert.equal((await call('/api/ips', { as: token })).status, 200);
  });

  it('serves health without a session', async () => {
    // Health has to answer before anyone is logged in, or the operator cannot
    // see whether the surface is even up.
    const res = await call('/api/health');
    assert.equal(res.status, 200);
    assert.equal(res.body.ok, true);
  });

  it('404s an unknown endpoint', async () => {
    assert.equal((await call('/api/nope', { as: token })).status, 404);
  });

  it('rejects a malformed json body', async () => {
    await new Promise<void>((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port, path: '/api/login', method: 'POST', headers: { 'content-type': 'application/json' } },
        (res) => { res.resume(); res.on('end', () => { assert.equal(res.statusCode, 400); resolve(); }); },
      );
      req.end('{not json');
    });
  });

  it('serves the dashboard page to an allowed peer without a session', async () => {
    const res = await call('/');
    assert.equal(res.status, 200);
    assert.equal((res.body.raw as string).includes('monitor'), true);
  });

  it('requires admin for the capture views', async () => {
    const login = await call('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    const alpha = login.body.token as string;
    assert.equal((await call('/api/stats', { as: alpha })).status, 403);
    assert.equal((await call('/api/checker', { as: alpha })).status, 403);
    assert.equal((await call('/api/flags', { as: alpha })).status, 403);
    assert.equal((await call('/api/artifacts', { as: alpha })).status, 403);
  });

  it('serves the capture views to an admin', async () => {
    assert.equal((await call('/api/stats', { as: token })).status, 200);
    const stats = await call('/api/stats', { as: token });
    assert.ok((stats.body.history as { attempts: number }).attempts >= 0);
    // The test fixture runs without a capture store, so storage reports null.
    assert.equal(stats.body.storage, null);
    assert.equal((await call('/api/checker', { as: token })).status, 200);
    assert.equal((await call('/api/flags', { as: token })).status, 200);
    assert.equal((await call('/api/artifacts?type=md5', { as: token })).status, 200);
    assert.equal((await call('/api/history?service=curs&principal=team', { as: token })).status, 200);
  });
});

describe('labels and services (state dir)', () => {
  let stateDir = '';
  let discoveryDir = '';
  let a4: ReturnType<typeof createAnalyticsServer>;
  let gw4: Gateway;
  let p4 = 0;
  let t4 = '';

  function c4(
    pathname: string,
    init: { method?: string; body?: unknown; as?: string | null } = {},
  ): Promise<{ status: number; body: Record<string, unknown>; error: string | null }> {
    return new Promise((resolve) => {
      const headers: Record<string, string> = {};
      if (init.body !== undefined) headers['content-type'] = 'application/json';
      if (init.as) headers.authorization = `Bearer ${init.as}`;
      const req = http.request(
        { host: '127.0.0.1', port: p4, path: pathname, method: init.method ?? (init.body === undefined ? 'GET' : 'POST'), headers, timeout: 5000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let body: Record<string, unknown> = {};
            try {
              body = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {};
            } catch {
              body = { raw: text };
            }
            resolve({ status: res.statusCode ?? 0, body, error: null });
          });
        },
      );
      req.on('error', (e: Error) => resolve({ status: 0, body: {}, error: e.code ?? e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: {}, error: 'TIMEOUT' }); });
      if (init.body !== undefined) req.write(JSON.stringify(init.body));
      req.end();
    });
  }

  before(async () => {
    stateDir = mkdtempSync(path.join(tmpdir(), 'ad-state-'));
    discoveryDir = mkdtempSync(path.join(tmpdir(), 'ad-disc-'));
    // Layout for the folder-per-service model: the scanned directory holds one
    // folder per service, and each folder holds the service's own compose and
    // env files (its sub-services).
    mkdirSync(path.join(discoveryDir, 'curs'), { recursive: true });
    writeFileSync(
      path.join(discoveryDir, 'curs', 'docker-compose.yml'),
      'services:\n  curs:\n    image: x\n    ports:\n      - "8083:80"\n  db:\n    image: mysql\n    ports:\n      - "3306:3306"\n',
      'utf8',
    );
    writeFileSync(path.join(discoveryDir, 'curs', '.env'), 'CURS_PORT=8083\nDB_PORT=3307\nMISC_PORT=8888\nNOPE=8084\n', 'utf8');

    const config = parseGatewayConfig(
      JSON.stringify({
        listen: { host: '127.0.0.1', port: 0 },
        analytics_listen: { host: '127.0.0.1', port: 0 },
        checker: [{ cidr: '127.0.0.9' }],
        admin: [{ cidr: '127.0.0.1' }],
        teams: [{ cidr: '127.0.0.9' }],
        routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:1' } },
      }),
    );
    gw4 = new Gateway(config, { rateLimitPerSecond: 100, rateBurst: 100 });
    await gw4.listen();
    a4 = createAnalyticsServer(config, gw4, { verify, stateDir, discoveryDir });
    p4 = await a4.listen();
    await a4.bootstrap();
    const login = await c4('/api/login', { body: { login: 'ops', password: 'hunter2' } });
    t4 = login.body.token as string;
  });

  after(async () => {
    await a4.close();
    await gw4.close();
    rmSync(stateDir, { recursive: true, force: true });
    rmSync(discoveryDir, { recursive: true, force: true });
  });

  it('requires admin to write a label', async () => {
    const login = await c4('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    const res = await c4('/api/labels', { as: login.body.token as string, body: { cidr: '127.0.0.5', kind: 'checker' } });
    assert.equal(res.status, 403);
  });

  it('labels a candidate as a checker, live and persisted', async () => {
    const res = await c4('/api/labels', { as: t4, body: { cidr: '127.0.0.5', kind: 'checker' } });
    assert.equal(res.status, 200);
    // The proxy map must reflect it immediately, without a restart.
    assert.equal(gw4.network.describe().filter((r) => r.kind === 'checker' && r.cidr === '127.0.0.5').length, 1);
    const disk = loadLabels(stateDir);
    assert.equal(disk.some((e) => e.cidr === '127.0.0.5' && e.kind === 'checker'), true);
  });

  it('classifies traffic by a labelled address on the probe side too', async () => {
    // labelled address is now a checker, so a probe from it must be forwarded.
    assert.equal(
      gw4.network.decide('127.0.0.5', { requireAllowlist: true }).isChecker,
      true,
    );
  });

  it('marks an own-team label and reports it in the network view', async () => {
    const res = await c4('/api/labels', {
      as: t4,
      body: { cidr: '127.0.0.6', kind: 'team', team: 'alpha', own: true },
    });
    assert.equal(res.status, 200);
    assert.equal(gw4.network.decide('127.0.0.6', { requireAllowlist: true }).own, true);
    const net = await c4('/api/network', { as: t4 });
    assert.ok((net.body.ownTeams as string[]).includes('alpha'));
  });

  it('re-reads labels across a restart', async () => {
    // A second analytics server on the same state dir sees the persisted labels.
    const config = parseGatewayConfig(
      JSON.stringify({
        listen: { host: '127.0.0.1', port: 0 },
        analytics_listen: { host: '127.0.0.1', port: 0 },
        checker: [{ cidr: '127.0.0.9' }],
        admin: [{ cidr: '127.0.0.1' }],
        teams: [{ cidr: '127.0.0.9' }],
        routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:1' } },
      }),
    );
    const gw2 = new Gateway(config);
    const a2 = createAnalyticsServer(config, gw2, { verify, stateDir });
    await a2.listen();
    try {
      assert.equal(gw2.network.describe().some((r) => r.kind === 'checker' && r.cidr === '127.0.0.5'), true);
    } finally {
      await a2.close();
      await gw2.close();
    }
  });

  it('rebinds saved services on a restart', async () => {
    // A service saved before a restart must be routed again by bootstrap, which
    // has to compare against the gateway's listeners (the in-memory desired
    // list and the loaded list are the same object otherwise).
    const seed = 39123;
    const config = parseGatewayConfig(
      JSON.stringify({
        listen: { host: '127.0.0.1', port: 0 },
        analytics_listen: { host: '127.0.0.1', port: 0 },
        checker: [{ cidr: '127.0.0.9' }],
        admin: [{ cidr: '127.0.0.1' }],
        teams: [{ cidr: '127.0.0.9' }],
        routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:1' } },
      }),
    );
    const gw2 = new Gateway(config);
    const a2 = createAnalyticsServer(config, gw2, { verify, stateDir });
    await a2.listen();
    saveServices(stateDir, [{ port: seed, service: 'curs', upstream: '127.0.0.1:2' }]);
    await a2.close();
    await gw2.close();

    const gw3 = new Gateway(config);
    const a3 = createAnalyticsServer(config, gw3, { verify, stateDir });
    await a3.listen();
    try {
      const res = await a3.bootstrap();
      assert.equal(res.ok, true);
      assert.ok(gw3.activeIngressPorts.some((r) => r.publicPort === seed));
    } finally {
      await a3.close();
      await gw3.close();
    }
  });

  it('adds a service from the UI with an upstream default and persists it', async () => {
    const port5 = 39083;
    const res = await c4('/api/services', { as: t4, body: { port: port5, service: 'curs' } });
    assert.equal(res.status, 200);
    assert.equal(gw4.activeIngressPorts.some((r) => r.publicPort === port5 && r.upstreamPort === port5), true);
    const disk = loadServices(stateDir);
    assert.equal(disk.some((s) => s.port === port5), true);
    const net = await c4('/api/network', { as: t4 });
    const ingressPorts = net.body.ingressPorts as Array<{ port: number }>;
    assert.ok(ingressPorts.some((r) => r.port === port5));
    // Remove it again so the listener does not leak into the rest of the suite.
    assert.equal((await c4(`/api/services?port=${port5}`, { as: t4, method: 'DELETE' })).status, 200);
  });

  it('auto-detects service ports from compose and env files, grouped by folder', async () => {
    const res = await c4('/api/discover', { as: t4, body: {} });
    assert.equal(res.status, 200);
    const candidates = res.body.candidates as Array<{
      group: string;
      service: string;
      publicPort: number;
      upstream: string;
      containerPort: number | null;
    }>;
    // The folder is the service; a compose sub-service there is addressed by its
    // own name on the shared network, on the container port (`8083:80`), so
    // stripping the published port does not break the gateway's route to it.
    assert.ok(
      candidates.some(
        (c) => c.group === 'curs' && c.service === 'curs' && c.publicPort === 8083 && c.containerPort === 80 && c.upstream === 'curs:80',
      ),
    );
    // A bare .env port has no container to name; it keeps the loopback default.
    assert.ok(
      candidates.some(
        (c) => c.group === 'curs' && c.service === 'misc' && c.publicPort === 8888 && c.upstream === '127.0.0.1:8888',
      ),
    );
    // Databases are not routed: a gateway in front of a connection that speaks
    // the DB protocol only breaks it, unlike an HTTP check the gate forwards.
    // Neither the compose 'db' nor the env DB_PORT may show up.
    assert.ok(!candidates.some((c) => c.service === 'db' || c.publicPort === 3306 || c.publicPort === 3307));
    // When compose and .env name the same port, compose wins (it knows the
    // container half of the mapping).
    const curs = candidates.filter((c) => c.service === 'curs' && c.publicPort === 8083);
    assert.equal(curs.length, 1);
    assert.equal(curs[0]?.upstream, 'curs:80');
    assert.equal(curs[0]?.containerPort, 80);
  });

  it('generates the path graph as YAML and writes the same bytes to disk', async () => {
    const res = await c4('/api/graph.yaml', { as: t4 });
    assert.equal(res.status, 200);
    const yaml = res.body.raw as string;
    assert.equal(typeof yaml, 'string');
    assert.ok(yaml.startsWith('version: 1\n'));
    const topology = parseTopologyYaml(yaml);
    assert.ok(topology.nodes.some((n) => n.kind === 'gateway'));
    // The config routes are host paths in the graph.
    assert.ok(topology.nodes.some((n) => n.kind === 'host' && n.label === 'app.local'));
    assert.ok(topology.edges.some((e) => e.from === 'gateway' && e.to === 'host:app.local'));
    // The file is the artifact the dashboard also reads; it must match.
    assert.equal(readFileSync(path.join(stateDir, 'graph.yaml'), 'utf8'), yaml);
  });

  it('serves the same graph as JSON and hides it from non-admins', async () => {
    const res = await c4('/api/graph', { as: t4 });
    assert.equal(res.status, 200);
    assert.ok(Array.isArray(res.body.nodes));
    assert.ok(Array.isArray(res.body.edges));
    const login = await c4('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    assert.equal((await c4('/api/graph.yaml', { as: login.body.token as string })).status, 403);
  });

  it('stores the manual graph overlay and serves it back', async () => {
    const empty = { version: 1, positions: {}, removed: [], added: [] };
    assert.deepEqual((await c4('/api/graph/layout', { as: t4 })).body, empty);
    const layout = {
      version: 1,
      positions: { 'host:app.local': { x: 40, y: 12 } },
      removed: ['["gateway","host:app.local","host"]'],
      added: [{ from: 'gateway', to: 'up:web:80', label: 'вручную' }],
    };
    const saved = await c4('/api/graph/layout', { as: t4, method: 'POST', body: layout });
    assert.equal(saved.status, 200);
    assert.deepEqual(saved.body, { ok: true, positions: 1, removed: 1, added: 1 });
    assert.deepEqual((await c4('/api/graph/layout', { as: t4 })).body, layout);
    assert.deepEqual(JSON.parse(readFileSync(path.join(stateDir, 'graph.layout.json'), 'utf8')), layout);
    // A malformed overlay is a client error and leaves the stored one intact.
    assert.equal((await c4('/api/graph/layout', { as: t4, method: 'POST', body: { positions: { a: { x: 'no' } } } })).status, 400);
    assert.deepEqual((await c4('/api/graph/layout', { as: t4 })).body, layout);
    // Only admins may read or write it.
    const login = await c4('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    assert.equal((await c4('/api/graph/layout', { as: login.body.token as string })).status, 403);
    // Reset clears the memory and the file.
    assert.equal((await c4('/api/graph/layout', { as: t4, method: 'DELETE' })).status, 200);
    assert.deepEqual((await c4('/api/graph/layout', { as: t4 })).body, empty);
    assert.deepEqual(JSON.parse(readFileSync(path.join(stateDir, 'graph.layout.json'), 'utf8')), empty);
  });
});

describe('clean stand', () => {
  let dataDir = '';
  let stateDir = '';
  let discoveryDir = '';
  let a5: ReturnType<typeof createAnalyticsServer>;
  let gw5: Gateway;
  let p5 = 0;
  let t5 = '';

  function c5(
    pathname: string,
    init: { method?: string; body?: unknown; as?: string | null } = {},
  ): Promise<{ status: number; body: Record<string, unknown>; error: string | null }> {
    return new Promise((resolve) => {
      const headers: Record<string, string> = {};
      if (init.body !== undefined) headers['content-type'] = 'application/json';
      if (init.as) headers.authorization = `Bearer ${init.as}`;
      const req = http.request(
        { host: '127.0.0.1', port: p5, path: pathname, method: init.method ?? (init.body === undefined ? 'GET' : 'POST'), headers, timeout: 5000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let body: Record<string, unknown> = {};
            try {
              body = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {};
            } catch {
              body = { raw: text };
            }
            resolve({ status: res.statusCode ?? 0, body, error: null });
          });
        },
      );
      req.on('error', (e: Error) => resolve({ status: 0, body: {}, error: e.code ?? e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: {}, error: 'TIMEOUT' }); });
      if (init.body !== undefined) req.write(JSON.stringify(init.body));
      req.end();
    });
  }

  before(async () => {
    dataDir = mkdtempSync(path.join(tmpdir(), 'ad-clean-'));
    stateDir = path.join(dataDir, 'state');
      discoveryDir = mkdtempSync(path.join(tmpdir(), 'ad-clean-disc-'));
      mkdirSync(path.join(discoveryDir, 'curs'), { recursive: true });
      writeFileSync(path.join(discoveryDir, 'curs', 'docker-compose.yml'), 'services: {}\n', 'utf8');
      mkdirSync(path.join(dataDir, 'curs'), { recursive: true });
    writeFileSync(path.join(dataDir, 'curs', '2026-10-01.jsonl'), '{"service":"curs"}\n', 'utf8');
    mkdirSync(stateDir, { recursive: true });
    saveLabels(stateDir, [{ cidr: '127.0.0.5', kind: 'checker' }]);
    saveGraphLayout(stateDir, { version: 1, positions: { x: { x: 1, y: 2 } }, removed: [], added: [] });

    const config = parseGatewayConfig(
      JSON.stringify({
        listen: { host: '127.0.0.1', port: 0 },
        analytics_listen: { host: '127.0.0.1', port: 0 },
        checker: [{ cidr: '127.0.0.9' }],
        admin: [{ cidr: '127.0.0.1' }],
        teams: [{ cidr: '127.0.0.9' }],
        routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:1' } },
      }),
    );
    gw5 = new Gateway(config, { rateLimitPerSecond: 100, rateBurst: 100 });
    await gw5.listen();
      a5 = createAnalyticsServer(config, gw5, {
        verify,
        stateDir,
        discoveryDir,
        dataDir,
        launchDir: discoveryDir,
        launchRun: async () => ({ code: 0, stdout: 'id1\n', stderr: '' }),
      });
    p5 = await a5.listen();
    const login = await c5('/api/login', { body: { login: 'ops', password: 'hunter2' } });
    t5 = login.body.token as string;
  });

  after(async () => {
    await a5.close();
    await gw5.close();
    rmSync(dataDir, { recursive: true, force: true });
    rmSync(discoveryDir, { recursive: true, force: true });
  });

  it('empties labels, graph edits and captures, and clears the history', async () => {
    assert.equal(existsSync(path.join(dataDir, 'curs', '2026-10-01.jsonl')), true);
    assert.equal(loadLabels(stateDir).length, 1);
    gw5.history.add({
      id: 'x',
      at: new Date().toISOString(),
      ip: '127.0.0.9',
      principal: 'checker',
      team: null,
      host: null,
      method: 'GET',
      target: '/',
      outcome: 'forwarded',
      reason: 'ok',
      status: 200,
      bytes: 1,
      durationMs: 1,
      rules: [],
    });
    assert.ok(gw5.history.size > 0);

    const res = await c5('/api/state', { as: t5, method: 'DELETE' });
    assert.equal(res.status, 200);
    assert.deepEqual(loadLabels(stateDir), []);
    assert.equal(existsSync(path.join(dataDir, 'curs')), false);
    assert.deepEqual(JSON.parse(readFileSync(path.join(stateDir, 'graph.layout.json'), 'utf8')), emptyGraphLayout());
    assert.equal(gw5.history.size, 0);
  });

    it('refuses a malformed launch request without touching docker', async () => {
      assert.equal((await c5('/api/services/launch', { as: t5, body: {} })).status, 400);
      const login = await c5('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
      assert.equal((await c5('/api/state', { as: login.body.token as string, method: 'DELETE' })).status, 403);
    });

    it('reports per-folder running state and hides it from a team', async () => {
      const res = await c5('/api/services/status', { as: t5 });
      assert.equal(res.status, 200);
      assert.deepEqual(res.body.groups, [{ group: 'curs', running: true, containers: 1 }]);
      const login = await c5('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
      assert.equal((await c5('/api/services/status', { as: login.body.token as string })).status, 403);
    });

  it('clears captured history but keeps routes, labels and graph edits', async () => {
    mkdirSync(path.join(dataDir, 'curs'), { recursive: true });
    writeFileSync(path.join(dataDir, 'curs', '2026-10-02.jsonl'), '{"service":"curs"}\n', 'utf8');
    saveLabels(stateDir, [{ cidr: '127.0.0.5', kind: 'checker' }]);
    saveGraphLayout(stateDir, { version: 1, positions: { x: { x: 1, y: 2 } }, removed: [], added: [] });
    gw5.history.add({
      id: 'y',
      at: new Date().toISOString(),
      ip: '127.0.0.9',
      principal: 'checker',
      team: null,
      host: null,
      method: 'GET',
      target: '/',
      outcome: 'forwarded',
      reason: 'ok',
      status: 200,
      bytes: 1,
      durationMs: 1,
      rules: [],
    });
    assert.ok(gw5.history.size > 0);

    const res = await c5('/api/history', { as: t5, method: 'DELETE' });
    assert.equal(res.status, 200);
    assert.equal(existsSync(path.join(dataDir, 'curs')), false);
    assert.equal(gw5.history.size, 0);
    assert.equal(loadLabels(stateDir).length, 1);
    assert.deepEqual(JSON.parse(readFileSync(path.join(stateDir, 'graph.layout.json'), 'utf8')).positions, { x: { x: 1, y: 2 } });
    const login = await c5('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    assert.equal((await c5('/api/history', { as: login.body.token as string, method: 'DELETE' })).status, 403);
  });
  });

describe('jwt sessions, attempt detail and route deletion', () => {
  const SECRET = Buffer.from('stand-secret', 'utf8');
  let gj: Gateway;
  let aj: ReturnType<typeof createAnalyticsServer>;
  let gp: number;
  let pj: number;
  let tj = '';

  function cj(
    pathname: string,
    init: { method?: string; body?: unknown; as?: string | null; port?: number } = {},
  ): Promise<{ status: number; body: Record<string, unknown>; error: string | null }> {
    const port = init.port ?? pj;
    return new Promise((resolve) => {
      const headers: Record<string, string> = {};
      if (init.body !== undefined) headers['content-type'] = 'application/json';
      if (init.as && init.as !== null) headers.authorization = `Bearer ${init.as}`;
      const req = http.request(
        { host: '127.0.0.1', port, path: pathname, method: init.method ?? (init.body === undefined ? 'GET' : 'POST'), headers, timeout: 5000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () => {
            const text = Buffer.concat(chunks).toString('utf8');
            let body: Record<string, unknown> = {};
            try {
              body = text.length > 0 ? (JSON.parse(text) as Record<string, unknown>) : {};
            } catch {
              body = { raw: text };
            }
            resolve({ status: res.statusCode ?? 0, body, error: null });
          });
        },
      );
      req.on('error', (e: Error) => resolve({ status: 0, body: {}, error: e.code ?? e.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: 0, body: {}, error: 'TIMEOUT' }); });
      if (init.body !== undefined) req.write(JSON.stringify(init.body));
      req.end();
    });
  }

  function jwtConfig() {
    return parseGatewayConfig(
      JSON.stringify({
        listen: { host: '127.0.0.1', port: 0 },
        analytics_listen: { host: '127.0.0.1', port: 0 },
        checker: [{ cidr: '127.0.0.9' }],
        admin: [{ cidr: '127.0.0.1' }],
        teams: [{ cidr: '127.0.0.9' }],
        routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:1' } },
      }),
    );
  }

  before(async () => {
    const config = jwtConfig();
    gj = new Gateway(config, { rateLimitPerSecond: 100, rateBurst: 100 });
    gp = await gj.listen();
    aj = createAnalyticsServer(config, gj, { verify, jwtSecret: SECRET });
    pj = await aj.listen();
    const login = await cj('/api/login', { body: { login: 'ops', password: 'hunter2' } });
    tj = login.body.token as string;
    // A JWT has three dot-separated parts; a session key has none.
    assert.equal(tj.split('.').length, 3);
  });

  after(async () => {
    await aj.close();
    await gj.close();
  });

  it('reads /api/me with the token the login issued', async () => {
    assert.equal((await cj('/api/me', { as: tj })).status, 200);
  });

  it('a rebuilt facade keeps the same secret, so the operator stays logged in', async () => {
    const config = jwtConfig();
    const g2 = new Gateway(config, { rateLimitPerSecond: 100, rateBurst: 100 });
    const gp2 = await g2.listen();
    try {
      const a2 = createAnalyticsServer(config, g2, { verify, jwtSecret: SECRET });
      const p2 = await a2.listen();
      try {
        const me = await cj('/api/me', { as: tj, port: p2 });
        assert.equal(me.status, 200, 'a restart must not log the operator out');
      } finally {
        await a2.close();
      }
    } finally {
      await g2.close();
      void gp2;
    }
  });

  it('a facade with a different secret turns the old token away', async () => {
    const config = jwtConfig();
    const g2 = new Gateway(config, { rateLimitPerSecond: 100, rateBurst: 100 });
    const gp2 = await g2.listen();
    try {
      const a2 = createAnalyticsServer(config, g2, { verify, jwtSecret: Buffer.from('other-stand', 'utf8') });
      const p2 = await a2.listen();
      try {
        assert.equal((await cj('/api/me', { as: tj, port: p2 })).status, 401);
      } finally {
        await a2.close();
      }
    } finally {
      await g2.close();
      void gp2;
    }
  });

  it('logout revokes the exact token at once, leaving older logins intact', async () => {
    const login = await cj('/api/login', { body: { login: 'ops', password: 'hunter2' } });
    const doomed = login.body.token as string;
    assert.equal((await cj('/api/logout', { as: doomed, method: 'POST' })).status, 200);
    assert.equal((await cj('/api/me', { as: doomed })).status, 401, 'revoked token must fail immediately');
    assert.equal((await cj('/api/me', { as: tj })).status, 200, 'unrelated sessions keep working');
  });

  it('a token without the formula is not a session', async () => {
    const me = await cj('/api/me', { as: 'not-a-jwt' });
    assert.equal(me.status, 401);
  });

  it('serves the full captured record by id for the flag popup', async () => {
    // Force the ingress to record a request with headers and a body, then open
    // it through the API the popup uses. The backend is a dead loopback, so the
    // attempt still exists with the error outcome -- the modal shows the record,
    // not the health of a service.
    const before = await cj('/api/history?limit=500', { as: tj });
    const seen = (before.body.attempts as Array<{ id: string; at: string }>) ?? [];
    assert.equal(
      await new Promise<number>((resolve) => {
        const req = http.request(
          { host: '127.0.0.1', port: gp, path: '/echo?AD{popup_probe}', method: 'POST', headers: { host: 'app.local', 'x-op': 'probe', 'content-type': 'text/plain' }, timeout: 5000 },
          (res) => {
            res.resume();
            res.on('end', () => resolve(res.statusCode ?? 0));
          },
        );
        req.on('error', () => resolve(0));
        req.write('hello body with a flag claim');
        req.end();
      }) >= 400,
      true,
    );
    const after = await cj('/api/history?limit=500', { as: tj });
    const attempts = (after.body.attempts as Array<{ id: string; status: unknown; headers?: unknown; body?: unknown }>) ?? [];
    const mine = attempts.find((x) => !seen.some((s) => s.id === x.id));
    assert.ok(mine, 'the probe must be recorded');
    const id = mine?.id ?? '';
    assert.ok(id.length > 0);
    const detail = await cj(`/api/attempt?id=${encodeURIComponent(id)}`, { as: tj });
    assert.equal(detail.status, 200);
    const attempt = detail.body.attempt as { id: string; headers?: Record<string, string>; body?: string; target: string };
    assert.equal(attempt.id, id);
    assert.equal(attempt.headers?.['x-op'], 'probe');
    assert.ok(attempt.body?.includes('hello body') === true || attempt.body === undefined);
    // Unknown ids are a 404, not a crash.
    assert.equal((await cj('/api/attempt?id=deadmilk', { as: tj })).status, 404);
  });

  it('an operator can drop a config route at runtime; a second drop is a 404', async () => {
    const drop = await cj('/api/routes?host=app.local', { as: tj, method: 'DELETE' });
    assert.equal(drop.status, 200);
    const services = await cj('/api/services', { as: tj });
    const routes = (services.body.routes as Array<{ host: string }>) ?? [];
    assert.equal(routes.some((r) => r.host === 'app.local'), false);
    assert.equal((await cj('/api/routes?host=app.local', { as: tj, method: 'DELETE' })).status, 404);
  });

  it('only an admin may delete routes', async () => {
    const login = await cj('/api/login', { body: { login: 'alpha', password: 'alpha-pass' } });
    assert.equal((await cj('/api/routes?host=nope.local', { as: login.body.token as string, method: 'DELETE' })).status, 403);
  });
});
