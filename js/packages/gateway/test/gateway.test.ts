/**
 * The gateway against a real upstream.
 *
 * A stub server stands in for a course service so the assertions can be about the
 * gateway's own behaviour: that a stranger is forwarded and recorded rather than
 * cut, that a checker reaches the backend with attack syntax intact, that a
 * participant with attack syntax is cut at the connection level, and that a
 * forged Host cannot redirect traffic.
 */

import { strict as assert } from 'node:assert';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { after, before, describe, it } from 'node:test';

import { parseGatewayConfig } from '../src/config.js';
import { Gateway } from '../src/gateway.js';
import { RequestHistory } from '../src/history.js';

interface Seen {
  method: string;
  url: string;
  host: string | undefined;
  forwardedFor: string | undefined;
  forwardedHost: string | undefined;
}

let backend: http.Server;
let backendPort = 0;
let gateway: Gateway;
let gatewayPort = 0;
let history: RequestHistory;
let seen: Seen[] = [];

/**
 * Built inside `before`, not at module load: the upstream port is only known
 * once the stub is listening.
 */
function gatewayConfig(): unknown {
  return {
    // Port 0: a test must never bind a real service port, and 8080 is in use on
    // this host by the AltayCoin backend.
    listen: { host: '127.0.0.1', port: 0 },
    checker: [{ cidr: '127.0.0.9' }],
    admin: [{ cidr: '127.0.0.8' }],
    teams: [{ cidr: '127.0.0.1', team: 'alpha' }],
    routes: { 'app.local': { service: 'curs', upstream: `127.0.0.1:${backendPort}` } },
  };
}

interface ProbeResult {
  status: number | null;
  body: string;
  error: string | null;
}

/**
 * Send a request, and report a reset as `error` rather than a status.
 *
 * `http.request` reports a destroyed socket as ECONNRESET, which is what a client
 * sees when a connection is refused. Asserting on the status alone would let a
 * reset masquerade as any outcome, which is the distinction under test here.
 */
function probe(
  headers: Record<string, string>,
  path = '/',
  method = 'GET',
  body?: string,
  /** Source address, so a test can pretend to be the checker. */
  localAddress?: string,
): Promise<ProbeResult> {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: gatewayPort,
        path,
        method,
        headers,
        ...(localAddress === undefined ? {} : { localAddress }),
        timeout: 5000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? null,
            body: Buffer.concat(chunks).toString('utf8'),
            error: null,
          }),
        );
      },
    );
    req.on('error', (err: Error) => resolve({ status: null, body: '', error: err.code ?? err.message }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: null, body: '', error: 'TIMEOUT' });
    });
    if (body !== undefined) req.write(body);
    req.end();
  });
}

before(async () => {
  backend = http.createServer((req, res) => {
    seen.push({
      method: req.method ?? 'GET',
      url: req.url ?? '/',
      host: req.headers.host,
      forwardedFor: req.headers['x-forwarded-for'] as string | undefined,
      forwardedHost: req.headers['x-forwarded-host'] as string | undefined,
    });
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('backend ok');
  });
  await new Promise<void>((resolve) => backend.listen(0, '127.0.0.1', resolve));
  backendPort = (backend.address() as AddressInfo).port;

  const cfg = parseGatewayConfig(JSON.stringify(gatewayConfig()));
  history = new RequestHistory({ capacity: 200 });
  gateway = new Gateway(cfg, { rateLimitPerSecond: 1000, rateBurst: 2000 }, { history });
  gatewayPort = await gateway.listen();
});

after(async () => {
  await gateway.close();
  await new Promise<void>((resolve) => backend.close(() => resolve()));
});

describe('routing', () => {
  it('forwards a declared hostname to its upstream', async () => {
    seen = [];
    const result = await probe({ host: 'app.local' });
    assert.equal(result.status, 200);
    assert.equal(result.body, 'backend ok');
    assert.equal(seen.length, 1);
  });

  it('preserves the client path, including the query', async () => {
    seen = [];
    const result = await probe({ host: 'app.local' }, '/user/login?next=%2Fadmin');
    assert.equal(result.status, 200, 'a redirect target is not an attack');
    assert.equal(seen[0]?.url, '/user/login?next=%2Fadmin');
  });

  it('drops the connection for a hostname the operator never declared', async () => {
    seen = [];
    const result = await probe({ host: 'evil.example.com' });
    // No 404: an unrouted destination is broken at the socket, so a scan learns
    // nothing about what is listening behind the network.
    assert.equal(result.status, null);
    assert.equal(result.body, '');
    assert.ok(
      result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED',
      `expected a broken connection, got ${result.error ?? `status ${result.status}`}`,
    );
    // The critical part: nothing was forwarded anywhere.
    assert.equal(seen.length, 0);
  });

  it('drops the connection when the Host header is missing', async () => {
    const result = await probe({});
    assert.equal(result.status, null);
    assert.ok(result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED', `got ${result.error}`);
  });

  it('does not let a forged X-Forwarded-Host change the destination', async () => {
    seen = [];
    const result = await probe({ host: 'app.local', 'x-forwarded-host': '169.254.169.254' });
    assert.equal(result.status, 200);
    assert.equal(seen.length, 1);
    // A trusted proxy states the host it routed to; the client's claim is
    // replaced rather than relayed, so nothing downstream reads the forged value.
    assert.equal(seen[0]?.forwardedHost, 'app.local');
  });
});

describe('strangers', () => {
  it('forwards a stranger instead of refusing, so the grader is never cut', async () => {
    // 127.0.0.5 is not in any configured range. The proxy surface must not
    // refuse it: on a live run the grader's address is beyond our control, and
    // a stranger that is cut is exactly a grader that just lost a check.
    const result = await probe({ host: 'app.local' }, '/', 'GET', undefined, '127.0.0.5');
    assert.equal(result.status, 200, 'a stranger must be forwarded, not refused');
  });

  it('forwards a stranger even when it sends a payload that would block a team', async () => {
    // Without a checker entry in the config -- the case the stand runs today --
    // an unlisted address with attack syntax still reaches the backend. Only a
    // positively-known participant is policed.
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
      '127.0.0.5',
    );
    assert.equal(result.status, 200, 'an unlisted address must not be attack-blocked');
  });

  it('records the unlisted address as a candidate so the operator can add it later', () => {
    const candidates = history.unknownCandidates();
    assert.ok(
      candidates.some((c) => c.ip === '127.0.0.5'),
      'a forwarded stranger must still appear as a candidate',
    );
  });

  it('forwards the operator instead of attack-blocking them, even with a payload', async () => {
    // 127.0.0.8 is the admin in the config. The rules exist to police
    // participants; the operator's own traffic must never be cut by them.
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
      '127.0.0.8',
    );
    assert.equal(result.status, 200, 'the operator must pass regardless of the payload');
  });
});

/** Like `probe`, but also reports response headers. */
function probeWithHeaders(
  headers: Record<string, string>,
  path = '/',
): Promise<{ status: number | null; retryAfter: string | undefined }> {
  return new Promise((resolve) => {
    const req = http.request(
      { host: '127.0.0.1', port: gatewayPort, path, headers, timeout: 5000 },
      (res) => {
        res.resume();
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? null,
            retryAfter: (res.headers['retry-after'] as string | undefined) ?? undefined,
          }),
        );
      },
    );
    req.on('error', () => resolve({ status: null, retryAfter: undefined }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: null, retryAfter: undefined });
    });
    req.end();
  });
}

describe('checker', () => {
  it('is not blocked by a payload that would block a team', async () => {
    // 127.0.0.9 is the checker in the config. The same request from a team
    // address is blocked in the suite below, so this is a real comparison.
    const result = await probe({ host: 'app.local' }, '/.git/config', 'GET', undefined, '127.0.0.9');
    assert.equal(result.status, 200, 'the checker must never be blocked');
  });

  it('is forwarded even when it sends injection syntax', async () => {
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
      '127.0.0.9',
    );
    assert.equal(result.status, 200);
  });

  it('is recorded as the checker, not as a team', async () => {
    await probe({ host: 'app.local' }, '/', 'GET', undefined, '127.0.0.9');
    const recent = history.recent(1)[0];
    assert.equal(recent?.principal, 'checker');
    assert.equal(recent?.ip, '127.0.0.9');
  });
});

describe('blocking', () => {
  it('drops the connection on a git metadata probe instead of answering', async () => {
    seen = [];
    // No status, no body: the client must not learn that anything is inspecting
    // it, or which rule fired.
    const result = await probe({ host: 'app.local' }, '/.git/config');
    assert.equal(result.status, null);
    assert.equal(result.body, '');
    assert.ok(
      result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED',
      `expected a broken connection, got ${result.error ?? `status ${result.status}`}`,
    );
    // The backend must not have seen it.
    assert.equal(seen.length, 0);
  });

  it('keeps the rule in the history, since the client never learns it', async () => {
    await probe({ host: 'app.local' }, '/.env');
    const recent = history.recent(1)[0];
    assert.equal(recent?.outcome, 'blocked');
    assert.equal(recent?.status, null);
    assert.ok(
      (recent?.rules ?? []).some((id) => id.startsWith('exposure-')),
      `expected an exposure rule, got ${(recent?.rules ?? []).join(',')}`,
    );
  });

  it('does not answer a sql injection attempt either', async () => {
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
    );
    assert.equal(result.status, null);
    assert.equal(result.body, '');
    assert.ok(result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED', `got ${result.error}`);
  });

  it('blocks a sql injection attempt from a team address', async () => {
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
    );
    assert.equal(result.status, null, 'a held-back request gets no status');
  });

  it('lets ordinary traffic through', async () => {
    seen = [];
    const result = await probe({ host: 'app.local' }, '/users/1');
    assert.equal(result.status, 200);
    assert.equal(seen.length, 1);
  });

  it('forwards a post body without a framing conflict', async () => {
    // A client that sends a chunked body must not be relayed alongside a
    // content-length; the upstream answers 400 to that, which is a gateway bug
    // rather than anything the client did.
    seen = [];
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      'login=alice&password=hunter2',
    );
    assert.equal(result.status, 200);
    assert.equal(seen.length, 1);
  });

  it('does not block an ordinary form post', async () => {
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      'login=alice&password=hunter2',
    );
    assert.equal(result.status, 200);
  });
});

describe('client address', () => {
  it('passes the real peer to the upstream, not the gateway', async () => {
    seen = [];
    await probe({ host: 'app.local' });
    assert.equal(seen[0]?.forwardedFor, '127.0.0.1');
  });
});

describe('throttling', () => {
  // Its own gateway with limits low enough to reach inside a test run, instead
  // of lowering the shared one and making every other test slower.
  let tight: Gateway;
  let tightPort = 0;
  let tightBackend: http.Server;

  before(async () => {
    tightBackend = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    await new Promise<void>((resolve) => tightBackend.listen(0, '127.0.0.1', resolve));
    const backendPort2 = (tightBackend.address() as AddressInfo).port;

    const config = gatewayConfig() as Record<string, unknown>;
    (config.routes as Record<string, unknown>)['app.local'] = { service: 'curs', upstream: `127.0.0.1:${backendPort2}` };
    tight = new Gateway(parseGatewayConfig(JSON.stringify(config)), { rateLimitPerSecond: 5, rateBurst: 10 });
    tightPort = await tight.listen();
  });

  after(async () => {
    await tight.close();
    await new Promise<void>((resolve) => tightBackend.close(() => resolve()));
  });

  interface BurstResult {
    status: number | null;
    error: string | null;
  }

  /** Requests fired together, so they really do arrive inside one second. */
  function burst(count: number, prefix: string, body?: string): Promise<BurstResult[]> {
    return Promise.all(
      Array.from({ length: count }, (_, i) =>
        new Promise<BurstResult>((resolve) => {
          const req = http.request(
            {
              host: '127.0.0.1',
              port: tightPort,
              path: `${prefix}${i}`,
              method: body === undefined ? 'GET' : 'POST',
              headers: { host: 'app.local', ...(body === undefined ? {} : { 'content-type': 'application/x-www-form-urlencoded' }) },
              timeout: 5000,
            },
            (res) => {
              res.resume();
              res.on('end', () => resolve({ status: res.statusCode ?? null, error: null }));
            },
          );
          req.on('error', (e: Error) => resolve({ status: null, error: e.code ?? e.message }));
          req.on('timeout', () => { req.destroy(); resolve({ status: null, error: 'TIMEOUT' }); });
          if (body !== undefined) req.write(body);
          req.end();
        }),
      ),
    );
  }

  it('lets a burst through when it is under the limit', async () => {
    const results = await burst(3, '/?calm=');
    assert.deepEqual([...new Set(results.map((r) => r.status))], [200]);
  });

  it('drops a held-back request rather than answering it', async () => {
    // Same treatment as an attack: the client gets a broken connection, so a
    // throttle is not distinguishable from a block by what it can see.
    const results = await burst(60, '/?i=');
    const held = results.filter((r) => r.status === null);
    assert.ok(held.length > 0, `expected some connections dropped, statuses=${[...new Set(results.map((r) => r.status))].join(',')}`);
    assert.ok(
      held.every((r) => r.error === 'ECONNRESET' || r.error === 'ECONNREFUSED'),
      `unexpected errors: ${[...new Set(held.map((r) => r.error))].join(',')}`,
    );
  });

  it('records throttled requests separately from blocked ones', async () => {
    const before2 = tight.history.recent(500).filter((a) => a.outcome === 'throttled').length;
    await burst(60, '/?m=');
    const after2 = tight.history.recent(500).filter((a) => a.outcome === 'throttled').length;
    assert.ok(after2 > before2, 'throttling has to be visible to the operator');
    const throttled = tight.history.recent(500).filter((a) => a.outcome === 'throttled');
    assert.ok(
      throttled.every((a) => a.status === null),
      'a throttled request never got a status',
    );
  });

  it('records a mixed burst as blocked, not throttled, when an attack is present', async () => {
    // The attack is the reason to hold the request; the outcome the operator
    // reads has to say so.
    const before2 = tight.history.recent(500).filter((a) => a.outcome === 'blocked').length;
    await burst(60, '/?p=', "user=admin' or '1'='1");
    const blocked = tight.history.recent(500).filter((a) => a.outcome === 'blocked');
    assert.ok(blocked.length > before2, 'expected blocked attempts');
    assert.ok(
      blocked.some((a) => a.rules.some((r) => r.startsWith('sqli-'))),
      `expected a sqli rule, saw ${[...new Set(blocked.flatMap((a) => a.rules))].join(',')}`,
    );
  });
});

describe('ingress_ports (port-redirection mode)', () => {
  let portGateway: Gateway;
  const PUBLIC_PORT = 19002;
  // redirect_offset defaults to 10000; the gateway binds public+offset.
  const INGRESS_LISTEN = PUBLIC_PORT + 10_000;

  before(async () => {
    const config = {
      listen: { host: '127.0.0.1', port: 0 },
      checker: [{ cidr: '127.0.0.9' }],
      teams: [{ cidr: '127.0.0.1', team: 'alpha' }],
      routes: { 'app.local': { service: 'curs', upstream: `127.0.0.1:${backendPort}` } },
      ingress_ports: { [String(PUBLIC_PORT)]: { service: 'curs', upstream: `127.0.0.1:${backendPort}` } },
    };
    portGateway = new Gateway(parseGatewayConfig(JSON.stringify(config)));
    await portGateway.listen();
  });

  after(async () => {
    await portGateway.close();
  });

  it('routes by the listening port even when the Host header matches nothing', async () => {
    seen = [];
    // This is a client on a real network who dialled the service's address; its
    // Host is that address, not a declared hostname. The listener port (public+
    // offset, as netfilter redirected it) must decide the route.
    const result = await new Promise<ProbeResult>((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port: INGRESS_LISTEN, path: '/', method: 'GET', headers: { host: '10.0.0.5:19002' }, timeout: 5000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () =>
            resolve({ status: res.statusCode ?? null, body: Buffer.concat(chunks).toString('utf8'), error: null }),
          );
        },
      );
      req.on('error', (err: Error) => resolve({ status: null, body: '', error: err.code ?? err.message }));
      req.end();
    });
    assert.equal(result.status, 200, 'a port-based route must forward like a hostname route');
    assert.equal(seen.length, 1);
    assert.equal(seen[0]?.forwardedHost, 'curs:19002');
    assert.equal(result.error, null, `history=${JSON.stringify(portGateway.history.recent(3))}`);
  });
});

describe('unrouted requests', () => {
  it('records a dropped unrouted request with no status', async () => {
    await probe({ host: 'evil.example.com' }, '/.git/config');
    const recent = history.recent(1)[0];
    assert.equal(recent?.outcome, 'error');
    assert.equal(recent?.reason, 'no route');
    assert.equal(recent?.status, null);
    assert.equal(recent?.host, 'evil.example.com');
  });
});

describe('address labels (UI overrides)', () => {
  it('lets a labelled address become a checker without a restart', async () => {
    // 127.0.0.5 is unknown in the config. Labelled as checker, it must be
    // forwarded with attack syntax, exactly like any checker.
    gateway.applySourceOverrides([{ kind: 'checker', cidr: '127.0.0.5' }]);
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
      '127.0.0.5',
    );
    assert.equal(result.status, 200, 'a labelled checker must not be attack-blocked');
    const recent = history.recent(1)[0];
    assert.equal(recent?.principal, 'checker');
  });

  it('labelling the same address as a team puts it under the rules', async () => {
    gateway.applySourceOverrides([{ kind: 'team', cidr: '127.0.0.5', team: 'beta' }]);
    const result = await probe(
      { host: 'app.local', 'content-type': 'application/x-www-form-urlencoded' },
      '/login',
      'POST',
      "user=admin' or '1'='1",
      '127.0.0.5',
    );
    assert.equal(result.status, null, 'a labelled team address must be attack-blocked');
    const recent = history.recent(1)[0];
    assert.equal(recent?.principal, 'team');
    assert.equal(recent?.team, 'beta');
    gateway.applySourceOverrides([]);
  });

  it('flags a labelled own-team address in the recorded attempt', async () => {
    gateway.applySourceOverrides([{ kind: 'team', cidr: '127.0.0.5', team: 'beta', own: true }]);
    const result = await probe({ host: 'app.local' }, '/', 'GET', undefined, '127.0.0.5');
    assert.equal(result.status, 200);
    const recent = history.recent(1)[0];
    assert.equal(recent?.principal, 'team');
    assert.equal(recent?.own, true);
    gateway.applySourceOverrides([]);
  });

  it('reports the effective map to the operator', () => {
    gateway.applySourceOverrides([{ kind: 'checker', cidr: '127.0.0.5' }]);
    const kinds = gateway.network.describe().map((r) => r.kind);
    assert.equal(kinds.filter((k) => k === 'checker').length, 2);
    gateway.applySourceOverrides([]);
  });
});

describe('protected ports (port-redirection mode)', () => {
  let dbGateway: Gateway;
  let allowGateway: Gateway;
  const DB_PUBLIC = 19003;
  const DB_LISTEN = DB_PUBLIC + 10_000;

  before(async () => {
    const base = {
      listen: { host: '127.0.0.1', port: 0 },
      checker: [{ cidr: '127.0.0.9' }],
      teams: [{ cidr: '127.0.0.1', team: 'alpha' }],
      routes: { 'app.local': { service: 'curs', upstream: `127.0.0.1:${backendPort}` } },
      protected_ports: { [String(DB_PUBLIC)]: 'postgresql' },
    };
    dbGateway = new Gateway(parseGatewayConfig(JSON.stringify(base)));
    await dbGateway.listen();
    allowGateway = new Gateway(
      parseGatewayConfig(JSON.stringify({ ...base, allow_protected_ports: true })),
    );
    await allowGateway.listen();
  });

  after(async () => {
    await dbGateway.close();
    await allowGateway.close();
  });

  function dial(port: number, gw: Gateway): Promise<ProbeResult> {
    return new Promise((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port, path: '/', method: 'GET', headers: { host: `10.0.0.5:${DB_PUBLIC}` }, timeout: 5000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () =>
            resolve({ status: res.statusCode ?? null, body: Buffer.concat(chunks).toString('utf8'), error: null }),
          );
        },
      );
      req.on('error', (err: Error) => resolve({ status: null, body: '', error: err.code ?? err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: null, body: '', error: 'TIMEOUT' }); });
      req.end();
    });
  }

  it('destroys a connection aimed at a protected port', async () => {
    const result = await dial(DB_LISTEN, dbGateway);
    assert.equal(result.status, null);
    assert.equal(result.body, '');
    assert.ok(result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED', `got ${result.error}`);
    const recent = dbGateway.history.recent(1)[0];
    assert.equal(recent?.outcome, 'blocked');
    assert.equal(recent?.reason, 'protected port postgresql');
    assert.equal(recent?.status, null);
  });

  it('does not bind a protected port when allow_protected_ports is on', async () => {
    // With the toggle on, the redirected traffic is left to the service's own
    // listener, so nothing on the offset answers and nothing is recorded.
    const result = await dial(DB_LISTEN, allowGateway);
    assert.ok(result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED', `got ${result.error}`);
    assert.equal(allowGateway.history.size, 0);
  });
});

describe('runtime ingress ports (UI services)', () => {
  let rtGateway: Gateway;
  const RT_PUBLIC = 19004;
  const RT_LISTEN = RT_PUBLIC + 10_000;

  before(async () => {
    rtGateway = new Gateway(
      parseGatewayConfig(
        JSON.stringify({
          listen: { host: '127.0.0.1', port: 0 },
          checker: [{ cidr: '127.0.0.9' }],
          teams: [{ cidr: '127.0.0.1', team: 'alpha' }],
          routes: { 'app.local': { service: 'curs', upstream: `127.0.0.1:${backendPort}` } },
        }),
      ),
    );
    await rtGateway.listen();
  });

  after(async () => {
    await rtGateway.close();
  });

  function dial(port: number): Promise<ProbeResult> {
    return new Promise((resolve) => {
      const req = http.request(
        { host: '127.0.0.1', port, path: '/', method: 'GET', headers: { host: `10.0.0.5:${RT_PUBLIC}` }, timeout: 5000 },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (c: Buffer) => chunks.push(c));
          res.on('end', () =>
            resolve({ status: res.statusCode ?? null, body: Buffer.concat(chunks).toString('utf8'), error: null }),
          );
        },
      );
      req.on('error', (err: Error) => resolve({ status: null, body: '', error: err.code ?? err.message }));
      req.on('timeout', () => { req.destroy(); resolve({ status: null, body: '', error: 'TIMEOUT' }); });
      req.end();
    });
  }

  it('routes a port added by the operator without a restart', async () => {
    const added = await rtGateway.addIngressPort(RT_PUBLIC, 'curs', `127.0.0.1:${backendPort}`);
    assert.equal(added.ok, true, added.error ?? '');
    const result = await dial(RT_LISTEN);
    assert.equal(result.status, 200);
    assert.equal(result.error, null);
    assert.equal(rtGateway.activeIngressPorts.some((r) => r.publicPort === RT_PUBLIC), true);
  });

  it('refuses to double-route the same port', async () => {
    const again = await rtGateway.addIngressPort(RT_PUBLIC, 'curs', `127.0.0.1:${backendPort}`);
    assert.equal(again.ok, false);
  });

  it('stops routing a removed port', async () => {
    const removed = await rtGateway.removeIngressPort(RT_PUBLIC);
    assert.equal(removed.ok, true);
    const result = await dial(RT_LISTEN);
    assert.ok(result.error === 'ECONNRESET' || result.error === 'ECONNREFUSED', `got ${result.error}`);
  });
});
