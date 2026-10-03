/**
 * HTTP contract tests.
 *
 * These run the real app against a temporary config directory, so they cover the
 * same path an operator hits: discover configs, analyse, filter, read reports and
 * ask about poisoning. Poisoning is the part with a hard safety contract, so it
 * gets the most assertions: the checker must never receive a poisoned value.
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import type { Server } from 'node:http';

// The app reads AD_CONFIG_DIR at import time, so the fixture must exist first.
const fixture = mkdtempSync(path.join(tmpdir(), 'ad-server-test-'));
const SECRET = 'test-secret-not-a-real-flag';

const APP_SOURCE = [
  'from flask import Flask',
  '',
  'app = Flask(__name__)',
  '',
  '@app.route("/api/user/<int:uid>", methods=["GET"])',
  'def get_user(uid):',
  '    return {"uid": uid}',
  '',
  '@app.route("/api/user/<int:uid>", methods=["DELETE"])',
  'def delete_user(uid):',
  '    if not is_admin():',
  '        raise PermissionError',
  '    return "deleted"',
  '',
  '@app.route("/api/flag", methods=["GET"])',
  'def get_flag():',
  '    return {"flag": current_flag()}',
  '',
].join('\n');

mkdirSync(path.join(fixture, 'app'), { recursive: true });
writeFileSync(path.join(fixture, 'app', 'auth.py'), APP_SOURCE, 'utf8');

const CONFIG = {
  service_name: 'Fixture',
  source_roots: [fixture],
  output_dir: path.join(fixture, 'out'),
  flag_format: { pattern: 'fx{[a-z0-9]{8}}', prefix: 'fx', body_alphabet: 'a-z0-9', min_length: 8 },
  known_flags: [],
  team_networks: [{ label: 'team', cidr: '10.10.1.0/24' }],
  checker_networks: [{ label: 'checker', cidr: '10.10.9.0/24' }],
  request_logs: [],
};

writeFileSync(path.join(fixture, 'Fixture.json'), JSON.stringify(CONFIG, null, 2), 'utf8');

// A second service with no flag pattern, to exercise the disabled path.
writeFileSync(
  path.join(fixture, 'NoPattern.json'),
  JSON.stringify(
    {
      ...CONFIG,
      service_name: 'NoPattern',
      flag_format: { pattern: '', prefix: '', body_alphabet: '', min_length: 0 },
    },
    null,
    2,
  ),
  'utf8',
);

process.env.AD_CONFIG_DIR = fixture;
process.env.AD_POISON_SECRET = SECRET;
process.env.AD_WEB_DIST = path.join(fixture, 'no-such-web-dist');

const { createApp, clearCache } = await import('../src/index.js');

let server: Server;
let base = '';

interface Json {
  status: number;
  body: any;
}

async function get(urlPath: string): Promise<Json> {
  const response = await fetch(`${base}${urlPath}`);
  return { status: response.status, body: await response.json() };
}

async function send(method: string, urlPath: string, body?: unknown): Promise<Json> {
  const response = await fetch(`${base}${urlPath}`, {
    method,
    headers: { 'content-type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}

before(async () => {
  const app = createApp();
  await new Promise<void>((resolve) => {
    server = app.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  assert.ok(address && typeof address === 'object');
  base = `http://127.0.0.1:${address.port}`;
});

after(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
  rmSync(fixture, { recursive: true, force: true });
});

describe('discovery', () => {
  it('reports health without leaking a stack trace', async () => {
    const { status, body } = await get('/api/health');
    assert.equal(status, 200);
    assert.equal(body.ok, true);
    assert.equal(typeof body.schema, 'string');
  });

  it('lists every discovered service with counts', async () => {
    const { status, body } = await get('/api/services');
    assert.equal(status, 200);
    const names = body.services.map((service: { name: string }) => service.name).sort();
    assert.deepEqual(names, ['Fixture', 'NoPattern']);
    const service = body.services.find((s: { name: string }) => s.name === 'Fixture');
    assert.ok(service);
    assert.equal(service.error, undefined);
    assert.ok(service.filesScanned >= 1);
    assert.ok(service.generatedUtc.length > 0);
    // Absolute server paths are not part of the summary.
    for (const key of Object.keys(service)) {
      assert.doesNotMatch(String(service[key]), /[A-Za-z]:\\/, `${key} leaks a filesystem path`);
    }
  });

  it('rejects a traversal attempt instead of resolving it', async () => {
    const { status, body } = await get('/api/services/..%2f..%2fpackage');
    assert.equal(status, 400);
    assert.match(body.error, /invalid service name/);
  });

  it('404s an unknown service', async () => {
    const { status, body } = await get('/api/services/DoesNotExist');
    assert.equal(status, 404);
    assert.match(body.error, /unknown service/);
  });
});

describe('report', () => {
  it('returns the report.json contract verbatim', async () => {
    const { status, body } = await get('/api/services/Fixture');
    assert.equal(status, 200);
    assert.equal(body.meta.service, 'Fixture');
    assert.equal(body.meta.schema_version.length > 0, true);
    // snake_case, exactly as report.json writes it
    assert.equal(typeof body.finding_counts, 'object');
    assert.ok(Array.isArray(body.unguarded_id_routes), 'unguarded_id_routes must be a list');
    assert.equal(typeof body.flag_flow, 'object');
    for (const finding of body.findings) {
      assert.equal(typeof finding.rule_id, 'string');
    }
  });

  it('flags an unguarded id route and not a guarded one', async () => {
    const { body } = await get('/api/services/Fixture');
    const routes = body.routes as {
      path: string;
      method: string;
      guarded: boolean;
      id_param: boolean;
    }[];
    const getUser = routes.find((r) => r.path.includes('/api/user/<int:uid>') && r.method === 'GET');
    const deleteUser = routes.find(
      (r) => r.path.includes('/api/user/<int:uid>') && r.method === 'DELETE',
    );
    assert.ok(getUser, `expected a GET route, got ${JSON.stringify(routes.map((r) => `${r.method} ${r.path}`))}`);
    assert.equal(getUser.id_param, true);
    assert.equal(getUser.guarded, false);
    assert.ok(deleteUser, 'expected a DELETE route');
    assert.equal(deleteUser.guarded, true);
    const unguarded = (body.unguarded_id_routes as { path: string; method: string }[]).map(
      (r) => `${r.method} ${r.path}`,
    );
    assert.ok(unguarded.includes('GET /api/user/<int:uid>'));
  });

  it('serves flag flow, runtime and routes sub-resources', async () => {
    const flow = await get('/api/services/Fixture/flagflow');
    assert.equal(flow.status, 200);
    assert.equal(flow.body.pattern_known, true);

    const runtime = await get('/api/services/Fixture/runtime');
    assert.equal(runtime.status, 200);
    assert.ok(Array.isArray(runtime.body.cross_actor_observations));

    const routes = await get('/api/services/Fixture/routes');
    assert.equal(routes.status, 200);
    assert.equal(routes.body.total, routes.body.routes.length);
  });

  it('serves the on-disk Markdown report as text/markdown', async () => {
    const response = await fetch(`${base}/api/services/Fixture/report.md`);
    assert.equal(response.status, 200);
    assert.match(response.headers.get('content-type') ?? '', /text\/markdown/);
    assert.match(await response.text(), /Fixture/);
  });
});

describe('findings filters', () => {
  it('filters by severity and keeps the total honest', async () => {
    const all = await get('/api/services/Fixture/findings');
    assert.equal(all.status, 200);
    assert.equal(all.body.limit, 100);
    assert.equal(all.body.offset, 0);

    const high = await get('/api/services/Fixture/findings?severity=high');
    for (const finding of high.body.findings) {
      assert.equal(finding.severity, 'high');
    }
    assert.ok(high.body.total <= all.body.total);
  });

  it('filters by rule id and free text', async () => {
    const byRule = await get('/api/services/Fixture/findings?rule=NO_AUTH_ON_ID_ROUTE');
    assert.equal(byRule.status, 200);
    for (const finding of byRule.body.findings) {
      assert.equal(finding.rule_id, 'NO_AUTH_ON_ID_ROUTE');
    }

    const byText = await get('/api/services/Fixture/findings?q=sqlite3');
    assert.equal(byText.status, 200);
    for (const finding of byText.body.findings) {
      assert.ok(
        `${finding.title} ${finding.description} ${JSON.stringify(finding.evidence)}`
          .toLowerCase()
          .includes('sqlite3'),
      );
    }
  });

  it('applies offset as a zero-based index', async () => {
    const all = await get('/api/services/Fixture/findings');
    assert.ok(all.body.total >= 2, `fixture should produce at least 2 findings, got ${all.body.total}`);

    const first = await get('/api/services/Fixture/findings?limit=1&offset=0');
    const second = await get('/api/services/Fixture/findings?limit=1&offset=1');
    assert.equal(first.body.offset, 0);
    assert.equal(second.body.offset, 1);
    assert.equal(first.body.findings.length, 1);
    assert.equal(second.body.findings.length, 1);
    // The same rule can fire on several lines, so compare the evidence site
    // rather than the rule id.
    assert.notDeepEqual(
      first.body.findings[0].evidence,
      second.body.findings[0].evidence,
    );

    // An offset past the end is an empty page, not an error.
    const past = await get('/api/services/Fixture/findings?limit=1&offset=9999');
    assert.equal(past.status, 200);
    assert.deepEqual(past.body.findings, []);
  });
});

describe('rules', () => {
  it('serves the whole pack with the fields the UI renders', async () => {
    const { status, body } = await get('/api/rules');
    assert.equal(status, 200);
    assert.equal(body.total, body.rules.length);
    assert.ok(body.total >= 40);
    for (const rule of body.rules) {
      for (const field of [
        'id',
        'category',
        'title',
        'severity',
        'description',
        'exploit',
        'breaker',
        'remediation',
      ]) {
        assert.ok(rule[field], `rule ${rule.id} is missing ${field}`);
      }
      assert.ok(Array.isArray(rule.cwe));
    }
  });

  it('filters by category', async () => {
    const { status, body } = await get('/api/rules?category=authentication');
    assert.equal(status, 200);
    for (const rule of body.rules) {
      assert.equal(rule.category, 'authentication');
    }
  });
});

describe('poisoning contract', () => {
  const flag = 'fx{deadbeef}';

  it('poisons team traffic with a distinct value', async () => {
    const { status, body } = await send('POST', '/api/poison', {
      service: 'Fixture',
      flag,
      actor: 'team',
      team: 't1',
      endpoint: '/get',
    });
    assert.equal(status, 200);
    assert.equal(body.action, 'poison');
    assert.equal(body.actor, 'team');
    assert.equal(body.team_key, 't1');
    assert.equal(body.flag_in, flag);
    assert.notEqual(body.flag_out, flag);
    // The redaction secret must never travel over the wire.
    assert.ok(!JSON.stringify(body).includes(SECRET));
  });

  it('never poisons the checker', async () => {
    const { status, body } = await send('POST', '/api/poison', {
      service: 'Fixture',
      flag,
      actor: 'checker',
      team: 't1',
      endpoint: '/get',
    });
    assert.equal(status, 200);
    assert.notEqual(body.action, 'poison');
    assert.equal(body.flag_out, flag);
  });

  it('never poisons an unknown actor', async () => {
    const { status, body } = await send('POST', '/api/poison', {
      service: 'Fixture',
      flag,
      actor: 'unknown',
      team: 't1',
      endpoint: '/get',
    });
    assert.equal(status, 200);
    assert.notEqual(body.action, 'poison');
    assert.equal(body.flag_out, flag);
  });

  it('gives two teams different values, and a stable one per team', async () => {
    const ask = async (team: string): Promise<string> => {
      const { body } = await send('POST', '/api/poison', {
        service: 'Fixture',
        flag,
        actor: 'team',
        team,
        endpoint: '/get',
      });
      return body.flag_out as string;
    };
    const [a1, b1, a2] = await Promise.all([ask('t1'), ask('t2'), ask('t1')]);
    assert.notEqual(a1, b1, 'per-team values must differ or teams cross-read');
    assert.equal(a1, a2, 'the same team must get a stable value');
  });

  it('requires a flag', async () => {
    const { status, body } = await send('POST', '/api/poison', { service: 'Fixture' });
    assert.equal(status, 400);
    assert.match(body.error, /flag is required/);
  });

  it('rejects an actor outside the enum', async () => {
    const { status, body } = await send('POST', '/api/poison', {
      service: 'Fixture',
      flag,
      actor: 'attacker',
    });
    assert.equal(status, 400);
    assert.match(body.error, /unknown actor/);
  });

  it('rejects a traversal service name', async () => {
    const { status, body } = await send('POST', '/api/poison', {
      service: '../package',
      flag,
      actor: 'team',
    });
    assert.equal(status, 400);
    assert.match(body.error, /invalid service name/);
  });

  it('stays disabled without a flag pattern and passes the flag through', async () => {
    const { status, body } = await send('POST', '/api/poison', {
      service: 'NoPattern',
      flag,
      actor: 'team',
      team: 't1',
      endpoint: '/get',
    });
    // An empty pattern is a decision, not a misconfiguration: the answer is 200
    // with `action: disabled`, and the flag comes back untouched.
    assert.equal(status, 200);
    assert.equal(body.action, 'disabled');
    assert.match(body.reason, /pattern/i);
    assert.equal(body.flag_out, flag);
    assert.ok(!JSON.stringify(body).includes(SECRET));
  });

  it('409s and refuses to derive a key when AD_POISON_SECRET is unset', async () => {
    const saved = process.env.AD_POISON_SECRET;
    delete process.env.AD_POISON_SECRET;
    try {
      const { status, body } = await send('POST', '/api/poison', {
        service: 'Fixture',
        flag,
        actor: 'team',
        team: 't1',
        endpoint: '/get',
      });
      assert.equal(status, 409);
      assert.equal(body.action, 'disabled');
      assert.match(body.reason, /AD_POISON_SECRET/);
      assert.equal(body.error, body.reason);
      assert.ok(!JSON.stringify(body).includes(SECRET));
    } finally {
      process.env.AD_POISON_SECRET = saved;
    }
  });
});

describe('caching', () => {
  it('reuses an analysis and re-runs on refresh', async () => {
    clearCache();
    const cold = await get('/api/services/Fixture');
    const warm = await get('/api/services/Fixture');
    assert.equal(cold.body.meta.generated_utc, warm.body.meta.generated_utc);

    // A refresh is a new analysis, so the timestamp may move on.
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const refreshed = await get('/api/services/Fixture?refresh=1');
    assert.equal(refreshed.status, 200);
    assert.notEqual(refreshed.body.meta.generated_utc, warm.body.meta.generated_utc);
  });
});

describe('unknown paths', () => {
  it('answers a missing API route with JSON, not the SPA shell', async () => {
    const { status, body } = await get('/api/nope');
    assert.equal(status, 404);
    assert.deepEqual(body, { error: 'not found' });
  });
});
