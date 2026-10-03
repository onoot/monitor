/**
 * Config parsing, with the emphasis on the cases that would otherwise surface
 * as strange runtime behaviour: an unknown hostname must resolve to nothing, and
 * a gateway with no allowlist must refuse to start.
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { GatewayConfigError, parseGatewayConfig } from '../src/config.js';

const MINIMAL = JSON.stringify({
  checker: [{ cidr: '10.77.0.9' }],
  teams: [{ cidr: '10.0.0.0/8', team: 'everyone' }],
  routes: {
    'curs.local': { service: 'curs', upstream: '127.0.0.1:8083' },
  },
});

function parse(extra: Record<string, unknown> = {}, base: unknown = MINIMAL): ReturnType<typeof parseGatewayConfig> {
  const merged = typeof base === 'string' ? JSON.parse(base) : base;
  return parseGatewayConfig(JSON.stringify({ ...merged, ...extra }));
}

describe('routes', () => {
  it('resolves a declared hostname to its upstream', () => {
    const route = parse().routes.get('curs.local');
    assert.equal(route?.upstreamHost, '127.0.0.1');
    assert.equal(route?.upstreamPort, 8083);
    assert.equal(route?.service, 'curs');
  });

  it('has no route for a hostname the operator never declared', () => {
    // This is the SSRF boundary: an unknown Host must not become a target.
    assert.equal(parse().routes.get('evil.example.com'), undefined);
  });

  it('lowercases hostnames so lookup is not case-sensitive', () => {
    const cfg = parse({
      routes: { 'CURS.Local': { service: 'curs', upstream: '127.0.0.1:8083' } },
    });
    assert.equal(cfg.routes.get('curs.local')?.upstreamPort, 8083);
  });

  it('parses a bracketed ipv6 upstream', () => {
    const cfg = parse({
      routes: { 'v6.local': { service: 'curs', upstream: '[::1]:8083' } },
    });
    assert.equal(cfg.routes.get('v6.local')?.upstreamHost, '::1');
  });

  it('rejects an upstream that is not host:port', () => {
    assert.throws(
      () => parse({ routes: { 'x.local': { service: 'curs', upstream: 'http://evil/' } } }),
      GatewayConfigError,
    );
  });

  it('rejects a hostname that is not a hostname', () => {
    assert.throws(
      () => parse({ routes: { 'x local/y': { service: 'curs', upstream: '127.0.0.1:1' } } }),
      GatewayConfigError,
    );
  });

  it('rejects a route with no service', () => {
    assert.throws(
      () => parse({ routes: { 'x.local': { upstream: '127.0.0.1:1' } } }),
      GatewayConfigError,
    );
  });

  it('accepts a utf-8 BOM, which is what a Windows editor writes', () => {
    // PowerShell's `Set-Content -Encoding utf8` and Notepad both prepend one.
    // JSON forbids it, but the config is hand-edited on the machine it runs on,
    // so refusing to start over an invisible character helps nobody.
    const cfg = parseGatewayConfig(`\ufeff${MINIMAL}`);
    assert.equal(cfg.routes.get('curs.local')?.upstreamPort, 8083);
    assert.equal(cfg.sources.length > 0, true);
  });

  it('still rejects genuinely broken JSON', () => {
    assert.throws(() => parseGatewayConfig('{"checker": ['), GatewayConfigError);
  });
});

describe('listen specs', () => {
  it('defaults both ports', () => {
    const cfg = parse();
    assert.equal(cfg.listen.port, 8080);
    assert.equal(cfg.analyticsListen.port, 8787);
  });

  it('rejects a port that is not a port', () => {
    assert.throws(() => parse({ listen: { host: '0.0.0.0', port: 99999 } }), GatewayConfigError);
  });
});

describe('allowlist', () => {
  it('refuses to start with no addresses at all', () => {
    assert.throws(
      () => parse({}, { routes: {} }),
      /refusing to start/,
    );
  });

  it('rejects a malformed cidr by name', () => {
    assert.throws(
      () => parse({ checker: [{ cidr: 'ten.77.0.9' }] }),
      /cannot parse/,
    );
  });

  it('keeps the checker ahead of teams in the resolved map', () => {
    const kinds = parse().network.describe().map((r) => r.kind);
    assert.deepEqual(kinds, ['checker', 'team']);
  });

  it('carries the own flag and the own_team name through', () => {
    const cfg = parse({
      teams: [{ cidr: '10.1.2.0/28', team: 'alpha', own: true }],
      own_team: 'alpha',
    });
    assert.equal(cfg.network.describe().find((r) => r.cidr === '10.1.2.0/28')?.own, true);
    assert.equal(cfg.ownTeam, 'alpha');
  });

  it('ignores an own flag on a non-team range', () => {
    const cfg = parse({ checker: [{ cidr: '10.77.0.9', own: true }] });
    assert.equal(cfg.network.describe().find((r) => r.kind === 'checker')?.own, undefined);
  });
});

describe('ingress_ports', () => {
  it('maps a public port onto a listener at public+offset and a default upstream', () => {
    const cfg = parse({ ingress_ports: { 8083: 'curs' } });
    const route = cfg.ingressPorts.get(8083);
    assert.equal(route?.service, 'curs');
    assert.equal(route?.upstreamHost, '127.0.0.1');
    assert.equal(route?.upstreamPort, 8083);
    assert.equal(route?.listenPort, 8083 + cfg.redirectOffset);
  });

  it('accepts an explicit upstream override', () => {
    const cfg = parse({ ingress_ports: { 8083: { service: 'curs', upstream: '10.0.0.5:8083' } } });
    assert.equal(cfg.ingressPorts.get(8083)?.upstreamHost, '10.0.0.5');
  });

  it('uses a custom redirect_offset', () => {
    const cfg = parse({ redirect_offset: 5000, ingress_ports: { 8083: 'curs' } });
    assert.equal(cfg.ingressPorts.get(8083)?.listenPort, 8083 + 5000);
  });

  it('rejects a non-numeric port key', () => {
    assert.throws(
      () => parse({ ingress_ports: { abc: 'curs' } }),
      GatewayConfigError,
    );
  });

  it('rejects an offset that would overflow the port range', () => {
    assert.throws(
      () => parse({ redirect_offset: 65000, ingress_ports: { 8083: 'curs' } }),
      /overflows/,
    );
  });
});

describe('protected_ports', () => {
  it('parses a port-to-note map and defaults to dropping them', () => {
    const cfg = parse({ protected_ports: { 5432: 'postgresql' } });
    assert.equal(cfg.protectedPorts.get(5432), 'postgresql');
    assert.equal(cfg.allowProtectedPorts, false);
  });

  it('defaults a missing note to the port itself', () => {
    const cfg = parse({ protected_ports: { 3306: '' } });
    assert.equal(cfg.protectedPorts.get(3306), '3306');
  });

  it('honours allow_protected_ports', () => {
    const cfg = parse({ protected_ports: { 5432: 'postgres' }, allow_protected_ports: true });
    assert.equal(cfg.allowProtectedPorts, true);
  });

  it('rejects a non-boolean toggle', () => {
    assert.throws(() => parse({ allow_protected_ports: 'yes' }), GatewayConfigError);
  });

  it('refuses a public port claimed by both a route and a protection', () => {
    assert.throws(
      () => parse({ ingress_ports: { 8083: 'curs' }, protected_ports: { 8083: 'panel' } }),
      /both claim port 8083/,
    );
  });

  it('rejects a protected port whose listener would overflow', () => {
    assert.throws(
      () => parse({ redirect_offset: 65000, protected_ports: { 8083: 'panel' } }),
      /overflows/,
    );
  });
});
