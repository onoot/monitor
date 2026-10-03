import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { parseGatewayConfig } from '../src/config.js';
import { Gateway } from '../src/gateway.js';
import { buildTopology, parseTopologyYaml, toYaml, topologyToYaml } from '../src/topology.js';

function config() {
  return parseGatewayConfig(
    JSON.stringify({
      listen: { host: '127.0.0.1', port: 0 },
      analytics_listen: { host: '127.0.0.1', port: 0 },
      checker: [{ cidr: '10.77.0.9' }],
      admin: [{ cidr: '10.77.0.1' }],
      teams: [
        { cidr: '10.77.0.0/28', team: 'alpha' },
        { cidr: '10.77.0.16/28', team: 'beta' },
      ],
      routes: {
        'curs.local': { service: 'curs', upstream: 'curs:8083' },
        'app.local': { service: 'web', upstream: 'web:80' },
      },
    }),
  );
}

describe('topology graph', () => {
  it('lays actors, the gateway, hosts and upstreams into layers', async () => {
    const gw = new Gateway(config(), { rateLimitPerSecond: 100, rateBurst: 100 });
    await gw.listen();
    try {
      const topo = buildTopology({
        config: config(),
        ingress: gw,
        services: [
          {
            host: 'curs:8083',
            service: 'curs',
            upstream: 'curs:8083',
            upstreamHost: 'curs',
            upstreamPort: 8083,
            publicPort: 8083,
            listenPort: 8083,
          },
        ],
        now: new Date('2026-01-01T00:00:00.000Z'),
      });

      const byId = new Map(topo.nodes.map((n) => [n.id, n]));
      assert.equal(byId.get('actor:checker')?.layer, 0);
      assert.equal(byId.get('actor:team:alpha')?.layer, 0);
      assert.equal(byId.get('actor:team:beta')?.layer, 0);
      assert.equal(byId.get('gateway')?.layer, 1);
      assert.equal(byId.get('host:curs.local')?.layer, 2);
      assert.equal(byId.get('port:8083')?.layer, 2);
      assert.equal(byId.get('up:curs:8083')?.layer, 3);
      assert.equal(byId.get('up:web:80')?.layer, 3);
      assert.equal(byId.get('unknown'), undefined);
      assert.equal(topo.version, 1);
      assert.equal(topo.generatedAt, '2026-01-01T00:00:00.000Z');

      // Every actor reaches the gateway; every way in reaches its upstream.
      assert.ok(topo.edges.some((e) => e.from === 'actor:checker' && e.to === 'gateway'));
      assert.ok(topo.edges.some((e) => e.from === 'gateway' && e.to === 'host:curs.local' && e.label === 'host'));
      assert.ok(topo.edges.some((e) => e.from === 'host:curs.local' && e.to === 'up:curs:8083' && e.label === 'curs'));
      assert.ok(topo.edges.some((e) => e.from === 'gateway' && e.to === 'port:8083' && e.label === 'порт'));
      // The same upstream is one node even though a route and a port both use it.
      assert.equal(topo.nodes.filter((n) => n.id === 'up:curs:8083').length, 1);
    } finally {
      await gw.close();
    }
  });

  it('marks discovered-but-unoccupied ports as candidates, not live paths', async () => {
    const gw = new Gateway(config(), { rateLimitPerSecond: 100, rateBurst: 100 });
    await gw.listen();
    try {
      const topo = buildTopology({
        config: config(),
        ingress: gw,
        services: [
          {
            host: 'curs:8083',
            service: 'curs',
            upstream: 'curs:8083',
            upstreamHost: 'curs',
            upstreamPort: 8083,
            publicPort: 8083,
            listenPort: 8083,
          },
        ],
        candidates: [
          { group: 'magiclib', service: 'magiclib', publicPort: 1337, containerPort: 1337, upstream: 'magiclib:1337', source: 'compose' },
          { group: 'curs', service: 'curs', publicPort: 8083, containerPort: 80, upstream: 'curs:80', source: 'compose' },
        ],
      });
      const candidate = topo.nodes.find((n) => n.kind === 'candidate');
      assert.equal(candidate?.label, 'magiclib:1337');
      assert.equal(candidate?.layer, 2);
      assert.ok(topo.edges.some((e) => e.to === candidate?.id && e.label === 'свободен'));
      // A candidate whose port is occupied by a live listener is not repeated.
      assert.equal(topo.nodes.filter((n) => n.id.includes('svc:curs')).length, 0);
    } finally {
      await gw.close();
    }
  });

  it('round-trips through the YAML writer and reader unchanged', async () => {
    const gw = new Gateway(config(), { rateLimitPerSecond: 100, rateBurst: 100 });
    await gw.listen();
    try {
      const topo = buildTopology({
        config: config(),
        ingress: gw,
        services: [],
        now: new Date('2026-01-01T00:00:00.000Z'),
      });
      const yaml = topologyToYaml(topo);
      const back = parseTopologyYaml(yaml);
      assert.deepEqual(back, topo);
      // And the YAML is human-legible block style, not a JSON blob.
      assert.ok(yaml.startsWith('version: 1\n'));
      assert.ok(yaml.includes('nodes:\n  - id: "actor:admin"'));
    } finally {
      await gw.close();
    }
  });

  it('emits every string quoted, so a colon in a value is never a key', () => {
    const yaml = toYaml({ id: 'a:b', n: 3, ok: true, empty: null });
    assert.deepEqual(yaml, ['id: "a:b"', 'n: 3', 'ok: true', 'empty: null']);
  });
});
