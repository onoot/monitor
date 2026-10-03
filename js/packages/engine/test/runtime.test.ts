/**
 * Runtime actor attribution must stay consistent with the derived aggregates.
 *
 * Mirrors tests/test_runtime.py in the Python tree.
 */

import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createRuntimeReport, loadRequests, normaliseGinTs } from '../src/requests.js';
import type { RuntimeReport } from '../src/requests.js';
import { loadConfig, makeNetworkForTest } from '../src/config.js';
import type { Config } from '../src/config.js';
import { ROOT } from './regression.test.js';

const RECORDS = [
  {
    client_ip: '10.0.0.5',
    method: 'POST',
    path: '/login',
    body: { username: 'alice', password: 'hunter2' },
    response: '{}',
  },
  {
    client_ip: '10.0.0.5',
    method: 'GET',
    path: '/startscreen',
    body: '',
    response: 'alt{aaaaaaaaaaaaaaaa}',
  },
  {
    client_ip: '203.0.113.7',
    method: 'PUT',
    path: '/flags',
    body: { flag: 'alt{bbbbbbbbbbbbbbbb}' },
    response: '{}',
  },
];

/** The Python test rebuilds the config with new networks; do the same. */
function cfgWithNetworks(): Config {
  const cfg = loadConfig(path.join(ROOT, 'configs', 'magiclib.json'));
  const teamNetworks = [makeNetworkForTest('10.0.0.0/8')];
  const checkerNetworks = [makeNetworkForTest('203.0.113.0/24')];
  return {
    ...cfg,
    teamNetworks,
    checkerNetworks,
    classifyIp(ip: string): 'checker' | 'team' | 'unknown' {
      for (const net of teamNetworks) if (net.contains(ip)) return 'team';
      for (const net of checkerNetworks) if (net.contains(ip)) return 'checker';
      return 'unknown';
    },
  };
}

let dir: string;
let cfg: Config;
let report: RuntimeReport;

beforeEach(() => {
  cfg = cfgWithNetworks();
  dir = mkdtempSync(path.join(tmpdir(), 'ad-runtime-'));
  const file = path.join(dir, 'requests.json');
  writeFileSync(file, JSON.stringify(RECORDS), 'utf8');
  report = loadRequests([file], cfg);
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('runtime attribution', () => {
  it('every record is parsed', () => {
    expect(report.requests).toHaveLength(3);
  });

  it('classification assigns actors by network', () => {
    const applied = report.classifyUnknown(cfg);
    expect(applied['10.0.0.5']).toBe('team');
    expect(applied['203.0.113.7']).toBe('checker');
  });

  it('profiles are recomputed after classification', () => {
    report.classifyUnknown(cfg);
    const actors = [...report.profiles.keys()];
    expect(actors).toContain('team');
    expect(actors).toContain('checker');
    expect(actors).not.toContain('unknown');
    expect(report.profiles.get('checker')?.requests).toBe(1);
  });

  it('flag reads land on the team, not the checker', () => {
    report.classifyUnknown(cfg);
    expect(report.profiles.get('team')?.flagReads).toBe(1);
    expect(report.profiles.get('checker')?.flagReads).toBe(0);
  });

  it('checker PUT counts as a write, not a read', () => {
    report.classifyUnknown(cfg);
    expect(report.profiles.get('checker')?.flagWrites).toBe(1);
    expect(report.profiles.get('team')?.flagWrites).toBe(0);
  });

  it('route matrix separates reads from writes', () => {
    report.classifyUnknown(cfg);
    const byRoute = new Map(
      report.routeMatrix().map((entry) => [entry.route, entry.actors]),
    );
    const putFlags = byRoute.get('PUT /flags')?.checker;
    expect(putFlags?.flag_writes).toBe(1);
    expect(putFlags?.flag_reads).toBe(0);
    expect(byRoute.get('GET /startscreen')?.team?.flag_reads).toBe(1);
  });

  it('route matrix reflects classification', () => {
    report.classifyUnknown(cfg);
    const actors = new Map(
      report.routeMatrix().map((entry) => [
        entry.route,
        Object.keys(entry.actors).sort(),
      ]),
    );
    expect(actors.get('POST /login')).toEqual(['team']);
    expect(actors.get('PUT /flags')).toEqual(['checker']);
  });

  it('classification is idempotent', () => {
    report.classifyUnknown(cfg);
    const first = [...report.profiles.keys()].sort();
    const secondApplied = report.classifyUnknown(cfg);
    expect(secondApplied).toEqual({});
    expect([...report.profiles.keys()].sort()).toEqual(first);
  });

  it('unclassified IP stays unknown and unpoisonable', () => {
    const first = report.requests[0];
    if (first) first.clientIp = '198.51.100.9';
    const applied = report.classifyUnknown(cfg);
    expect(applied['198.51.100.9']).toBe('unknown');
    expect([...report.profiles.keys()]).toContain('unknown');
  });
});

describe('empty report', () => {
  it('starts with no profiles and no cross-actor notes', () => {
    const empty = createRuntimeReport();
    expect(empty.profiles.size).toBe(0);
    expect(empty.crossActorFindings).toEqual([]);
    expect(empty.routeMatrix()).toEqual([]);
  });
});

/**
 * Real lines from `docker logs curs-curs-1`, captured from the Curs service.
 * Before gin was a supported format these parsed to zero records, leaving the
 * whole runtime section of a Go service empty.
 */
const GIN_LOG = [
  '[GIN] 2026/10/02 - 04:28:12 | 200 | 365.216\u00b5s |      172.23.0.1 | GET      "/"',
  '[GIN] 2026/10/02 - 04:28:12 | 303 |   38.502\u00b5s |      172.23.0.1 | GET      "/dashboard"',
  '[GIN] 2026/10/02 - 04:28:20 | 409 |     52.55ms |      172.23.0.1 | POST     "/user/register"',
  '[GIN] 2026/10/02 - 04:28:21 | 401 |    47.69ms |      172.23.0.1 | POST     "/user/login"',
  '[GIN] 2026/10/02 - 04:28:36 | 200 |      5.06ms | 172.23.0.1 | POST     "/user/login?next=%2Fadmin"',
  '',
].join('\n');

describe('gin access log', () => {
  let dir: string;
  let ginReport: RuntimeReport;

  beforeEach(() => {
    const cfg = cfgWithNetworks();
    dir = mkdtempSync(path.join(tmpdir(), 'ad-gin-'));
    const file = path.join(dir, 'curs-gin.log');
    writeFileSync(file, GIN_LOG, 'utf8');
    ginReport = loadRequests([file], cfg);
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it('every gin line becomes a request', () => {
    expect(ginReport.requests).toHaveLength(5);
    expect(ginReport.parserNotes).toEqual([]);
  });

  it('fields land in the right columns', () => {
    const first = ginReport.requests[0];
    expect(first?.clientIp).toBe('172.23.0.1');
    expect(first?.method).toBe('GET');
    expect(first?.path).toBe('/');
    expect(first?.status).toBe(200);
    expect(first?.headers['user-agent']).toBe('');
  });

  it('status and method survive multibyte latency', () => {
    const conflict = ginReport.requests[2];
    expect(conflict?.status).toBe(409);
    expect(conflict?.method).toBe('POST');
    expect(conflict?.path).toBe('/user/register');
    expect(ginReport.requests[3]?.status).toBe(401);
  });

  it('query is split off the path', () => {
    const login = ginReport.requests[4];
    expect(login?.path).toBe('/user/login');
    expect(login?.query).toBe('next=%2Fadmin');
  });

  it('gin timestamp is normalised to iso', () => {
    expect(ginReport.requests[0]?.ts).toBe('2026-10-02T04:28:12');
    expect(normaliseGinTs('2026/10/02 - 04:28:12')).toBe('2026-10-02T04:28:12');
  });

  it('bad timestamp is left alone not invented', () => {
    expect(normaliseGinTs('not a timestamp')).toBe('not a timestamp');
  });

  it('gin open bracket does not trigger a json note', () => {
    expect(ginReport.parserNotes.join(' ')).not.toContain('not valid JSON');
  });

  it('gin lines are attributed like any other capture', () => {
    const first = ginReport.requests[0];
    if (first) first.clientIp = '10.0.0.5';
    const applied = ginReport.classifyUnknown(cfgWithNetworks());
    expect(applied['10.0.0.5']).toBe('team');
    expect(ginReport.profiles.get('team')?.requests).toBe(1);
  });
});
