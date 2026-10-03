import { after, before, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import { AttemptFileStore } from '../src/storage.js';
import type { StoredCapture } from '../src/storage.js';

const dirs: string[] = [];

function capture(service: string, at = '2026-10-02T10:00:00.000Z'): StoredCapture {
  return {
    at,
    ip: '10.0.0.1',
    principal: 'team',
    team: 'stand',
    service,
    host: 'curs.local',
    method: 'GET',
    target: '/',
    outcome: 'forwarded',
    reason: 'curs.local',
    status: 200,
    bytes: 0,
    durationMs: 1,
    rules: [],
    flags: [],
    artifacts: [],
    headers: { host: 'curs.local' },
    body: '',
  };
}

before(() => {
  const dir = mkdtempSync(join(tmpdir(), 'ad-store-'));
  dirs.push(dir);
});

after(() => {
  for (const dir of dirs) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
});

describe('AttemptFileStore', () => {
  it('writes per-service subfolders and flushes the queue', async () => {
    const store = new AttemptFileStore(dirs[0] as string);
    store.append(capture('curs'));
    store.append(capture('magiclib'));
    store.append(capture('AltayCoin'));
    await store.flush();

    const curs = readFileSync(join(dirs[0] as string, 'curs', '2026-10-02.jsonl'), 'utf8');
    const magic = readFileSync(join(dirs[0] as string, 'magiclib', '2026-10-02.jsonl'), 'utf8');
    const altay = readFileSync(join(dirs[0] as string, 'AltayCoin', '2026-10-02.jsonl'), 'utf8');

    assert.equal(curs.trim().split('\n').length, 1);
    assert.equal(JSON.parse(curs).service, 'curs');
    assert.equal(JSON.parse(magic).service, 'magiclib');
    assert.equal(JSON.parse(altay).service, 'AltayCoin');
  });

  it('keeps a checker subfolder when service is checker', async () => {
    const store = new AttemptFileStore(dirs[0] as string);
    store.append(capture('checker'));
    await store.flush();
    const lines = readFileSync(join(dirs[0] as string, 'checker', '2026-10-02.jsonl'), 'utf8');
    assert.equal(JSON.parse(lines).principal, 'team'); // service 'checker' is the folder; principal is whatever network said
  });

  it('rotates by calendar day', async () => {
    const store = new AttemptFileStore(dirs[0] as string);
    store.append(capture('curs', '2026-10-02T10:00:00.000Z'));
    store.append(capture('curs', '2026-10-03T10:00:00.000Z'));
    await store.flush();
    assert.ok(readFileSync(join(dirs[0] as string, 'curs', '2026-10-02.jsonl'), 'utf8').length > 0);
    assert.ok(readFileSync(join(dirs[0] as string, 'curs', '2026-10-03.jsonl'), 'utf8').length > 0);
  });

  it('counts failures instead of throwing on a broken data path', async () => {
    // A directory cannot be created under a file, so `missing/file` traps any
    // mkdir and stands in for a broken disk.
    const trap = join(dirs[0] as string, 'afile');
    writeFileSync(trap, 'x');
    const store = new AttemptFileStore(join(trap, 'sub'));
    store.append(capture('curs'));
    await store.flush();
    const stats = store.stats();
    assert.equal(stats.written, 0);
    assert.equal(stats.failures, 1);
    assert.equal(typeof stats.lastError, 'string');
  });

  it('exposes stats without the data directory existing', () => {
    const store = new AttemptFileStore(join(dirs[0] as string, 'not-made-yet'));
    assert.equal(store.stats().queued, 0);
  });
});