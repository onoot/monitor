import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, it } from 'node:test';

import {
  edgeKey,
  emptyGraphLayout,
  graphLayoutPath,
  loadGraphLayout,
  normalizeGraphLayout,
  saveGraphLayout,
} from '../src/graphLayout.js';

describe('graph layout overlay', () => {
  it('starts empty and uses a distinct identity per labelled link', () => {
    assert.deepEqual(emptyGraphLayout(), { version: 1, positions: {}, removed: [], added: [] });
    assert.notEqual(edgeKey('a', 'b', 'host'), edgeKey('a', 'b', 'порт'));
    assert.equal(edgeKey('a', 'b'), edgeKey('a', 'b', undefined));
    assert.notEqual(edgeKey('a', 'b'), edgeKey('a', 'b', ''));
  });

  it('round-trips through disk', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'ad-layout-'));
    try {
      const layout = normalizeGraphLayout({
        positions: { 'host:curs.local': { x: 120.5, y: 30 }, gateway: { x: 0, y: 0 } },
        removed: [edgeKey('gateway', 'host:curs.local', 'host')],
        added: [{ from: 'gateway', to: 'up:curs:8083', label: 'вручную' }],
      });
      saveGraphLayout(dir, layout);
      assert.deepEqual(loadGraphLayout(dir), layout);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('treats a corrupt or missing file as empty instead of failing', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'ad-layout-'));
    try {
      assert.deepEqual(loadGraphLayout(dir), emptyGraphLayout());
      writeFileSync(graphLayoutPath(dir), '{ not json', 'utf8');
      assert.deepEqual(loadGraphLayout(dir), emptyGraphLayout());
      writeFileSync(graphLayoutPath(dir), JSON.stringify({ positions: { bad: { x: 'no' } } }), 'utf8');
      assert.deepEqual(loadGraphLayout(dir), emptyGraphLayout());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('rejects malformed overlays with a human-readable reason', () => {
    assert.throws(() => normalizeGraphLayout(null), /object/);
    assert.throws(() => normalizeGraphLayout({ positions: [] }), /positions/);
    assert.throws(() => normalizeGraphLayout({ positions: { a: { x: 1 } } }), /finite x and y/);
    assert.throws(() => normalizeGraphLayout({ positions: { a: { x: Infinity, y: 0 } } }), /finite/);
    assert.throws(() => normalizeGraphLayout({ removed: [1] }), /removed link/);
    assert.throws(() => normalizeGraphLayout({ added: [{ from: 'a' }] }), /added link to/);
  });

  it('drops unknown fields and collapses duplicate links', () => {
    const layout = normalizeGraphLayout({
      version: 99,
      extra: 'ignored',
      positions: {},
      removed: ['k', 'k', 'j'],
      added: [
        { from: 'a', to: 'b' },
        { from: 'a', to: 'b' },
        { from: 'a', to: 'b', label: 'x' },
      ],
    });
    assert.deepEqual(layout.removed, ['k', 'j']);
    assert.equal(layout.added.length, 2);
    assert.deepEqual(Object.keys(layout).sort(), ['added', 'positions', 'removed', 'version']);
  });
});
