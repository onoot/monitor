import { readFileSync, writeFileSync } from 'node:fs';
import nodePath from 'node:path';

/**
 * The operator's manual overlay on the generated path graph. The graph itself
 * stays deterministic (see topology.ts); this file only records what a human
 * changed with the mouse: where they dragged a node, which links they cut, and
 * which links they drew. Keeping the two apart is what lets the generated
 * graph.yaml be regenerated at any time without losing the layout.
 */
export interface GraphPoint {
  x: number;
  y: number;
}

export interface GraphLayoutEdge {
  from: string;
  to: string;
  label?: string;
}

export interface GraphLayout {
  version: 1;
  positions: Record<string, GraphPoint>;
  removed: string[];
  added: GraphLayoutEdge[];
}

/** A link's identity: the same pair of nodes may carry several labelled links. */
export function edgeKey(from: string, to: string, label?: string): string {
  return JSON.stringify([from, to, label === undefined ? null : label]);
}

export function emptyGraphLayout(): GraphLayout {
  return { version: 1, positions: {}, removed: [], added: [] };
}

export function graphLayoutPath(dir: string): string {
  return nodePath.join(dir, 'graph.layout.json');
}

const MAX_ENTRIES = 20_000;
const MAX_ID = 256;

function asId(value: unknown, what: string): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ID) {
    throw new Error(`${what} must be a non-empty string of at most ${MAX_ID} characters`);
  }
  return value;
}

/**
 * Turn untrusted input into a canonical overlay. Unknown fields are dropped and
 * duplicates collapsed so a hand-edited file cannot smuggle anything odd into
 * the UI. Throws with a human-readable reason; the endpoint maps it to HTTP 400.
 */
export function normalizeGraphLayout(input: unknown): GraphLayout {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new Error('layout must be a JSON object');
  }
  const raw = input as { positions?: unknown; removed?: unknown; added?: unknown };

  const positions: Record<string, GraphPoint> = {};
  if (raw.positions !== undefined) {
    if (typeof raw.positions !== 'object' || raw.positions === null || Array.isArray(raw.positions)) {
      throw new Error('positions must be a JSON object');
    }
    const entries = Object.entries(raw.positions as Record<string, unknown>);
    if (entries.length > MAX_ENTRIES) throw new Error('too many positions');
    for (const [id, value] of entries) {
      asId(id, 'position id');
      if (typeof value !== 'object' || value === null) throw new Error(`position ${id} must be an object`);
      const point = value as { x?: unknown; y?: unknown };
      if (typeof point.x !== 'number' || !Number.isFinite(point.x) || typeof point.y !== 'number' || !Number.isFinite(point.y)) {
        throw new Error(`position ${id} must have finite x and y`);
      }
      positions[id] = { x: point.x, y: point.y };
    }
  }

  const removed: string[] = [];
  if (raw.removed !== undefined) {
    if (!Array.isArray(raw.removed)) throw new Error('removed must be an array');
    if (raw.removed.length > MAX_ENTRIES) throw new Error('too many removed links');
    const seen = new Set<string>();
    for (const key of raw.removed) {
      if (typeof key !== 'string' || key.length === 0 || key.length > MAX_ID * 3) {
        throw new Error('every removed link must be a non-empty string');
      }
      if (seen.has(key)) continue;
      seen.add(key);
      removed.push(key);
    }
  }

  const added: GraphLayoutEdge[] = [];
  if (raw.added !== undefined) {
    if (!Array.isArray(raw.added)) throw new Error('added must be an array');
    if (raw.added.length > MAX_ENTRIES) throw new Error('too many added links');
    const seen = new Set<string>();
    for (const value of raw.added) {
      if (typeof value !== 'object' || value === null) throw new Error('every added link must be an object');
      const link = value as { from?: unknown; to?: unknown; label?: unknown };
      const from = asId(link.from, 'added link from');
      const to = asId(link.to, 'added link to');
      if (link.label !== undefined && (typeof link.label !== 'string' || link.label.length > MAX_ID)) {
        throw new Error('added link label must be a string');
      }
      const entry: GraphLayoutEdge = link.label === undefined ? { from, to } : { from, to, label: link.label };
      const key = edgeKey(from, to, entry.label);
      if (seen.has(key)) continue;
      seen.add(key);
      added.push(entry);
    }
  }

  return { version: 1, positions, removed, added };
}

export function loadGraphLayout(dir: string): GraphLayout {
  try {
    return normalizeGraphLayout(JSON.parse(readFileSync(graphLayoutPath(dir), 'utf8')));
  } catch {
    return emptyGraphLayout();
  }
}

export function saveGraphLayout(dir: string, layout: GraphLayout): void {
  writeFileSync(graphLayoutPath(dir), `${JSON.stringify(layout, null, 2)}\n`, 'utf8');
}
