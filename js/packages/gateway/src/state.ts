/**
 * The operator's own additions, kept out of the hand-edited gateway.json.
 *
 * Two files under the data directory, written by the analytics API and read at
 * boot so a restart keeps the labels and the extra services:
 *
 * - `labels.json`: addresses the operator marked in the UI (checker, admin, or a
 *   team). They overlay the config ranges and decide classification live.
 * - `services.json`: extra public ports to route, from the UI's service list.
 *
 * Writes are atomic (tmp file + rename) and read as a whole, so a crash between
 * loading the two files is the only way to split them, and both are versioned by
 * whole-object replacement rather than in-place mutation.
 */

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';

import type { Principal } from './network.js';

export interface LabelOverride {
  cidr: string;
  kind: Principal;
  /** Team label for `team` entries, so the UI can attribute requests. */
  team?: string;
  /** Marks the operator's own team range (only meaningful for `team`). */
  own?: boolean;
  note?: string;
}

export interface ServiceEntry {
  /** The public port clients keep dialling. */
  port: number;
  service: string;
  /** `host:port`; defaults to the public port on the loopback. */
  upstream?: string;
}

function readJson<T>(dirPath: string, name: string, fallback: T): T {
  try {
    return JSON.parse(readFileSync(path.join(dirPath, name), 'utf8')) as T;
  } catch {
    return fallback;
  }
}

function writeJson(dirPath: string, name: string, value: unknown): void {
  mkdirSync(dirPath, { recursive: true });
  const target = path.join(dirPath, name);
  writeFileSync(`${target}.tmp`, JSON.stringify(value, null, 2), 'utf8');
  renameSync(`${target}.tmp`, target);
}

export function loadLabels(dirPath: string): LabelOverride[] {
  const raw = readJson<{ overrides?: LabelOverride[] } | undefined>(dirPath, 'labels.json', undefined);
  if (raw === undefined || !Array.isArray(raw.overrides)) return [];
  return raw.overrides;
}

export function saveLabels(dirPath: string, overrides: LabelOverride[]): void {
  writeJson(dirPath, 'labels.json', { overrides });
}

export function loadServices(dirPath: string): ServiceEntry[] {
  const raw = readJson<{ services?: ServiceEntry[] } | undefined>(dirPath, 'services.json', undefined);
  if (raw === undefined || !Array.isArray(raw.services)) return [];
  return raw.services;
}

export function saveServices(dirPath: string, services: ServiceEntry[]): void {
  writeJson(dirPath, 'services.json', { services });
}