/**
 * Durable capture: every attempt is appended as JSON Lines, one file per
 * service per day, under the data directory.
 *
 * Layout:
 *
 *   data/curs/2026-10-02.jsonl      - team/admin/unknown traffic for "curs"
 *   data/checker/2026-10-02.jsonl   - checker traffic, its own subfolder
 *   data/other/2026-10-02.jsonl     - requests that matched no route
 *
 * The checker gets a separate folder so its data can be told apart without
 * reading every row, and the UI mirrors that: the checker tab reads exactly
 * this principal. A folder per service keeps one day of one service readable by
 * hand, which is the whole point of file-form storage instead of a database.
 *
 * The store is a write-behind queue, not a synchronous write per request. A
 * flood is precisely when the store is busiest, and forcing every request onto
 * a synchronous disk write would turn the captured DDoS into a self-inflicted
 * slow-down of the proxy itself. The queue is bounded: past the cap old lines
 * are dropped and counted, and a failed append only bumps a counter -- a broken
 * disk must never take the gateway down with it.
 */

import { appendFile, mkdir } from 'node:fs/promises';
import path from 'node:path';

import type { Artifact } from '@ad/engine';

export interface StoredCapture {
  at: string;
  ip: string;
  principal: string;
  team: string | null;
  /** True when the address belongs to the operator's own team. */
  own?: boolean;
  /** `checker`, the route's service label, or `other` when no route matched. */
  service: string;
  host: string | null;
  method: string;
  target: string;
  outcome: string;
  reason: string;
  status: number | null;
  bytes: number;
  durationMs: number;
  rules: string[];
  flags: string[];
  artifacts: Artifact[];
  headers: Record<string, string>;
  /** Body up to a cap; the full body was already analysed in memory. */
  body: string;
}

/** How many stored lines may wait before the oldest are dropped. */
const MAX_QUEUED = 4000;
/** Captured body is truncated at this many characters per request. */
export const BODY_STORE_MAX = 4096;

function dayOf(at: string): string {
  return at.slice(0, 10);
}

export interface FileStoreStats {
  dir: string;
  queued: number;
  written: number;
  failures: number;
  dropped: number;
  lastError: string | null;
}

export class AttemptFileStore {
  private readonly dir: string;
  private pending: { key: string; date: string; line: string }[] = [];
  private readonly createdDirs = new Set<string>();
  private draining = false;
  written = 0;
  failures = 0;
  droppedDeferred = 0;
  lastError: string | null = null;

  constructor(dataDir: string) {
    this.dir = dataDir;
  }

  get baseDir(): string {
    return this.dir;
  }

  /**
   * Forget the queue and the directory cache after the capture files were
   * removed from under the store. Without dropping `createdDirs` a later write
   * would skip the mkdir and append into a folder that no longer exists.
   */
  reset(): void {
    this.pending = [];
    this.createdDirs.clear();
    this.written = 0;
    this.failures = 0;
    this.droppedDeferred = 0;
    this.lastError = null;
  }

  /** Enqueue a line for the subfolder its `service` names. */
  append(record: StoredCapture): void {
    const key = record.service || 'other';
    const date = dayOf(record.at) || 'unknown';
    this.pending.push({ key, date, line: JSON.stringify(record) });
    if (this.pending.length > MAX_QUEUED) {
      const excess = this.pending.length - MAX_QUEUED;
      this.pending = this.pending.slice(excess);
      this.droppedDeferred += excess;
    }
    if (!this.draining) {
      this.draining = true;
      setImmediate(() => void this.drain());
    }
  }

  /** Flush whatever is queued. Safe to call at shutdown. */
  async flush(): Promise<void> {
    while (this.pending.length > 0) {
      const batch = this.pending;
      this.pending = [];
      for (const item of batch) {
        await this.write(item).catch((err: unknown) => {
          this.failures += 1;
          this.lastError = (err as Error).message;
        });
      }
    }
  }

  stats(): FileStoreStats {
    return {
      dir: this.dir,
      queued: this.pending.length,
      written: this.written,
      failures: this.failures,
      dropped: this.droppedDeferred,
      lastError: this.lastError,
    };
  }

  private async drain(): Promise<void> {
    try {
      if (this.pending.length > 0) {
        const batch = this.pending;
        this.pending = [];
        for (const item of batch) {
          await this.write(item).catch((err: unknown) => {
            this.failures += 1;
            this.lastError = (err as Error).message;
          });
        }
      }
    } finally {
      this.draining = false;
      // Anything appended while we were writing is drained by the next append.
      if (this.pending.length > 0 && !this.draining) {
        this.draining = true;
        setImmediate(() => void this.drain());
      }
    }
  }

  private async write(item: { key: string; date: string; line: string }): Promise<void> {
    const folder = path.join(this.dir, item.key);
    if (!this.createdDirs.has(folder)) {
      await mkdir(folder, { recursive: true });
      this.createdDirs.add(folder);
    }
    const file = path.join(folder, `${item.date}.jsonl`);
    await appendFile(file, `${item.line}\n`, 'utf8');
    this.written += 1;
  }
}