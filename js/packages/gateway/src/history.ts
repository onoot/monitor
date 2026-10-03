/**
 * The record of who knocked, kept whether or not they were let in.
 *
 * Since the proxy forwards strangers, the history is only complete if every
 * request is accounted for: the address is known the moment the kernel accepts
 * the socket, long before any classification happens, so a caller that will be
 * forwarded or attacked is still a name the operator can act on. The candidates
 * list exists for addresses the operator has not yet placed.
 *
 * The buffer is bounded. A flood is precisely the case where this grows fastest,
 * and an unbounded log would turn a detected DDoS into an out-of-memory kill,
 * which would look exactly like the outage we were trying to prevent. Past the
 * cap the oldest entries are dropped and a counter records how many were lost, so
 * a truncated history is visible rather than silent.
 */

import type { Artifact } from '@ad/engine';

import type { Principal } from './network.js';

export type Outcome = 'forwarded' | 'blocked' | 'throttled' | 'refused' | 'error';

export interface Attempt {
  /** Opaque id, stable for the life of the in-memory entry; the UI opens a
   * detail popup by it. */
  id: string;
  at: string;
  ip: string;
  principal: Principal;
  team: string | null;
  /** True when the address belongs to the operator's own team. */
  own?: boolean;
  host: string | null;
  method: string;
  /** Path plus query, with the query left intact for the analyser. */
  target: string;
  outcome: Outcome;
  /** Rule id, or the refusal reason. */
  reason: string;
  status: number | null;
  bytes: number;
  durationMs: number;
  /** Which rule ids fired, so the UI can explain a block. */
  rules: string[];
  /** Route service label (`checker` for the grader), for the UI folders. */
  service?: string;
  /** Flag-shaped strings found anywhere in the request. */
  flags?: string[];
  /** Hashes and encodings found in the request. */
  artifacts?: Artifact[];
  /** Request headers, when the capture scan kept them. */
  headers?: Record<string, string>;
  /** Request body up to the store cap; the analyser saw the whole of it. */
  body?: string;
}

export interface HistoryOptions {
  /** Entries kept in memory. */
  capacity?: number;
  /** Retained per-IP rolling counters, for rate and behaviour analysis. */
  trackerCapacity?: number;
}

export interface TrackerSnapshot {
  ip: string;
  principal: Principal;
  team: string | null;
  firstSeen: number;
  lastSeen: number;
  requests: number;
  /** Milliseconds spent on arithmetic that could show as CPU pressure. */
  bytesSent: number;
  statuses: Record<string, number>;
  routes: Record<string, number>;
  /** Per-second request timestamps, capped, for the rate rule. */
  recent: number[];
  blocked: number;
  refused: number;
}

const DEFAULT_CAPACITY = 5000;
const DEFAULT_TRACKER_CAPACITY = 2000;
/** Ten minutes of timestamps per IP is enough to judge a flood. */
const RECENT_WINDOW_MS = 10 * 60 * 1000;
const RECENT_MAX = 4096;

class Tracker {
  readonly ip: string;
  principal: Principal = 'unknown';
  team: string | null = null;
  firstSeen = 0;
  lastSeen = 0;
  requests = 0;
  bytesSent = 0;
  blocked = 0;
  refused = 0;
  readonly statuses = new Map<number, number>();
  readonly routes = new Map<string, number>();
  recent: number[] = [];

  /** Arrival timestamps, counted before the request is judged. */
  arrivals: number[] = [];

  constructor(ip: string) {
    this.ip = ip;
  }

  touch(now: number): void {
    if (this.firstSeen === 0) this.firstSeen = now;
    this.lastSeen = now;
  }

  /**
   * Count an arrival, before the request is analysed or forwarded.
   *
   * Rate has to be judged on arrival, not on completion. A client that opens many
   * connections at once has all of them in flight before the first one finishes,
   * so counting finished requests lets a burst through in full -- which is
   * exactly the case a denial-of-service rule exists to stop.
   */
  arrive(now: number): void {
    this.arrivals.push(now);
    const cutoff = now - RECENT_WINDOW_MS;
    let drop = 0;
    while (drop < this.arrivals.length && (this.arrivals[drop] as number) < cutoff) drop += 1;
    if (drop > 0) this.arrivals = this.arrivals.slice(drop);
    if (this.arrivals.length > RECENT_MAX) {
      this.arrivals = this.arrivals.slice(this.arrivals.length - RECENT_MAX);
    }
    this.touch(now);
  }

  /** Sustained and peak arrival rate, including the request being judged. */
  arrivalRates(now: number): { perSecond: number; peakPerSecond: number } {
    const buckets = new Map<number, number>();
    for (const stamp of this.arrivals) {
      const second = Math.floor(stamp / 1000);
      buckets.set(second, (buckets.get(second) ?? 0) + 1);
    }
    let peak = 0;
    for (const count of buckets.values()) if (count > peak) peak = count;
    const first = this.arrivals[0] ?? now;
    const windowSeconds = Math.max(1, (now - first) / 1000);
    return { perSecond: this.arrivals.length / windowSeconds, peakPerSecond: peak };
  }

  record(route: string, status: number | null, bytes: number, now: number): void {
    this.requests += 1;
    this.bytesSent += bytes;
    if (status !== null) this.statuses.set(status, (this.statuses.get(status) ?? 0) + 1);
    this.routes.set(route, (this.routes.get(route) ?? 0) + 1);
    this.recent.push(now);
    const cutoff = now - RECENT_WINDOW_MS;
    // Timestamps arrive in order, so dropping from the front is enough.
    let drop = 0;
    while (drop < this.recent.length && (this.recent[drop] as number) < cutoff) drop += 1;
    if (drop > 0) this.recent = this.recent.slice(drop);
    if (this.recent.length > RECENT_MAX) {
      this.recent = this.recent.slice(this.recent.length - RECENT_MAX);
    }
  }

  /** Requests per second over the retained window, and the peak second. */
  rates(now: number): { perSecond: number; peakPerSecond: number } {
    const buckets = new Map<number, number>();
    for (const stamp of this.recent) {
      const second = Math.floor(stamp / 1000);
      buckets.set(second, (buckets.get(second) ?? 0) + 1);
    }
    let peak = 0;
    for (const count of buckets.values()) if (count > peak) peak = count;
    const windowSeconds = Math.max(1, (now - this.firstSeen) / 1000);
    return { perSecond: this.requests / windowSeconds, peakPerSecond: peak };
  }

  snapshot(): TrackerSnapshot {
    const statuses: Record<string, number> = {};
    for (const [status, count] of this.statuses) statuses[String(status)] = count;
    const routes: Record<string, number> = {};
    for (const [route, count] of this.routes) routes[route] = count;
    return {
      ip: this.ip,
      principal: this.principal,
      team: this.team,
      firstSeen: this.firstSeen,
      lastSeen: this.lastSeen,
      requests: this.requests,
      bytesSent: this.bytesSent,
      statuses,
      routes,
      recent: [...this.recent],
      blocked: this.blocked,
      refused: this.refused,
    };
  }
}

export class RequestHistory {
  private readonly capacity: number;
  private readonly trackerCapacity: number;
  private entries: Attempt[] = [];
  /** Addresses whose oldest entries were evicted, for the operator. */
  dropped = 0;
  private trackers = new Map<string, Tracker>();
  private trackersDropped = 0;

  constructor(options: HistoryOptions = {}) {
    this.capacity = options.capacity ?? DEFAULT_CAPACITY;
    this.trackerCapacity = options.trackerCapacity ?? DEFAULT_TRACKER_CAPACITY;
  }

  get size(): number {
    return this.entries.length;
  }

  get trackedIps(): number {
    return this.trackers.size;
  }

  get trackersEvicted(): number {
    return this.trackersDropped;
  }

  /** Forget every captured attempt and per-address counter. */
  clear(): void {
    this.entries = [];
    this.trackers.clear();
    this.dropped = 0;
    this.trackersDropped = 0;
  }

  /** The tracker for an address, created on first sight. */
  private ensureTracker(ip: string): Tracker {
    let tracker = this.trackers.get(ip);
    if (tracker === undefined) {
      if (this.trackers.size >= this.trackerCapacity) {
        this.evictOldestTracker();
      }
      tracker = new Tracker(ip);
      this.trackers.set(ip, tracker);
    }
    return tracker;
  }

  add(attempt: Attempt): void {
    this.entries.push(attempt);
    if (this.entries.length > this.capacity) {
      const excess = this.entries.length - this.capacity;
      this.entries = this.entries.slice(excess);
      this.dropped += excess;
    }
    const now = Date.parse(attempt.at);
    const tracker = this.ensureTracker(attempt.ip);
    tracker.principal = attempt.principal;
    tracker.team = attempt.team;
    tracker.touch(Number.isNaN(now) ? Date.now() : now);
    tracker.record(
      `${attempt.method} ${attempt.target}`,
      attempt.status,
      attempt.bytes,
      Number.isNaN(now) ? Date.now() : now,
    );
    if (attempt.outcome === 'blocked') tracker.blocked += 1;
    // Throttling is counted with blocked requests: for a behavioural profile the
    // two are the same signal, "this client is being held back", and splitting
    // them would hide a sustained burst behind a separate counter.
    if (attempt.outcome === 'throttled') tracker.blocked += 1;
    if (attempt.outcome === 'refused') tracker.refused += 1;
  }

  private evictOldestTracker(): void {
    let oldestIp: string | null = null;
    let oldest = Infinity;
    for (const [ip, tracker] of this.trackers) {
      if (tracker.lastSeen < oldest) {
        oldest = tracker.lastSeen;
        oldestIp = ip;
      }
    }
    if (oldestIp !== null) {
      this.trackers.delete(oldestIp);
      this.trackersDropped += 1;
    }
  }

  trackerFor(ip: string): TrackerSnapshot | undefined {
    return this.trackers.get(ip)?.snapshot();
  }

  /**
   * Sustained and peak rate for an address, for the denial-of-service rule.
   *
   * Counted from arrivals, so a burst of concurrent connections is visible while
   * it is happening rather than once it has finished.
   */
  ratesFor(ip: string, now: number): { perSecond: number; peakPerSecond: number } {
    const tracker = this.trackers.get(ip);
    if (tracker === undefined) return { perSecond: 0, peakPerSecond: 0 };
    return tracker.arrivalRates(now);
  }

  /**
   * Count a connection as having arrived, before it is judged.
   *
   * The principal and team are passed in so a tracker is not attributed to
   * `unknown` by a request that later turns out to belong to a team.
   */
  noteArrival(ip: string, now: number, principal: Principal, team: string | null): void {
    const tracker = this.ensureTracker(ip);
    tracker.principal = principal;
    tracker.team = team;
    tracker.arrive(now);
  }

  recent(limit = 200): Attempt[] {
    return this.entries.slice(-limit).reverse();
  }

  /** Most recent attempts matching a filter, newest first. */
  filter(
    spec: { service?: string; principal?: string; outcome?: string; team?: string; own?: boolean },
    limit = 200,
  ): Attempt[] {
    const out: Attempt[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const entry = this.entries[i];
      if (entry === undefined) continue;
      if (spec.service !== undefined && entry.service !== spec.service) continue;
      if (spec.principal !== undefined && entry.principal !== spec.principal) continue;
      if (spec.outcome !== undefined && entry.outcome !== spec.outcome) continue;
      if (spec.team !== undefined && entry.team !== spec.team) continue;
      // `own` is stored only when true, so an absent flag means "not our team".
      if (spec.own !== undefined && (entry.own === true) !== spec.own) continue;
      out.push(entry);
    }
    return out;
  }

  /** Recent attempts of one principal, most recent first. */
  principalRecent(principal: Principal, limit = 200): Attempt[] {
    const out: Attempt[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const entry = this.entries[i];
      if (entry !== undefined && entry.principal === principal) out.push(entry);
    }
    return out;
  }

  /** Recent attempts of one service label (or the `checker` folder). */
  serviceRecent(service: string, limit = 200): Attempt[] {
    const out: Attempt[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const entry = this.entries[i];
      if (entry !== undefined && entry.service === service) out.push(entry);
    }
    return out;
  }

  /** Recent attempts that carried a flag, with the flag value up front. */
  recentFlags(limit = 200): {
    id: string;
    value: string;
    at: string;
    ip: string;
    principal: Principal;
    team: string | null;
    service: string | undefined;
    method: string;
    host: string | null;
    target: string;
    outcome: Outcome;
    status: number | null;
    durationMs: number;
    rules: string[];
  }[] {
    const out: { id: string; value: string; at: string; ip: string; principal: Principal; team: string | null; service: string | undefined; method: string; host: string | null; target: string; outcome: Outcome; status: number | null; durationMs: number; rules: string[] }[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const entry = this.entries[i];
      if (entry === undefined) continue;
      for (const value of entry.flags ?? []) {
        out.push({
          id: entry.id,
          value,
          at: entry.at,
          ip: entry.ip,
          principal: entry.principal,
          team: entry.team,
          service: entry.service,
          method: entry.method,
          host: entry.host,
          target: entry.target,
          outcome: entry.outcome,
          status: entry.status,
          durationMs: entry.durationMs,
          rules: entry.rules,
        });
      }
    }
    return out;
  }

  /** The full in-memory record for a detail popup, or null once evicted. */
  attemptById(id: string): Attempt | null {
    for (let i = this.entries.length - 1; i >= 0; i -= 1) {
      const entry = this.entries[i];
      if (entry !== undefined && entry.id === id) return entry;
    }
    return null;
  }

  /** Recent attempts that carried an artifact, with the artifact up front. */
  recentArtifacts(limit = 200): {
    type: Artifact['type'];
    value: string;
    at: string;
    ip: string;
    principal: Principal;
    team: string | null;
    service: string | undefined;
    method: string;
    host: string | null;
    target: string;
    outcome: Outcome;
  }[] {
    const out: {
      type: Artifact['type'];
      value: string;
      at: string;
      ip: string;
      principal: Principal;
      team: string | null;
      service: string | undefined;
      method: string;
      host: string | null;
      target: string;
      outcome: Outcome;
    }[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const entry = this.entries[i];
      if (entry === undefined) continue;
      for (const artifact of entry.artifacts ?? []) {
        out.push({
          type: artifact.type,
          value: artifact.value,
          at: entry.at,
          ip: entry.ip,
          principal: entry.principal,
          team: entry.team,
          service: entry.service,
          method: entry.method,
          host: entry.host,
          target: entry.target,
          outcome: entry.outcome,
        });
      }
    }
    return out;
  }

  stats(): {
    attempts: number;
    dropped: number;
    perPrincipal: Record<string, number>;
    perOutcome: Record<string, number>;
    perService: Record<string, number>;
    perTeam: Record<string, number>;
  } {
    const perPrincipal: Record<string, number> = {};
    const perOutcome: Record<string, number> = {};
    const perService: Record<string, number> = {};
    const perTeam: Record<string, number> = {};
    for (const entry of this.entries) {
      perPrincipal[entry.principal] = (perPrincipal[entry.principal] ?? 0) + 1;
      perOutcome[entry.outcome] = (perOutcome[entry.outcome] ?? 0) + 1;
      const service = entry.service ?? 'other';
      perService[service] = (perService[service] ?? 0) + 1;
      if (entry.team !== null) perTeam[entry.team] = (perTeam[entry.team] ?? 0) + 1;
    }
    return {
      attempts: this.entries.length,
      dropped: this.dropped,
      perPrincipal,
      perOutcome,
      perService,
      perTeam,
    };
  }

  /**
   * Addresses that knocked and matched nothing in the allowlist.
   *
   * This is the admin UI's candidate list. They are unlisted by construction, so
   * they are exactly the addresses an operator has to make a decision about.
   */
  unknownCandidates(limit = 50): { ip: string; attempts: number; lastSeen: string }[] {
    const out: { ip: string; attempts: number; lastSeen: string }[] = [];
    for (let i = this.entries.length - 1; i >= 0 && out.length < limit; i -= 1) {
      const entry = this.entries[i];
      if (entry === undefined || entry.principal !== 'unknown') continue;
      if (out.some((c) => c.ip === entry.ip)) continue;
      const tracker = this.trackers.get(entry.ip);
      out.push({
        ip: entry.ip,
        attempts: tracker?.requests ?? 1,
        lastSeen: entry.at,
      });
    }
    return out;
  }

  /** Per-IP trackers, most recently active first. */
  byIp(limit = 100): TrackerSnapshot[] {
    return [...this.trackers.values()]
      .sort((a, b) => b.lastSeen - a.lastSeen)
      .slice(0, limit)
      .map((t) => t.snapshot());
  }
}
