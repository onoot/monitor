/**
 * Who is on the wire, and what the gateway is allowed to do to them.
 *
 * The precedence here is the load-bearing part. A checker is never blocked and
 * never rate-limited, so its range is matched before any team range: an address
 * that sits in both must resolve to `checker`, otherwise a widening team subnet
 * can swallow the grading client and silently zero every score. This mirrors the
 * invariant the engine already keeps for poisoning, extended to blocking.
 *
 * Nothing in this module trusts a request to describe its own identity. A peer
 * can put any value it likes in a header; the only address that counts is the
 * one the kernel hands us at accept time.
 */

import { parseCidr, parseIp } from '@ad/engine';

/** What the gateway is willing to do with a connection. */
export type Principal = 'checker' | 'team' | 'admin' | 'unknown';

export interface PrincipalSource {
  kind: Principal;
  /** CIDR, or a bare address meaning /32 or /128. */
  cidr: string;
  /** Team label for `team` entries, so requests can be attributed to a team. */
  team?: string;
  /**
   * Marks the operator's own team. It does not change precedence -- an own range
   * is still kind `team` and wins among teams only by the longest prefix -- but
   * it lets the history and the UI separate our traffic from the opponents' when
   * our subnet sits inside a broader range handed to another team.
   */
  own?: boolean;
  note?: string;
}

export interface ResolvedRange {
  kind: Principal;
  cidr: string;
  team?: string;
  own?: boolean;
  note?: string;
  base: bigint;
  bits: number;
  family: 4 | 6;
  contains(ip: string): boolean;
}

/** Serialisable view of a range, for the admin UI and API responses. */
export interface PrincipalDescription {
  kind: Principal;
  cidr: string;
  team?: string;
  own?: boolean;
  note?: string;
  bits: number;
  family: 4 | 6;
}

export interface PrincipalDecision {
  principal: Principal;
  team: string | null;
  /** True when the matched range is the operator's own team. */
  own: boolean;
  /** The range that matched, or null when the address matched nothing. */
  matched: ResolvedRange | null;
  /**
   * True when the address is a checker. The gateway passes these through without
   * consulting the analyser, so a dead analyser can never take grading offline.
   */
  isChecker: boolean;
  /**
   * True when the address must be dropped at the socket with no HTTP response,
   * which is what a client sees as `ERR_CONNECTION_REFUSED`.
   */
  refuse: boolean;
  reason: string;
}

export class NetworkConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NetworkConfigError';
  }
}

function resolveRange(source: PrincipalSource): ResolvedRange {
  const parsed = parseCidr(source.cidr);
  if (parsed === null) {
    throw new NetworkConfigError(
      `cannot parse ${source.kind} address ${JSON.stringify(source.cidr)}`,
    );
  }
  return {
    kind: source.kind,
    cidr: source.cidr,
    ...(source.team === undefined ? {} : { team: source.team }),
    ...(source.own === true ? { own: true } : {}),
    ...(source.note === undefined ? {} : { note: source.note }),
    base: parsed.base,
    bits: parsed.bits,
    family: parsed.family,
    contains(ip: string): boolean {
      const value = parseIp(ip);
      // A malformed address matches nothing. Failing closed here would mean
      // "unparseable" silently became "checker", so it must not.
      if (value === null) return false;
      if ((ip.includes('.') ? 4 : 6) !== parsed.family) return false;
      if (parsed.bits === 0) return true;
      return (value >> BigInt((parsed.family === 4 ? 32 : 128) - parsed.bits)) === parsed.base;
    },
  };
}

/**
 * Build the lookup used on every connection.
 *
 * Order is fixed at construction: checker ranges first, then admin, then teams.
 * A later range never overrides an earlier one, so adding a broad team subnet
 * cannot reclassify the checker.
 */
export function buildRanges(sources: readonly PrincipalSource[]): ResolvedRange[] {
  const weight = (kind: Principal): number =>
    kind === 'checker' ? 0 : kind === 'admin' ? 1 : kind === 'team' ? 2 : 3;
  return [...sources]
    .map(resolveRange)
    .sort((a, b) => weight(a.kind) - weight(b.kind));
}

export class NetworkMap {
  readonly ranges: ResolvedRange[];

  constructor(sources: readonly PrincipalSource[]) {
    this.ranges = buildRanges(sources);
  }

  /**
   * Highest-priority kind wins outright; within that kind the longest prefix
   * wins, so a /32 checker entry beats a /8 team range even if both match.
   */
  private match(ip: string): ResolvedRange | null {
    let bestKind: Principal | null = null;
    let best: ResolvedRange | null = null;
    for (const range of this.ranges) {
      if (!range.contains(ip)) continue;
      if (bestKind === null) {
        bestKind = range.kind;
      } else if (range.kind !== bestKind) {
        // A higher-priority kind already matched, and the ranges are sorted by
        // that priority, so nothing further can outrank it.
        break;
      }
      if (best === null || range.bits > best.bits) best = range;
    }
    return best;
  }

  decide(ip: string, opts: { requireAllowlist: boolean }): PrincipalDecision {
    const matched = this.match(ip);
    if (matched === null) {
      return {
        principal: 'unknown',
        team: null,
        own: false,
        matched: null,
        isChecker: false,
        // An unmatched address is refused only on a surface that demands an
        // allowlist. The analytics surface passes `requireAllowlist: true`, so a
        // stranger is told nothing at all, as though the port did not exist. The
        // proxy surface passes `false`: a stranger there is forwarded and logged,
        // because an unlisted address is the grader the organiser did not give us.
        refuse: opts.requireAllowlist,
        reason: 'no matching allowlist entry',
      };
    }
    if (matched.kind === 'checker') {
      return {
        principal: 'checker',
        team: null,
        own: false,
        matched,
        isChecker: true,
        refuse: false,
        reason: 'checker range: never blocked',
      };
    }
    return {
      principal: matched.kind,
      team: matched.team ?? null,
      own: matched.own === true,
      matched,
      isChecker: false,
      // An address that matched admin or team is on the list, so it is never
      // refused; it is still eligible for attack blocking.
      refuse: false,
      reason: `${matched.kind} range ${matched.cidr}`,
    };
  }

  /** Every address the map knows about, for the admin UI. */
  describe(): PrincipalDescription[] {
    return this.ranges.map((r) => ({
      kind: r.kind,
      cidr: r.cidr,
      ...(r.team === undefined ? {} : { team: r.team }),
      ...(r.own === true ? { own: true } : {}),
      ...(r.note === undefined ? {} : { note: r.note }),
      bits: r.bits,
      family: r.family,
    }));
  }
}

/**
 * Strip a port and any IPv6 brackets from a socket address.
 *
 * `server.listen` reports IPv4 peers as a bare address but IPv6 peers wrapped in
 * brackets, and this value is compared against operator-supplied CIDRs, so the
 * shape has to be normalised once, here.
 */
export function normaliseRemoteAddress(raw: string): string {
  let text = raw.trim();
  if (text.startsWith('[')) {
    const close = text.indexOf(']');
    if (close !== -1) return text.slice(1, close);
  }
  const lastColon = text.lastIndexOf(':');
  // Only a v4 address has exactly one colon; a v6 address has many and none of
  // them separate a port.
  if (lastColon !== -1 && text.indexOf(':') === lastColon) text = text.slice(0, lastColon);
  return text;
}
