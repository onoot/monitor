/**
 * Instance topology and checker lifecycle model.
 *
 * Derived from publicly released Altay checkers (AltayCTF-2018/2019) the engine
 * follows a fixed contract:
 *
 *     ip = config.IP_PATTERN.format(team_number=team)
 *     creds = Credentials.objects(team=team).order_by('-round').first()
 *
 *     check_index -> register/signup -> save_creds -> auth/signin
 *                 -> functional operations
 *                 -> put (write this round's flag)
 *                 -> next round: check_old_flag (read previous round's flag)
 *
 * Because the contract is stable we can reconstruct the expected traffic shape
 * for an unknown service and diff it against what was actually observed.
 */

import { parseCidr, parseIp } from './config.js';

const IP_PATTERN_RE = /IP_PATTERN\s*=\s*["'](?<p>[^"']+)["']/;

export interface Topology {
  ipPattern: string;
  /** team number -> instance address */
  teamIps: Map<number, string>;
  inferred(): boolean;
  teamCidrs(limit?: number): string[];
  /** Warn when a configured team network contains an inferred team IP. */
  overlapsConfiguredTeamNetworks(cidrs: readonly string[]): string[];
}

function makeTopology(ipPattern: string, teamIps: Map<number, string>): Topology {
  const topo: Topology = {
    ipPattern,
    teamIps,
    inferred(): boolean {
      return this.teamIps.size > 0;
    },
    teamCidrs(limit = 64): string[] {
      return [...this.teamIps.keys()]
        .sort((a, b) => a - b)
        .slice(0, limit)
        .map((num) => `${this.teamIps.get(num)}/32`);
    },
    overlapsConfiguredTeamNetworks(cidrs: readonly string[]): string[] {
      const overlaps: string[] = [];
      for (const cidr of cidrs) {
        const net = parseCidr(cidr);
        if (!net) continue;
        const maxBits = net.family === 4 ? 32 : 128;
        const shift = BigInt(maxBits - net.bits);
        for (const ip of this.teamIps.values()) {
          const value = parseIp(ip);
          if (value === null) continue;
          if ((ip.includes('.') ? 4 : 6) !== net.family) continue;
          if ((value >> shift) === net.base) {
            overlaps.push(cidr);
            break;
          }
        }
      }
      return overlaps;
    },
  };
  return topo;
}

/** Expand a Python `str.format` template with a single integer field. */
function formatTeamNumber(template: string, teamNumber: number): string | null {
  if (!template.includes('{') && !template.includes('}')) return null;
  return template
    .replace(/\{team_number\}/g, String(teamNumber))
    .replace(/\{team\}/g, String(teamNumber))
    .replace(/\{\s*\d+\s*\}/g, (match) => {
      // `{0}`-style positional index: unsupported, so bail out.
      throw new SyntaxError(match);
    });
}

/** Recover IP_PATTERN and the checker's own address from source dumps. */
export function inferTopology(sourceTexts: Iterable<string>): Topology {
  let pattern = '';
  for (const text of sourceTexts) {
    const match = IP_PATTERN_RE.exec(text);
    if (match) {
      pattern = match.groups?.p ?? '';
      break;
    }
  }
  if (!pattern) return makeTopology('', new Map());

  const teamIps = new Map<number, string>();
  // Bound the expansion: real deployments have at most a few dozen teams.
  for (let team = 0; team < 64; team += 1) {
    let ip: string | null;
    try {
      ip = formatTeamNumber(pattern, team);
    } catch {
      break;
    }
    if (ip === null || parseIp(ip) === null) break;
    teamIps.set(team, ip);
  }
  return makeTopology(pattern, teamIps);
}

export const LIFECYCLE_PHASES: readonly [string, string, string][] = [
  ['index', 'Service availability probe', 'checker'],
  ['register', 'Account / entity creation (flag is planted here or later)', 'checker'],
  ['auth', 'Login with previously stored credentials', 'checker'],
  ['operate', 'Normal functional read/write operations', 'both'],
  ['put', "This round's flag written into the service", 'checker'],
  ['get_old', "Previous round's flag read back", 'checker'],
];

export interface LifecyclePhase {
  key: string;
  description: string;
  expectedActor: string;
}

export function lifecycle(): LifecyclePhase[] {
  return LIFECYCLE_PHASES.map(([key, description, expectedActor]) => ({
    key,
    description,
    expectedActor,
  }));
}
