/**
 * A best-effort scan of the services' own configuration files, so the operator
 * can see what the machine actually runs instead of typing it from memory.
 *
 * The stand is laid out as one folder per service, each folder containing the
 * service's sub-services (its own compose). The scan takes that layout
 * seriously:
 *
 *  - The top-level folders of the scanned directory ARE the services. Every
 *    publishable port found inside a folder is a candidate for that service.
 *  - Database sub-services (mysql/postgres/redis/mongodb/... by service name
 *    or image) are not routed: a database answers by protocol and a connection
 *    that passes through the gateway simply breaks, which is not the same as
 *    the HTTP checks the checker performs.
 *
 * The two formats that carry exposed ports are understood:
 *
 *  - `docker-compose.yml` / `compose.yaml`: each service and its published
 *    (`host:container`) ports.
 *  - `.env` files: `KEY_PORT=8083` pairs, where the prefix is taken as a hint of
 *    the service name.
 *
 * The scan is deliberately forgiving: an indentation quirk or an unsupported
 * compose construct skips a candidate rather than failing the whole scan, and
 * the result is a list of guesses the operator confirms in the UI, not a
 * machine that rewrites the network on its own.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

export interface DiscoveryCandidate {
  /** Folder that names the service; one card per folder in the UI. */
  group: string;
  /** The compose sub-service that publishes the port (the DNS name). */
  service: string;
  publicPort: number;
  /** The port inside the container; null when only a host-side value is known. */
  containerPort: number | null;
  /**
   * The address a route would forward to. For a compose service this is
   * `service:containerPort`, resolvable by DNS on the service networks the
   * gateway joins; for a bare `.env` port it stays the published port on
   * loopback, where the service is assumed to run on the host.
   */
  upstream: string;
  /** Where this port was found, so the operator can check whether it is current. */
  source: string;
}

export interface DiscoveryResult {
  candidates: DiscoveryCandidate[];
  /** Directory that was scanned; null when it does not exist. */
  dir: string | null;
  error: string | null;
}

const SKIP_DIRS = new Set([
  'node_modules',
  '.git',
  '.docker',
  'dist',
  'data',
  'build',
  'public',
  '.venv',
  'venv',
  'tmp',
]);
const COMPOSE_NAME = /^(docker-compose|compose)\.ya?ml$/;
const ENV_NAME = /(^\.env$|\.env$)/;
const DB_SERVICE = /^(db|database|mysql|mariadb|postgres|postgresql|mongodb|mongo|redis|memcached|tarantool|sqlite|clickhouse|cassandra)$/i;
const DB_IMAGE = /\b(mysql|mariadb|postgres|postgresql|mongodb|mongo|redis|memcached|tarantool|sqlite|clickhouse|cassandra)\b/i;

/** A database is not a routable checker target: skip its ports entirely. */
function isDatabase(service: string, image: string | null): boolean {
  if (DB_SERVICE.test(service)) return true;
  if (image !== null && DB_IMAGE.test(image)) return true;
  return false;
}

interface Mentioned {
  group: string;
  service: string;
  publicPort: number;
  /** The port inside the container; null when only a host-side value is known. */
  containerPort: number | null;
  source: string;
}

/**
 * Split a compose `ports:` token into the published (host) and container port.
 * `8083:80` means 8083 on the host and 80 inside the container; `8083` with no
 * pair (and a host address like `127.0.0.1:5435:5432` in front of the pair)
 * means the two halves can differ. When only one number is present it is used
 * for both halves, which covers most service files.
 */
function parsePortPair(token: string): { publicPort: number; containerPort: number } | null {
  const value = token.replace(/^['"]|['"]$/g, '').split(' #')[0] ?? '';
  const parts = value.split('/')[0]?.split(':') ?? [];
  const numeric: number[] = [];
  for (const part of parts) {
    const port = Number.parseInt(part, 10);
    if (/^\d+$/.test(part) && port >= 1 && port <= 65535) numeric.push(port);
  }
  if (numeric.length === 0) return null;
  const publicPort = numeric.length >= 2 ? (numeric[numeric.length - 2] as number) : (numeric[0] as number);
  const containerPort = numeric[numeric.length - 1] as number;
  return { publicPort, containerPort };
}

/**
 * Parse a compose file with a small indent-stack walker. Compose files on the
 * stand are hand-written and do not use a consistent indent (two spaces here,
 * three there), so the absolute column is never trusted: only the relative
 * depth between a name, its attributes and the items under `ports:` counts.
 */
function parseCompose(text: string, source: string, group: string): Mentioned[] {
  const out: Mentioned[] = [];
  const stack: Array<{ indent: number; key: string; parent: number }> = [];
  let servicesIdx = -1;
  let serviceIdx = -1;
  let serviceImage: string | null = null;
  for (const line of text.split(/\r?\n/)) {
    if (line.trim().length === 0 || line.trim().startsWith('#')) continue;
    const indent = line.match(/^\s*/)?.[0]?.length ?? 0;
    const content = line.slice(indent);
    const item = /^-\s+(.*)$/.exec(content);
    if (item !== null) {
      // A list item under `ports:` names the exposed ports of the current
      // service. Items under `environment:` and friends are ignored.
      const top = stack.length > 0 ? stack[stack.length - 1] : undefined;
      if (top !== undefined && top.key === 'ports' && serviceIdx >= 0) {
        const service = stack[serviceIdx]?.key ?? '';
        if (isDatabase(service, serviceImage)) continue;
        const value = (item[1] ?? '').split(' #')[0] ?? '';
        const pair = parsePortPair(value);
        if (pair === null) continue;
        out.push({ group, service, publicPort: pair.publicPort, containerPort: pair.containerPort, source });
      }
      continue;
    }
    const keyMatch = /^([A-Za-z0-9_.-]+):\s*(.*)$/.exec(content);
    if (keyMatch === null) continue;
    const key = keyMatch[1] as string;
    while (stack.length > 0 && (stack[stack.length - 1]?.indent ?? -1) >= indent) stack.pop();
    // A pop may have taken the section markers with it; invalidate them so a
    // stale marker never claims a later key.
    if (servicesIdx !== -1 && stack.length - 1 < servicesIdx) {
      servicesIdx = -1;
      serviceIdx = -1;
      serviceImage = null;
    } else if (serviceIdx !== -1 && stack.length - 1 < serviceIdx) {
      serviceIdx = -1;
      serviceImage = null;
    }
    const parent = stack.length - 1;
    stack.push({ indent, key, parent });
    const self = stack.length - 1;
    if (key === 'services' && parent === -1) {
      servicesIdx = self;
      serviceIdx = -1;
      serviceImage = null;
    } else if (servicesIdx >= 0 && parent === servicesIdx) {
      // Direct child of `services:` is a service name.
      serviceIdx = self;
      serviceImage = null;
    } else if (key === 'image' && serviceIdx >= 0 && parent === serviceIdx) {
      serviceImage = (keyMatch[2] as string).trim() || null;
    }
  }
  return out;
}

/** Read `KEY_PORT=8083` style pairs; the prefix names the sub-service. */
function parseEnv(text: string, source: string, group: string): Mentioned[] {
  const out: Mentioned[] = [];
  for (const line of text.split(/\r?\n/)) {
    const match = /^([A-Za-z0-9_]+)=(.*)$/.exec(line.trim());
    if (match === null) continue;
    const key = (match[1] as string).toUpperCase();
    // Only KEY_PORT pairs are candidates. A bare PORT= (the odd my-sql service
    // that hides in an env) cannot be attributed to a service by name, so it
    // would either leak a database or invent a routed loopback port for nothing.
    if (!key.endsWith('_PORT')) continue;
    const port = Number.parseInt((match[2] as string).replace(/^['"]|['"]$/g, ''), 10);
    if (!Number.isInteger(port) || port < 1 || port > 65535) continue;
    const name = key.slice(0, -'_PORT'.length).toLowerCase();
    if (name.length === 0 || isDatabase(name, null)) continue;
    out.push({ group, service: name, publicPort: port, containerPort: null, source });
  }
  return out;
}

function walk(
  dir: string,
  depth: number,
  cap: { files: number; candidates: number },
  group: string,
  out: Mentioned[],
): void {
  let entries: string[];
  try {
    entries = readdirSync(dir);
  } catch {
    return;
  }
  for (const name of entries) {
    if (out.length >= cap.candidates) return;
    const full = path.join(dir, name);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      if (SKIP_DIRS.has(name) || depth >= 5) continue;
      walk(full, depth + 1, cap, group, out);
      continue;
    }
    if (cap.files-- <= 0) return;
    if (COMPOSE_NAME.test(name)) {
      try {
        out.push(...parseCompose(readFileSync(full, 'utf8'), full, group));
      } catch {
        // unreadable file is a skipped candidate, never a failed scan
      }
    } else if (ENV_NAME.test(name)) {
      try {
        out.push(...parseEnv(readFileSync(full, 'utf8'), full, group));
      } catch {
        // same
      }
    }
  }
}

export function discoverServices(rootDir: string, skip?: Set<string>): DiscoveryResult {
  let stat;
  try {
    stat = statSync(rootDir);
  } catch {
    return { candidates: [], dir: null, error: `directory does not exist: ${rootDir}` };
  }
  if (!stat.isDirectory()) {
    return { candidates: [], dir: rootDir, error: `not a directory: ${rootDir}` };
  }

  let entries: string[];
  try {
    entries = readdirSync(rootDir);
  } catch {
    return { candidates: [], dir: rootDir, error: `cannot read directory: ${rootDir}` };
  }

  const mentioned: Mentioned[] = [];
  const cap = { files: 800, candidates: 200 };
  for (const name of entries) {
    const full = path.join(rootDir, name);
    let entryStat;
    try {
      entryStat = statSync(full);
    } catch {
      continue;
    }
    if (!entryStat.isDirectory() || SKIP_DIRS.has(name) || skip?.has(name)) continue;
    if (mentioned.length >= cap.candidates) break;
    walk(full, 1, cap, name, mentioned);
  }

  const seen = new Map<string, Mentioned>();
  for (const item of mentioned) {
    const key = `${item.group}:${item.service}:${item.publicPort}`;
    const existing = seen.get(key);
    // When a compose file and a .env both mention the same port, the compose
    // entry wins: it knows the container half of the mapping, the one a route
    // can use. Order of the walk must not decide that.
    if (existing === undefined || (existing.containerPort === null && item.containerPort !== null)) {
      seen.set(key, item);
    }
  }

  const candidates: DiscoveryCandidate[] = [];
  for (const item of seen.values()) {
    candidates.push({
      group: item.group,
      service: item.service,
      publicPort: item.publicPort,
      containerPort: item.containerPort,
      upstream:
        item.containerPort !== null
          ? `${item.service}:${item.containerPort}`
          : `127.0.0.1:${item.publicPort}`,
      source: item.source,
    });
  }
  candidates.sort((a, b) => {
    const byGroup = a.group.localeCompare(b.group);
    return byGroup !== 0 ? byGroup : a.service.localeCompare(b.service) || a.publicPort - b.publicPort;
  });
  return { candidates, dir: rootDir, error: null };
}