/**
 * The gateway's own configuration: who is allowed, and where a hostname goes.
 *
 * Two rules govern this file.
 *
 * Upstreams are an allowlist. A route resolves a hostname this file declares to
 * an address this file declares. Nothing a peer sends can introduce a new
 * destination, which is the difference between a proxy and an SSRF primitive --
 * and a real risk here, because the whole point of the box is to sit in front of
 * deliberately vulnerable services.
 *
 * Addresses are ground truth. A checker range is written down by the operator
 * before the run, so "is this the checker" is never answered by the traffic being
 * classified.
 */

import { readFileSync } from 'node:fs';
import { NetworkMap, NetworkConfigError, type PrincipalSource } from './network.js';
import type { Role } from './analytics.js';

export class GatewayConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GatewayConfigError';
  }
}

export interface Route {
  /** The hostname a client asks for. */
  host: string;
  /** Config name, used to look up the report for this service. */
  service: string;
  /** `host:port` on the local host or the docker network. */
  upstream: string;
  upstreamHost: string;
  upstreamPort: number;
}

/**
 * A route selected by the listening port rather than by the Host header.
 *
 * This is the only mode a checker outside our control can rely on: it dials the
 * team's address and the service port. Two deployments are covered by the same
 * fields:
 *
 *  - `redirect_offset: 0` binds the listener directly on the public port, on the
 *    interface named by `ingress_ports_host`. That is the deployment where the
 *    gateway itself is the team's address and services are private, so a client
 *    dialling `<team>:P` lands on this listener with the port deciding the
 *    route; the client's Host header is the team's IP and would never match a
 *    hostname route anyway.
 *
 *  - A positive offset keeps the netfilter REDIRECT model: the host REDIRECTs
 *    the service's public port P onto `P + redirect_offset`, where this listener
 *    sits, and nothing in the service or client configuration has to change.
 */
export interface PortRoute {
  /** label for logs and forward headers, e.g. `curs:8083`. */
  host: string;
  service: string;
  upstream: string;
  upstreamHost: string;
  upstreamPort: number;
  /** The public port clients keep dialling. */
  publicPort: number;
  /** The port the gateway actually binds (public + redirect offset). */
  listenPort: number;
}

export type ResolvedRoute = Route | PortRoute;

export interface ListenSpec {
  host: string;
  port: number;
}

/** An account for the analytics surface. */
export interface Account {
  login: string;
  /** scrypt hash, as `salt:hash` in hex. A plaintext password never reaches this file. */
  passwordHash: string;
  role: Role;
}

export interface GatewayConfig {
  listen: ListenSpec;
  analyticsListen: ListenSpec;
  routes: Map<string, Route>;
  /** Public port -> route, for the system-level port redirection mode. */
  ingressPorts: Map<number, PortRoute>;
  /** `public + this = listener port`; also tells the redirect rules the target. */
  redirectOffset: number;
  /** Where the redirected listeners bind; loopback unless overridden. */
  ingressPortsHost: string;
  /**
   * Ports the operator declared off-limits (a database, a management panel).
   * In the port-redirection mode the redirect rules turn these onto the gateway
   * too, and the gateway drops every connection on them with no response, so a
   * client dialling the service's own port learns nothing at all. With
   * `allow_protected_ports: true` the listeners are never bound and the forward
   * script skips redirecting them, which is what makes the database reachable
   * again for the operator who chose to.
   */
  protectedPorts: Map<number, string>;
  /** When true, protected ports are left to reach their own listener untouched. */
  allowProtectedPorts: boolean;
  network: NetworkMap;
  sources: PrincipalSource[];
  /** Team name the operator calls their own, for the UI's "наша" groupings. */
  ownTeam: string | null;
  accounts: Account[];
}

interface RawRoute {
  service?: unknown;
  upstream?: unknown;
}

function parseUpstream(value: unknown, host: string): { host: string; port: number } {
  if (typeof value !== 'string' || value.length === 0) {
    throw new GatewayConfigError(`route ${host}: upstream must be "host:port"`);
  }
  // IPv6 literals arrive bracketed, exactly as they would in a Host header.
  const bracketed = /^\[(.+)\]:(\d+)$/.exec(value);
  if (bracketed) {
    return { host: bracketed[1] as string, port: Number.parseInt(bracketed[2] as string, 10) };
  }
  const parts = value.split(':');
  if (parts.length !== 2) {
    throw new GatewayConfigError(
      `route ${host}: upstream ${JSON.stringify(value)} is not "host:port"`,
    );
  }
  const port = Number.parseInt(parts[1] as string, 10);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new GatewayConfigError(`route ${host}: upstream port is not a port: ${value}`);
  }
  return { host: parts[0] as string, port };
}

function parseListen(value: unknown, fallback: ListenSpec, label: string): ListenSpec {
  if (value === undefined) return fallback;
  const raw = value as { host?: unknown; port?: unknown };
  const port = raw.port === undefined ? fallback.port : Number(raw.port);
  // Port 0 is meaningful here: it asks the OS for any free port, which is what
  // tests and ephemeral runs need. Only an upstream port, where 0 would address
  // nothing, rejects it.
  if (!Number.isInteger(port) || (port as number) < 0 || (port as number) > 65535) {
    throw new GatewayConfigError(`${label}.port is not a port: ${String(raw.port)}`);
  }
  return { host: typeof raw.host === 'string' ? raw.host : fallback.host, port: port as number };
}

function readRanges(
  raw: unknown,
  kind: PrincipalSource['kind'],
  label: string,
): PrincipalSource[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new GatewayConfigError(`${label} must be an array`);
  return raw.map((entry) => {
    if (entry === null || typeof entry !== 'object') {
      throw new GatewayConfigError(`${label} entries must be objects`);
    }
    const item = entry as { cidr?: unknown; team?: unknown; own?: unknown; note?: unknown };
    if (typeof item.cidr !== 'string') {
      throw new GatewayConfigError(`${label} entry is missing a cidr`);
    }
    return {
      kind,
      cidr: item.cidr,
      ...(typeof item.team === 'string' ? { team: item.team } : {}),
      ...(kind === 'team' && item.own === true ? { own: true } : {}),
      ...(typeof item.note === 'string' ? { note: item.note } : {}),
    };
  });
}

function readAccounts(raw: unknown): Account[] {
  if (raw === undefined) return [];
  if (!Array.isArray(raw)) throw new GatewayConfigError('accounts must be an array');
  const seen = new Set<string>();
  return raw.map((entry) => {
    if (entry === null || typeof entry !== 'object') {
      throw new GatewayConfigError('accounts entries must be objects');
    }
    const item = entry as { login?: unknown; password_hash?: unknown; role?: unknown; team?: unknown };
    if (typeof item.login !== 'string' || item.login.length === 0) {
      throw new GatewayConfigError('accounts entry is missing a login');
    }
    if (seen.has(item.login)) {
      throw new GatewayConfigError(`duplicate account login ${item.login}`);
    }
    seen.add(item.login);
    if (typeof item.password_hash !== 'string' || !/^[0-9a-f]{32}:[0-9a-f]{128}$/.test(item.password_hash)) {
      // A plaintext password in the config would be a plaintext password in
      // version control, so the format is checked rather than merely accepted.
      throw new GatewayConfigError(
        `account ${item.login}: password_hash must be scrypt "salt:hash" in hex, not a password`,
      );
    }
    const kind = item.role === 'admin' || item.role === 'team' ? item.role : null;
    if (kind === null) throw new GatewayConfigError(`account ${item.login}: role must be "admin" or "team"`);
    if (kind === 'team' && (typeof item.team !== 'string' || item.team.length === 0)) {
      throw new GatewayConfigError(`account ${item.login}: a team account needs a team`);
    }
    return {
      login: item.login,
      passwordHash: item.password_hash,
      role: { kind, login: item.login, team: kind === 'team' ? (item.team as string) : null },
    };
  });
}

interface RawIngressEntry {
  service?: unknown;
  upstream?: unknown;
}

function readIngressPorts(raw: unknown, offset: number): Map<number, PortRoute> {
  const out = new Map<number, PortRoute>();
  if (raw === undefined) return out;
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new GatewayConfigError('ingress_ports must be an object keyed by public port');
  }
  for (const [key, value] of Object.entries(raw as Record<string, RawIngressEntry | string>)) {
    const publicPort = Number(key);
    if (!Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535) {
      throw new GatewayConfigError(`ingress_ports key ${JSON.stringify(key)} is not a port`);
    }
    const listenPort = publicPort + offset;
    if (listenPort > 65535) {
      throw new GatewayConfigError(
        `ingress_ports ${key}: listener port ${listenPort} overflows; lower redirect_offset`,
      );
    }

    let service: unknown;
    let upstreamRaw: unknown;
    if (typeof value === 'string') {
      service = value;
      upstreamRaw = undefined;
    } else if (value !== null && typeof value === 'object') {
      service = value.service;
      upstreamRaw = value.upstream;
    } else {
      throw new GatewayConfigError(`ingress_ports ${key}: value must be a service name or { service }`);
    }
    if (typeof service !== 'string' || service.length === 0) {
      throw new GatewayConfigError(`ingress_ports ${key} is missing a service`);
    }

    // The upstream defaults to the very port the client was dialling, which is
    // how this mode keeps the network unchanged under the hood: the redirect
    // moved the connection to the gateway, and the gateway gives it back.
    const upstream = parseUpstream(
      upstreamRaw === undefined ? `127.0.0.1:${publicPort}` : (upstreamRaw as string),
      `ingress_ports:${key}`,
    );
    out.set(publicPort, {
      host: `${service}:${publicPort}`,
      service,
      upstream: upstreamRaw === undefined ? `127.0.0.1:${publicPort}` : (upstreamRaw as string),
      upstreamHost: upstream.host,
      upstreamPort: upstream.port,
      publicPort,
      listenPort,
    });
  }
  return out;
}

function readProtectedPorts(raw: unknown): Map<number, string> {
  const out = new Map<number, string>();
  if (raw === undefined) return out;
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
    throw new GatewayConfigError('protected_ports must be an object keyed by port');
  }
  for (const [key, value] of Object.entries(raw as Record<string, unknown>)) {
    const port = Number(key);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new GatewayConfigError(`protected_ports key ${JSON.stringify(key)} is not a port`);
    }
    if (out.has(port)) {
      throw new GatewayConfigError(`duplicate protected_ports entry ${key}`);
    }
    out.set(port, typeof value === 'string' && value.length > 0 ? value : key);
  }
  return out;
}

export function parseGatewayConfig(text: string): GatewayConfig {
  let data: Record<string, unknown>;
  try {
    // A leading BOM is stripped before parsing. JSON does not allow one, but
    // every UTF-8-with-BOM writer on Windows adds it -- PowerShell's
    // `Set-Content -Encoding utf8` and Notepad among them -- and the resulting
    // "Unexpected token" points at a character nobody can see in the file.
    // The config is meant to be hand-edited on the machine where it runs, so
    // this is a routine accident rather than a malformed config.
    data = JSON.parse(text.charCodeAt(0) === 0xfeff ? text.slice(1) : text) as Record<
      string,
      unknown
    >;
  } catch (err) {
    throw new GatewayConfigError(`not valid JSON: ${(err as Error).message}`);
  }

  const sources: PrincipalSource[] = [
    ...readRanges(data.checker, 'checker', 'checker'),
    ...readRanges(data.admin, 'admin', 'admin'),
    ...readRanges(data.teams, 'team', 'teams'),
  ];
  if (sources.length === 0) {
    // Refusing to start is the only safe default: with no allowlist every
    // stranger would be refused and every listed address would be unreachable,
    // and a gateway that silently refuses everything is worse than one that
    // refuses to come up.
    throw new GatewayConfigError(
      'no checker, admin or team addresses configured; refusing to start',
    );
  }

  const routes = new Map<string, Route>();
  const rawRoutes = data.routes;
  if (rawRoutes !== undefined) {
    if (rawRoutes === null || typeof rawRoutes !== 'object' || Array.isArray(rawRoutes)) {
      throw new GatewayConfigError('routes must be an object keyed by hostname');
    }
    for (const [host, value] of Object.entries(rawRoutes as Record<string, RawRoute>)) {
      const normalisedHost = host.trim().toLowerCase();
      if (!/^[a-z0-9.-]+$/.test(normalisedHost)) {
        throw new GatewayConfigError(`route hostname ${JSON.stringify(host)} is not a hostname`);
      }
      if (value === null || typeof value !== 'object') {
        throw new GatewayConfigError(`route ${host} must be an object`);
      }
      if (typeof value.service !== 'string' || value.service.length === 0) {
        throw new GatewayConfigError(`route ${host} is missing a service`);
      }
      const upstream = parseUpstream(value.upstream, host);
      routes.set(normalisedHost, {
        host: normalisedHost,
        service: value.service,
        upstream: value.upstream as string,
        upstreamHost: upstream.host,
        upstreamPort: upstream.port,
      });
    }
  }

  let network: NetworkMap;
  try {
    network = new NetworkMap(sources);
  } catch (err) {
    if (err instanceof NetworkConfigError) {
      throw new GatewayConfigError(err.message);
    }
    throw err;
  }

  const accounts = readAccounts(data.accounts);
  const ownTeam =
    typeof data.own_team === 'string' && data.own_team.trim().length > 0
      ? data.own_team.trim()
      : null;

  const redirectOffsetRaw = Number(data.redirect_offset);
  const redirectOffset =
    data.redirect_offset === undefined
      ? 10_000
      : Number.isInteger(redirectOffsetRaw) && redirectOffsetRaw >= 0
        ? redirectOffsetRaw
        : (() => {
            throw new GatewayConfigError('redirect_offset must be a non-negative integer when set');
          })();
  const ingressPortsHost = typeof data.ingress_ports_host === 'string' && data.ingress_ports_host.length > 0
    ? data.ingress_ports_host
    : '127.0.0.1';

  const rawAllowProtected = data.allow_protected_ports;
  if (rawAllowProtected !== undefined && typeof rawAllowProtected !== 'boolean') {
    throw new GatewayConfigError('allow_protected_ports must be a boolean when set');
  }
  const allowProtectedPorts = rawAllowProtected === true;

  const ingressPorts = readIngressPorts(data.ingress_ports, redirectOffset);
  const protectedPorts = readProtectedPorts(data.protected_ports);

  // The same public port cannot be a route and a refusal; which one wins would
  // be a matter of argument, so the config refuses to present the ambiguity.
  for (const port of ingressPorts.keys()) {
    if (protectedPorts.has(port)) {
      throw new GatewayConfigError(
        `ingress_ports and protected_ports both claim port ${port}; remove it from one`,
      );
    }
  }
  for (const port of protectedPorts.keys()) {
    if (port + redirectOffset > 65535) {
      throw new GatewayConfigError(
        `protected_ports ${port}: listener port ${port + redirectOffset} overflows; lower redirect_offset`,
      );
    }
  }

  return {
    listen: parseListen(data.listen, { host: '0.0.0.0', port: 8080 }, 'listen'),
    analyticsListen: parseListen(
      data.analytics_listen,
      { host: '0.0.0.0', port: 8787 },
      'analytics_listen',
    ),
    routes,
    ingressPorts,
    redirectOffset,
    ingressPortsHost,
    protectedPorts,
    allowProtectedPorts,
    network,
    sources,
    ownTeam,
    accounts,
  };
}

export function loadGatewayConfig(configPath: string): GatewayConfig {
  return parseGatewayConfig(readFileSync(configPath, 'utf8'));
}
