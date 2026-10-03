/**
 * The ingress: every request to a protected service arrives here first.
 *
 * Four steps, and the order is the design.
 *
 * 1. The peer is identified from the socket address, before a byte of the request
 *    is read. A client cannot influence this. The address is recorded either way,
 *    because someone turned away at the door is still a decision the operator has
 *    to make later, and the admin UI offers exactly these addresses.
 *
 * 2. A known destination is resolved, or the request is a 404. Resolution reads
 *    only the config, so a crafted Host cannot aim the proxy anywhere.
 *
 * 3. A checker is forwarded immediately, with no reference to the analyser. This
 *    is what makes "fail closed without taking the checker down" true rather than
 *    aspirational: the grading path is a local decision over data already in
 *    memory, so a crash or a slow analysis cannot delay it.
 *
 * 4. Everyone else is scored. A block is a 403 with the rule that fired, because
 *    the participant has to be able to see why. A failure to score is itself a
 *    refusal, and a stranger is a socket destroyed before any byte is written,
 *    which a client reports as `ERR_CONNECTION_REFUSED` rather than a 403 that
 *    would confirm something is listening here.
 */

import http from 'node:http';
import type { Socket } from 'node:net';

import { scanCapture, type Artifact } from '@ad/engine';

import type { GatewayConfig, ResolvedRoute, Route, PortRoute } from './config.js';
import { RequestHistory, type Attempt, type Outcome } from './history.js';
import { NetworkMap, normaliseRemoteAddress, type Principal, type PrincipalSource } from './network.js';
import { detect, type RuleHit } from './rules.js';
import { AttemptFileStore, BODY_STORE_MAX } from './storage.js';

export interface DecisionInfo {
  ip: string;
  principal: Principal;
  team: string | null;
  host: string | null;
  method: string;
  target: string;
  outcome: Outcome;
  reason: string;
  status: number | null;
  durationMs: number;
  hits: RuleHit[];
  service: string | null;
  flags: string[];
  artifacts: Artifact[];
}

export interface GatewayOptions {
  rateLimitPerSecond: number;
  rateBurst: number;
  /** Hard cap on a buffered body, so a large upload cannot exhaust memory. */
  maxBodyBytes: number;
  upstreamTimeoutMs: number;
}

export const DEFAULT_OPTIONS: GatewayOptions = {
  rateLimitPerSecond: 20,
  rateBurst: 60,
  maxBodyBytes: 1024 * 1024,
  upstreamTimeoutMs: 15_000,
};

interface RequestTarget {
  target: string;
  path: string;
  query: string;
  host: string | null;
}

type Finish = (
  outcome: Outcome,
  reason: string,
  extra?: {
    status?: number | null;
    bytes?: number;
    hits?: RuleHit[];
    flags?: string[];
    artifacts?: Artifact[];
    headers?: Record<string, string>;
    body?: string;
  },
) => void;

interface CaptureScan {
  flags: string[];
  artifacts: Artifact[];
  headers: Record<string, string>;
  body: string;
}

/**
 * Scan a request for flags and hash/encoding material, and keep the pieces the
 * file store will record. The path and the field names are scanned too, because
 * a flag may travel in a query parameter name as easily as in its value.
 */
function scanRequest(
  headers: http.IncomingHttpHeaders,
  target: string,
  method: string,
  host: string | null,
  bodyText: string,
): CaptureScan {
  const flat = headerStrings(headers);
  const scan = scanCapture([target, method, host ?? '', ...Object.values(flat), bodyText]);
  return {
    flags: scan.flags,
    artifacts: scan.artifacts,
    headers: flat,
    body: bodyText.slice(0, BODY_STORE_MAX),
  };
}

function readTarget(req: http.IncomingMessage): RequestTarget {
  const raw = req.url ?? '/';
  const header = req.headers.host;
  let host: string | null = null;
  if (typeof header === 'string' && header.length > 0) {
    // Strip the port; a route is keyed by hostname alone.
    const colon = header.lastIndexOf(':');
    const bare = colon === -1 ? header : header.slice(0, colon);
    host = bare.toLowerCase().replace(/^\[|\]$/g, '');
  }
  const at = raw.indexOf('?');
  if (at === -1) return { target: raw, path: raw, query: '', host };
  return { target: raw, path: raw.slice(0, at), query: raw.slice(at + 1), host };
}

function readBody(req: http.IncomingMessage, cap: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > cap) {
        reject(new Error(`request body over ${cap} bytes`));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/** Reset the connection without writing a response, so nothing is disclosed. */
export function dropConnection(socket: Socket): void {
  socket.resetAndDestroy();
}

function headerStrings(headers: http.IncomingHttpHeaders): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    out[key] = Array.isArray(value) ? value.join(', ') : value;
  }
  return out;
}

export class Gateway {
  readonly history: RequestHistory;
  private readonly cfg: GatewayConfig;
  private readonly options: GatewayOptions;
  private readonly onDecision: ((info: DecisionInfo) => void) | undefined;
  readonly storage: AttemptFileStore | undefined;
  /** The main hostname-based ingress server. */
  private server: http.Server | null = null;
  /** Port-redirected ingress listeners (one per entry in `ingress_ports`). */
  private readonly portServers: http.Server[] = [];
  private readonly portListeners = new Map<number, http.Server>();
  private readonly ingressByListen = new Map<number, PortRoute>();
  /** Refusal listeners for `protected_ports`: accepted, then destroyed. */
  private readonly protectedServers: http.Server[] = [];
  private readonly protectedByListen = new Map<number, string>();
  /**
   * The effective network map. Built from the config at construction and rebuilt
   * when the operator labels an address in the UI, so a checker marked in the
   * dashboard takes effect without a restart.
   */
  private networkMap: NetworkMap;

  constructor(
    cfg: GatewayConfig,
    options: Partial<GatewayOptions> = {},
    extras: {
      history?: RequestHistory;
      onDecision?: (info: DecisionInfo) => void;
      storage?: AttemptFileStore;
    } = {},
  ) {
    this.cfg = cfg;
    this.options = { ...DEFAULT_OPTIONS, ...options };
    this.history = extras.history ?? new RequestHistory();
    this.onDecision = extras.onDecision;
    this.storage = extras.storage;
    this.networkMap = cfg.network;
    for (const route of cfg.ingressPorts.values()) {
      this.ingressByListen.set(route.listenPort, route);
    }
  }

  /** The current network map, including any address labels added at runtime. */
  get network(): NetworkMap {
    return this.networkMap;
  }

  /** The ports currently routed by the listener-port mode, config and UI alike. */
  get activeIngressPorts(): PortRoute[] {
    return [...this.ingressByListen.values()];
  }

  /**
   * Replace the network map with the config sources plus the operator's labels.
   * The config ranges stay ground truth; labels add to them and, because the map
   * sorts by kind first, a new checker range can never widen a team subnet into
   * covering the grader.
   */
  applySourceOverrides(overrides: readonly PrincipalSource[]): void {
    this.networkMap = new NetworkMap([...this.cfg.sources, ...overrides]);
  }

  private createServer(): http.Server {
    const server = http.createServer((req, res) => {
      void this.handle(req, res);
    });
    // A slow-loris style client must not be able to hold a connection open
    // indefinitely; the header timeout bounds the request line and headers.
    server.headersTimeout = 20_000;
    server.requestTimeout = 60_000;
    return server;
  }

  listen(): Promise<number> {
    this.server = this.createServer();
    const main = new Promise<number>((resolve, reject) => {
      const server = this.server as http.Server;
      server.once('error', reject);
      server.listen(this.cfg.listen.port, this.cfg.listen.host, () => {
        const address = server.address();
        resolve(typeof address === 'object' && address !== null ? address.port : 0);
      });
    });

    const bindings: Promise<void>[] = [...this.cfg.ingressPorts.values()].map((route) => {
      const server = this.createServer();
      this.portServers.push(server);
      this.portListeners.set(route.listenPort, server);
      return new Promise<void>((resolve, reject) => {
        server.once('error', reject);
        server.listen(route.listenPort, this.cfg.ingressPortsHost, () => resolve());
      });
    });

    if (!this.cfg.allowProtectedPorts) {
      for (const [port, note] of this.cfg.protectedPorts) {
        const listenPort = port + this.cfg.redirectOffset;
        const server = this.createServer();
        this.protectedServers.push(server);
        this.protectedByListen.set(listenPort, note);
        bindings.push(
          new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen(listenPort, this.cfg.ingressPortsHost, () => resolve());
          }),
        );
      }
    }

    return main.then(async (port) => {
      if (bindings.length > 0) await Promise.all(bindings);
      return port;
    });
  }

  async close(): Promise<void> {
    if (this.server !== null) {
      const server = this.server;
      this.server = null;
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    const servers = this.protectedServers.splice(0);
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
    const portServers = this.portServers.splice(0);
    await Promise.all(portServers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))));
  }

  /**
   * Route an extra public port from the operater's UI, living alongside the
   * `ingress_ports` in the config. Upstream defaults to the port the client was
   * dialling, exactly like a config entry.
   */
  async addIngressPort(
    publicPort: number,
    service: string,
    upstream?: string,
  ): Promise<{ ok: boolean; error?: string }> {
    if (!Number.isInteger(publicPort) || publicPort < 1 || publicPort > 65535) {
      return { ok: false, error: 'port is not a valid port number' };
    }
    if (typeof service !== 'string' || service.length === 0) {
      return { ok: false, error: 'service is required' };
    }
    const listenPort = publicPort + this.cfg.redirectOffset;
    if (listenPort > 65535) {
      return { ok: false, error: `listener port ${listenPort} overflows the offset` };
    }
    if (this.ingressByListen.has(listenPort) || this.protectedByListen.has(listenPort)) {
      return { ok: false, error: `port ${publicPort} is already routed or protected` };
    }
    const upstreamText = upstream === undefined || upstream.length === 0 ? `127.0.0.1:${publicPort}` : upstream;
    const parsed = /^(\[(?:[0-9a-fA-F:]+)\]|[^:]+):(\d+)$/.exec(upstreamText);
    if (parsed === null) {
      return { ok: false, error: 'upstream must be "host:port"' };
    }
    const upstreamPort = Number.parseInt(parsed[2] as string, 10);
    const upstreamHost = (parsed[1] as string).replace(/^\[|\]$/g, '');
    if (!Number.isInteger(upstreamPort) || upstreamPort < 1 || upstreamPort > 65535) {
      return { ok: false, error: 'upstream port is not a valid port number' };
    }
    const server = this.createServer();
    return new Promise((resolve) => {
      server.once('error', (err) => {
        server.close();
        const code = (err as NodeJS.ErrnoException).code;
        resolve({
          ok: false,
          error:
            code === 'EADDRINUSE'
              ? `listener port ${listenPort} is in use`
              : err instanceof Error ? err.message : String(err),
        });
      });
      server.listen(listenPort, this.cfg.ingressPortsHost, () => {
        this.portServers.push(server);
        this.portListeners.set(listenPort, server);
        this.ingressByListen.set(listenPort, {
          host: `${service}:${publicPort}`,
          service,
          upstream: upstreamText,
          upstreamHost,
          upstreamPort,
          publicPort,
          listenPort,
        });
        resolve({ ok: true });
      });
    });
  }

  /** Stop routing a public port added through the UI. */
  async removeIngressPort(publicPort: number): Promise<{ ok: boolean; error?: string }> {
    const listenPort = publicPort + this.cfg.redirectOffset;
    const server = this.portListeners.get(listenPort);
    if (server === undefined) {
      return { ok: false, error: 'port is not routed' };
    }
    this.portListeners.delete(listenPort);
    this.ingressByListen.delete(listenPort);
    const index = this.portServers.indexOf(server);
    if (index !== -1) this.portServers.splice(index, 1);
    await new Promise<void>((resolve) => server.close(() => resolve()));
    return { ok: true };
  }

  private routeFor(host: string | null): Route | null {
    if (host === null) return null;
    return this.cfg.routes.get(host) ?? null;
  }

  private routeForPeer(req: http.IncomingMessage, host: string | null): ResolvedRoute | null {
    // Port wins over Host: in the redirection mode a client dials the service's
    // own address, so its Host header is an IP:port that a hostname lookup would
    // never match, and the listener port is the only trustworthy signal.
    const portRoute = this.ingressByListen.get(req.socket.localPort ?? 0);
    if (portRoute !== undefined) return portRoute;
    return this.routeFor(host);
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const started = Date.now();
    const ip = normaliseRemoteAddress(req.socket.remoteAddress ?? '');
    const { target, path, query, host } = readTarget(req);
    // The ingress never refuses: everything coming in is recorded, and anything
    // unknown is forwarded as inoffensively as possible. Refusing strangers here
    // is what the analytics surface does, not the proxy. On a live run the
    // grader's address is not under our control, so a stranger must be observed
    // and forwarded rather than cut -- a cut stranger is exactly the grader.
    // The network map still classifies by priority (checker over admin over
    // team), which decides who is subject to the attack rules below; a stranger
    // is simply never subject to them.
    const decision = this.networkMap.decide(ip, { requireAllowlist: false });
    let route: ResolvedRoute | null = null;
    const method = req.method ?? 'GET';
    const headersFlat = headerStrings(req.headers);

    const finish: Finish = (outcome, reason, extra = {}) => {
      const durationMs = Date.now() - started;
      const hits = extra.hits ?? [];
      const flags = extra.flags ?? [];
      const artifacts = extra.artifacts ?? [];
      const service = decision.principal === 'checker' ? 'checker' : (route?.service ?? 'other');
      const attempt: Attempt = {
        id: `${Date.now().toString(36)}${Math.floor(Math.random() * 46656).toString(36)}${Math.floor(Math.random() * 46656).toString(36)}`,
        at: new Date().toISOString(),
        ip,
        principal: decision.principal,
        team: decision.team,
        own: decision.own,
        host,
        method,
        target,
        outcome,
        reason,
        status: extra.status ?? null,
        bytes: extra.bytes ?? 0,
        durationMs,
        rules: hits.map((h) => h.id),
        service,
        flags,
        artifacts,
        headers: extra.headers,
        body: extra.body,
      };
      this.history.add(attempt);
      if (this.storage !== undefined) {
        try {
          this.storage.append({
            at: attempt.at,
            ip,
            principal: decision.principal,
            team: decision.team,
            own: decision.own,
            service,
            host,
            method,
            target,
            outcome,
            reason,
            status: attempt.status,
            bytes: attempt.bytes,
            durationMs,
            rules: attempt.rules,
            flags,
            artifacts,
            headers: extra.headers ?? headersFlat,
            body: extra.body ?? '',
          });
        } catch {
          // The capture store must never take the proxy down; a failed append
          // only costs this one record, and the in-memory history still has it.
        }
      }
      this.onDecision?.({
        ip,
        principal: decision.principal,
        team: decision.team,
        host,
        method,
        target,
        outcome,
        reason,
        status: attempt.status,
        durationMs,
        hits,
        service,
        flags,
        artifacts,
      });
    };

    // Every call is recorded regardless of who it came from; nothing is dropped
    // on the ingress without being accounted for in the history first.

    // A protected port (a database, a management panel) is refused before any
    // routing: the connection was turned onto the gateway by the same redirect
    // rules as everything else, and it is destroyed with no response, so the
    // dialling client cannot tell that anything here is listening at all. The
    // operator sees the refusal in the history with the note from the config.
    const protectedNote = this.protectedByListen.get(req.socket.localPort ?? 0);
    if (protectedNote !== undefined) {
      const scan = scanRequest(req.headers, target, method, host, '');
      finish('blocked', `protected port ${protectedNote}`, { status: null, ...scan });
      dropConnection(req.socket);
      return;
    }

    route = this.routeForPeer(req, host);
    if (route === null) {
      // No body was read, so the scan covers path, method, host and headers. An
      // unrouted destination is broken at the socket, not answered with a 404:
      // a status would confirm that something here is inspecting the network.
      const scan = scanRequest(req.headers, target, method, host, '');
      finish('error', 'no route', { status: null, ...scan });
      dropConnection(req.socket);
      return;
    }

    let bodyText = '';
    let body: Buffer;
    try {
      body = await readBody(req, this.options.maxBodyBytes);
      bodyText = body.toString('utf8');
    } catch (err) {
      const scan = scanRequest(req.headers, target, method, host, '');
      res.writeHead(413, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: (err as Error).message }));
      finish('error', 'body rejected', { status: 413, ...scan });
      return;
    }
    const scan = scanRequest(req.headers, target, method, host, bodyText);

    // Only a positively-known participant is subject to the attack rules and
    // the rate limit. The checker, the operator, and any stranger are forwarded
    // and logged instead: a harness we do not control must pass whether or not
    // its address is known, and the operator must not cut their own traffic.
    // This is what makes a checker that was never told to us safe by position:
    // participant subnets are what get policed, everything else is observed.
    const analysable = decision.principal === 'team';

    if (analysable) {
      const now = Date.now();
      // Counted here, on arrival, so a burst of concurrent connections is judged
      // while it is in flight. Waiting for requests to finish would let the whole
      // burst through before the first one was ever recorded.
      this.history.noteArrival(ip, now, decision.principal, decision.team);
      const rate = this.history.ratesFor(ip, now);
      let result;
      try {
        result = detect(
          {
            method,
            path,
            query,
            body: body.toString('utf8'),
            headers: headerStrings(req.headers),
            remoteIp: ip,
            now,
            perSecond: rate.perSecond,
            peakPerSecond: rate.peakPerSecond,
          },
          this.options,
        );
      } catch (err) {
        // Fail closed against the analysis of a participant. The checker never
        // reached this code, so grading is unaffected by an analyser outage.
        res.writeHead(503, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'analyser unavailable' }));
        finish('blocked', `analyser error: ${(err as Error).message}`);
        return;
      }

      if (result.block) {
        // A held-back request gets no response at all. An HTTP status would tell
        // the client that something here is inspecting it and what it decided; a
        // broken connection is indistinguishable from a service that is simply
        // not accepting, which is what the emulated network should look like from
        // the outside. The rules and the reason stay in the history.
        finish(result.hits.every((hit) => hit.category === 'dos') ? 'throttled' : 'blocked', result.hits.map((h) => h.id).join(','), {
          status: null,
          hits: result.hits,
          ...scan,
        });
        dropConnection(req.socket);
        return;
      }

      await this.forward(req, res, route, ip, body, finish, result.hits, scan);
      return;
    }

    // Checker, operator, or unknown: forwarded without analysis, recorded all
    // the same. The peer and the route go to the upstream, and the history entry
    // says who it was under the principal the network map decided.
    await this.forward(req, res, route, ip, body, finish, [], scan);
  }

  private async forward(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    route: ResolvedRoute,
    ip: string,
    body: Buffer,
    finish: Finish,
    hits: RuleHit[],
    capture?: CaptureScan,
  ): Promise<void> {
    const headers = headerStrings(req.headers);
    // The upstream is told the real peer, so a course application that trusts
    // proxies logs who actually called rather than the gateway's address.
    const existing = headers['x-forwarded-for'];
    headers['x-forwarded-for'] = existing === undefined ? ip : `${ip}, ${existing}`;
    headers['x-forwarded-host'] = route.host;
    delete headers.host;
    delete headers.connection;
    // The body is buffered and re-framed, so the client's framing headers must
    // go. Relaying `transfer-encoding: chunked` alongside the `content-length`
    // set below is a protocol violation, and a Node server answers that with a
    // 400 before the request is ever routed.
    delete headers['transfer-encoding'];
    headers['content-length'] = String(body.length);

    await new Promise<void>((resolve) => {
      const upstream = http.request(
        {
          host: route.upstreamHost,
          port: route.upstreamPort,
          method: req.method ?? 'GET',
          // The path is the client's; only the destination is ours.
          path: req.url ?? '/',
          headers,
          timeout: this.options.upstreamTimeoutMs,
        },
        (upstreamRes) => {
          res.writeHead(upstreamRes.statusCode ?? 502, upstreamRes.headers);
          let sent = 0;
          upstreamRes.on('data', (chunk: Buffer) => {
            sent += chunk.length;
          });
          upstreamRes.pipe(res);
          upstreamRes.on('end', () => {
            finish('forwarded', route.host, { status: upstreamRes.statusCode ?? null, bytes: sent, hits, ...capture });
            resolve();
          });
          upstreamRes.on('error', () => {
            res.destroy();
            finish('error', 'upstream response aborted', { hits, ...capture });
            resolve();
          });
        },
      );
      upstream.on('timeout', () => upstream.destroy(new Error('upstream timeout')));
      upstream.on('error', (err) => {
        if (!res.headersSent) {
          res.writeHead(502, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'upstream unavailable', detail: err.message }));
        } else {
          res.destroy();
        }
        finish('error', `upstream error: ${err.message}`, { status: 502, hits, ...capture });
        resolve();
      });
      if (body.length > 0) upstream.write(body);
      upstream.end();
    });
  }
}
