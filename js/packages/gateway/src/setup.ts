/**
 * One-command config generation for a real network.
 *
 * Turns a small template -- teams, checker, admin, upstreams, accounts -- into a
 * ready gateway.json: passwords hashed, addresses validated, output re-parsed
 * through the same loader the gateway uses, so the file that lands on disk is
 * one the gateway would accept. The template holds no secrets: every account
 * names an environment variable that carries its password, and the plaintext
 * never touches the template or the output file.
 *
 *   node packages/gateway/dist/setup.js --template deploy/competition.example.json --out config/gateway.json
 *
 * When exactly one account is declared and it names no password_env, AD_PASSWORD
 * is used as a convenience fallback -- the common single-operator case.
 */

import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';

import { hashPassword } from './password.js';
import { parseGatewayConfig, type ListenSpec } from './config.js';

interface RawAccount {
  login?: unknown;
  role?: unknown;
  team?: unknown;
  password_env?: unknown;
}

interface RawTemplate {
  listen?: unknown;
  analytics_listen?: unknown;
  checker?: unknown;
  admin?: unknown;
  teams?: unknown;
  routes?: unknown;
  ingress_ports?: unknown;
  redirect_offset?: unknown;
  ingress_ports_host?: unknown;
  accounts?: unknown;
}

class SetupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SetupError';
  }
}

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value === undefined ? undefined : value;
}

function parseListen(value: unknown, label: string): ListenSpec {
  const raw = (value ?? {}) as { host?: unknown; port?: unknown };
  const defaultPort = label === 'analytics_listen' ? 8787 : 9090;
  const host = typeof raw.host === 'string' ? raw.host : '0.0.0.0';
  const port = Number(raw.port) > 0 ? Number(raw.port) : defaultPort;
  return { host, port };
}

function parseCidrs(value: unknown, label: string): { cidr: string; note?: string }[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw new SetupError(`${label} must be an array`);
  return value.map((entry) => {
    if (typeof entry === 'string') return { cidr: entry };
    if (entry === null || typeof entry !== 'object') {
      throw new SetupError(`${label} entries must be strings or { cidr, note }`);
    }
    const item = entry as { cidr?: unknown; note?: unknown };
    if (typeof item.cidr !== 'string' || item.cidr.length === 0) {
      throw new SetupError(`${label} entry is missing a cidr`);
    }
    return { cidr: item.cidr, ...(typeof item.note === 'string' ? { note: item.note } : {}) };
  });
}

function parseRoutes(value: unknown): Record<string, { service: string; upstream: string }> {
  const out: Record<string, { service: string; upstream: string }> = {};
  if (value === undefined) return out;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new SetupError('routes must be an object keyed by hostname');
  }
  for (const [host, entry] of Object.entries(value as Record<string, { service?: unknown; upstream?: unknown }>)) {
    if (typeof entry.service !== 'string' || typeof entry.upstream !== 'string') {
      throw new SetupError(`route ${host} needs service and upstream "host:port"`);
    }
    out[host] = { service: entry.service, upstream: entry.upstream };
  }
  return out;
}

/**
 * Port-redirection mode: `{ "8083": "curs" }` or `{ "8083": { service, upstream } }`.
 * The gateway listens on public+offset; deploy/iptables-forward.sh performs the
 * kernel redirect and reads this same block.
 */
function parseIngressPorts(value: unknown): Record<string, { service: string; upstream?: string }> {
  const out: Record<string, { service: string; upstream?: string }> = {};
  if (value === undefined) return out;
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new SetupError('ingress_ports must be an object keyed by public port');
  }
  for (const [port, entry] of Object.entries(value as Record<string, unknown>)) {
    if (!/^\d+$/.test(port)) throw new SetupError(`ingress_ports key ${port} must be a numeric port`);
    if (typeof entry === 'string') {
      if (entry.length === 0) throw new SetupError(`ingress_ports ${port}: empty service`);
      out[port] = { service: entry };
      continue;
    }
    const item = entry as { service?: unknown; upstream?: unknown };
    if (typeof item.service !== 'string' || item.service.length === 0) {
      throw new SetupError(`ingress_ports ${port}: missing service`);
    }
    out[port] = {
      service: item.service,
      ...(typeof item.upstream === 'string' ? { upstream: item.upstream } : {}),
    };
  }
  return out;
}

async function buildConfig(template: RawTemplate): Promise<Record<string, unknown>> {
  const accountsRaw = template.accounts;
  if (accountsRaw === undefined || !Array.isArray(accountsRaw) || accountsRaw.length === 0) {
    throw new SetupError('accounts must declare at least one account');
  }
  const accounts: { login: string; password_hash: string; role: string; team?: string }[] = [];
  const seen = new Set<string>();

  for (let index = 0; index < accountsRaw.length; index += 1) {
    const item = accountsRaw[index] as RawAccount;
    if (item === null || typeof item !== 'object') {
      throw new SetupError(`accounts[${index}] must be an object`);
    }
    const login = typeof item.login === 'string' ? item.login : '';
    if (login.length === 0) throw new SetupError(`accounts[${index}] is missing a login`);
    if (seen.has(login)) throw new SetupError(`duplicate account ${login}`);
    seen.add(login);

    const role = item.role === 'team' || item.role === 'admin' ? item.role : null;
    if (role === null) throw new SetupError(`account ${login}: role must be admin or team`);
    if (role === 'team' && (typeof item.team !== 'string' || item.team.length === 0)) {
      throw new SetupError(`account ${login}: a team account needs a team`);
    }

    const env = typeof item.password_env === 'string' && item.password_env.length > 0
      ? item.password_env
      : undefined;
    const password = env !== undefined
      ? process.env[env]
      : accountsRaw.length === 1
        ? process.env.AD_PASSWORD
        : undefined;
    if (password === undefined || password.length < 8) {
      throw new SetupError(
        `account ${login}: password of 8+ characters required via ` +
          (env !== undefined ? `\${${env}}` : '$AD_PASSWORD'),
      );
    }

    const passwordHash = await hashPassword(password);
    accounts.push({
      login,
      password_hash: passwordHash,
      role,
      ...(role === 'team' ? { team: item.team as string } : {}),
    });
  }

  return {
    _generated: 'by setup.js; edit deploy/competition.template.json and regenerate, not this file by hand',
    listen: parseListen(template.listen, 'listen'),
    analytics_listen: parseListen(template.analytics_listen, 'analytics_listen'),
    checker: parseCidrs(template.checker, 'checker'),
    admin: parseCidrs(template.admin, 'admin'),
    teams: parseCidrs(template.teams, 'teams'),
    routes: parseRoutes(template.routes),
    ...(template.ingress_ports !== undefined
      ? { ingress_ports: parseIngressPorts(template.ingress_ports) }
      : {}),
    ...(template.redirect_offset !== undefined ? { redirect_offset: template.redirect_offset } : {}),
    ...(template.ingress_ports_host !== undefined
      ? { ingress_ports_host: template.ingress_ports_host }
      : {}),
    accounts,
  };
}

async function main(): Promise<void> {
  const templatePath = arg('template');
  const outPath = arg('out');
  if (templatePath === undefined || outPath === undefined) {
    process.stderr.write(
      'usage: setup.js --template <template.json> --out <gateway.json>\n',
    );
    process.exit(2);
  }

  const template = JSON.parse(readFileSync(templatePath, 'utf8')) as RawTemplate;
  const config = await buildConfig(template);

  // The generated config is validated by the same loader the gateway starts
  // with, so a template that would make the gateway refuse to start is caught
  // at generation time rather than at 3am on the network.
  const text = JSON.stringify(config, null, 2);
  parseGatewayConfig(text);

  mkdirSync(path.dirname(path.resolve(outPath)), { recursive: true });
  writeFileSync(outPath, `${text}\n`);
  process.stdout.write(`setup: wrote ${path.resolve(outPath)}\n`);
}

main().catch((err: Error) => {
  process.stderr.write(`setup: ${err.message}\n`);
  process.exit(1);
});