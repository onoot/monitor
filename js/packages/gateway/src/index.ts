/**
 * Entry point for the gateway.
 *
 * `AD_CONFIG` points at configs/gateway.json. The ingress and the analytics
 * listener come up together, and the process refuses to start rather than
 * starting half-configured: a gateway that is listening without an allowlist
 * would refuse every participant, and one that is not listening leaves the
 * services unprotected.
 */

import { randomBytes } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { loadGatewayConfig, type GatewayConfig } from './config.js';
import { Gateway, type DecisionInfo } from './gateway.js';
import { createAnalyticsServer } from './analytics.js';
import { AccountStore } from './accounts.js';
import { AttemptFileStore } from './storage.js';

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(PACKAGE_ROOT, '..', '..', '..');
const CONFIG_PATH = path.resolve(
  process.env.AD_GATEWAY_CONFIG ?? path.join(REPO_ROOT, 'configs', 'gateway.json'),
);
const DATA_DIR = path.resolve(
  process.env.AD_DATA_DIR ?? path.join(REPO_ROOT, 'data'),
);
// Operator state (labelled addresses, extra services) and where auto-detection
// scans for service config files. On the host these are plain paths; in the
// stand the services directory is mounted read-only and pointed at here.
const STATE_DIR = path.join(DATA_DIR, 'state');
const DISCOVER_DIR = process.env.AD_DISCOVER_DIR ?? path.resolve(REPO_ROOT, '..', 'services');
// Folders in the discovery root that are not team services. The gateway must
// never offer its own project as a service to route to itself.
const DISCOVER_SKIP = new Set(
  (process.env.AD_DISCOVER_SKIP ?? 'monitoring')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
);
// Sessions are JWTs signed with this secret. Without a fixed secret an ephemeral
// key is generated per boot, which is fine for a one-shot run but logs the
// operator out on every restart; the stand sets AD_JWT_SECRET so a rebuild of
// the container keeps the operator's session.
let jwtSecretText = process.env.AD_JWT_SECRET ?? '';
if (jwtSecretText.length === 0) {
  jwtSecretText = randomBytes(32).toString('hex');
  process.stderr.write('gateway: AD_JWT_SECRET is not set; sessions will not survive a restart\n');
}
const JWT_SECRET = Buffer.from(jwtSecretText, 'utf8');

// The gateway is the last thing standing between a grader and the services, so
// a crash in one module must not become an outage for everything. Exceptions
// are logged and the process keeps running; a request that hit a broken module
// is already recorded, and the capture store and the analyser both fail on
// their own boundaries rather than through an exit.
process.on('uncaughtException', (err: Error) => {
  process.stderr.write(`gateway: uncaught exception: ${err.stack ?? err.message}\n`);
});
process.on('unhandledRejection', (reason: unknown) => {
  process.stderr.write(`gateway: unhandled rejection: ${String(reason)}\n`);
});

function log(info: DecisionInfo): void {
  // One line per decision, so the gateway's own log is a usable audit trail
  // alongside the in-memory history and the capture files.
  process.stdout.write(
    `${info.outcome.padEnd(9)} ${info.ip.padEnd(15)} ${info.principal.padEnd(7)} ` +
      `${(info.service ?? '-').padEnd(10)} ${info.method.padEnd(4)} ${info.host ?? '-'} ${info.target}` +
      `${info.hits.length > 0 ? `  [${info.hits.map((h) => h.id).join(',')}]` : ''}` +
      `${info.flags.length > 0 ? `  flags=${info.flags.join(',')}` : ''}\n`,
  );
}

export async function start(): Promise<{
  config: GatewayConfig;
  ingress: Gateway;
  analytics: ReturnType<typeof createAnalyticsServer>;
  storage: AttemptFileStore;
}> {
  const config = loadGatewayConfig(CONFIG_PATH);
  // Accounts live in their own writable file so the dashboard can manage them.
  // The config's accounts are the seed for the first boot; see accounts.ts.
  const accounts = new AccountStore(
    process.env.AD_ACCOUNTS_FILE ?? path.join(STATE_DIR, 'accounts.json'),
    config.accounts.map((account) => ({
      login: account.login,
      passwordHash: account.passwordHash,
      role: account.role.kind,
      team: account.role.team,
    })),
  );
  const storage = new AttemptFileStore(DATA_DIR);
  const ingress = new Gateway(
    config,
    {
      rateLimitPerSecond: Number.parseInt(process.env.AD_RATE_LIMIT ?? '20', 10),
      rateBurst: Number.parseInt(process.env.AD_RATE_BURST ?? '60', 10),
    },
    { onDecision: log, storage },
  );
  const port = await ingress.listen();
  const analytics = createAnalyticsServer(config, ingress, {
    stateDir: STATE_DIR,
    discoveryDir: DISCOVER_DIR,
    launchDir: process.env.AD_SERVICES_DIR ?? DISCOVER_DIR,
    selfContainer: process.env.AD_SELF_CONTAINER ?? 'ad-monitoring',
    dataDir: DATA_DIR,
    reportsDir: process.env.AD_REPORTS_DIR,
    discoverSkip: DISCOVER_SKIP,
    jwtSecret: JWT_SECRET,
    // The store is the live account list: an account created or edited in the
    // dashboard is usable on the next login without a restart.
    accounts,
    verify: (login, password) => accounts.verify(login, password),
  });
  await analytics.listen();
  // Apply any services the operator saved before a previous restart.
  const bootApplied = await analytics.bootstrap();
  if (!bootApplied.ok) {
    process.stderr.write(`gateway: ${bootApplied.error ?? 'could not apply saved services'}\n`);
  }

  process.stdout.write(
    `gateway: ingress on ${config.listen.host}:${port}, analytics on ` +
      `${config.analyticsListen.host}:${config.analyticsListen.port}\n`,
  );
  process.stdout.write(
    `gateway: ${config.routes.size} routes, ` +
      `${Math.max(0, ingress.activeIngressPorts.length - config.ingressPorts.size)} added ingress ports, ` +
      `${config.protectedPorts.size} protected ports (allow=${config.allowProtectedPorts}), ` +
      `${config.network.describe().filter((r) => r.kind === 'checker').length} checker ranges, ` +
      `${config.network.describe().filter((r) => r.kind === 'team').length} team ranges, ` +
      `${accounts.count()} accounts, capture -> ${DATA_DIR}\n`,
  );
  // Anything still queued at shutdown is flushed on SIGTERM; the capture files
  // are the durable record, so a restart must not eat the tail of it.
  process.once('SIGTERM', () => {
    void storage.flush().finally(() => process.exit(0));
  });
  return { config, ingress, analytics, storage };
}

const isMain = process.argv[1] !== undefined && import.meta.url.endsWith(path.basename(process.argv[1]));

if (isMain) {
  start().catch((err: Error) => {
    process.stderr.write(`gateway: ${err.message}\n`);
    process.exit(1);
  });
}
