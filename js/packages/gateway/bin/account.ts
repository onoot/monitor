/**
 * Create or update an account in the writable accounts file.
 *
 * Run with a login and a password on the command line; the password is hashed
 * before it is written, and the plaintext is never stored. Used to provision the
 * operator and team logins without going through the dashboard.
 *
 *   npx tsx bin/account.ts --login ops --role admin
 *   npx tsx bin/account.ts --login alpha --role team --team alpha
 *
 * An existing login is updated rather than duplicated, so re-running with a new
 * password is how a password is reset. The file defaults to
 * <data>/state/accounts.json (AD_ACCOUNTS_FILE overrides it); the accounts in
 * configs/gateway.json seed it on first boot, which is also what the gateway
 * itself does.
 */

import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { loadGatewayConfig } from '../src/config.js';
import { AccountStore, AccountError, type StoredAccount } from '../src/accounts.js';

const PACKAGE_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const REPO_ROOT = path.resolve(PACKAGE_ROOT, '..', '..', '..');
const CONFIG_PATH = path.resolve(
  process.env.AD_GATEWAY_CONFIG ?? path.join(REPO_ROOT, 'configs', 'gateway.json'),
);
const DATA_DIR = path.resolve(process.env.AD_DATA_DIR ?? path.join(REPO_ROOT, 'data'));
const ACCOUNTS_FILE = path.resolve(
  process.env.AD_ACCOUNTS_FILE ?? path.join(DATA_DIR, 'state', 'accounts.json'),
);

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`);
  if (index === -1) return undefined;
  const value = process.argv[index + 1];
  return value === undefined || value.startsWith('--') ? undefined : value;
}

const login = arg('login');
const password = arg('password') ?? process.env.AD_PASSWORD;
const role = arg('role');
const team = arg('team');

if (login === undefined || role === undefined) {
  process.stderr.write('usage: account.ts --login <name> --role admin|team [--team <name>] [--password <pw>]\n');
  process.stderr.write('       pass the password with AD_PASSWORD to keep it out of the command line\n');
  process.exit(2);
}

let seed: StoredAccount[] = [];
try {
  seed = loadGatewayConfig(CONFIG_PATH).accounts.map((account) => ({
    login: account.login,
    passwordHash: account.passwordHash,
    role: account.role.kind,
    team: account.role.team,
  }));
} catch {
  // No seed config (or an unreadable one): still let the operator add an
  // account, since the store is the source of truth once it exists.
}

const store = new AccountStore(ACCOUNTS_FILE, seed);
const existed = store.list().some((account) => account.login === login);

try {
  await store.upsert({ login, password, role, team });
} catch (err) {
  if (err instanceof AccountError) {
    process.stderr.write(`${err.message}\n`);
    process.exit(2);
  }
  throw err;
}

process.stdout.write(`${existed ? 'updated' : 'created'} ${role} account ${login} in ${ACCOUNTS_FILE}\n`);
