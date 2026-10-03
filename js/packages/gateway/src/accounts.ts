/**
 * The account store: who may sign in to the analytics surface.
 *
 * Accounts are kept in a dedicated JSON file rather than in the read-only
 * gateway config, because the dashboard is expected to create and edit them from
 * the UI. The file holds only scrypt hashes -- a plaintext password never
 * reaches it -- and is written atomically (temp file plus rename) so a crash
 * halfway through an edit cannot leave a half-written account list behind.
 *
 * The config's own `accounts` are the seed: on first boot, when the file does
 * not exist yet, they are copied in so the operator and team logins that were
 * provisioned for the stand keep working. After that the file is the truth.
 *
 * Fail-closed throughout: a corrupt file falls back to the seed (and an empty
 * seed means nobody can sign in) rather than being trusted or crashing the
 * gateway, and the last admin can never be demoted or removed, so the surface
 * cannot be locked out by its own management screen.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import nodePath from 'node:path';

import type { Role } from './analytics.js';
import { hashPassword, verifyPassword } from './password.js';

export class AccountError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AccountError';
  }
}

/** One account as it is stored on disk (hash only, never a password). */
export interface StoredAccount {
  login: string;
  passwordHash: string;
  role: 'admin' | 'team';
  team: string | null;
}

/** One account as the API and the UI see it (no hash leaves the process). */
export interface AccountView {
  login: string;
  role: 'admin' | 'team';
  team: string | null;
}

const LOGIN_RE = /^[A-Za-z0-9._-]{1,64}$/;
const TEAM_RE = /^[A-Za-z0-9._-]{1,64}$/;
const HASH_RE = /^[0-9a-f]{32}:[0-9a-f]{128}$/;
const MIN_PASSWORD = 8;

function toView(account: StoredAccount): AccountView {
  return { login: account.login, role: account.role, team: account.team };
}

function validateLogin(login: unknown): string {
  if (typeof login !== 'string' || !LOGIN_RE.test(login)) {
    throw new AccountError('login must be 1-64 characters of letters, digits, dot, dash or underscore');
  }
  return login;
}

function validateRole(role: unknown): 'admin' | 'team' {
  if (role !== 'admin' && role !== 'team') throw new AccountError('role must be admin or team');
  return role;
}

function validateTeam(role: 'admin' | 'team', team: unknown): string | null {
  if (role === 'admin') return null;
  if (typeof team !== 'string' || !TEAM_RE.test(team.trim())) {
    throw new AccountError('a team account needs a team name (letters, digits, dot, dash or underscore)');
  }
  return team.trim();
}

function validatePassword(password: unknown): string {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD) {
    throw new AccountError(`password must be at least ${MIN_PASSWORD} characters`);
  }
  return password;
}

export class AccountStore {
  private accounts: StoredAccount[];
  private readonly file: string;

  constructor(file: string, seed: StoredAccount[] = []) {
    this.file = file;
    this.accounts = this.load(seed);
  }

  /** Read the file, or seed it from the config's accounts on first boot. */
  private load(seed: StoredAccount[]): StoredAccount[] {
    const usableSeed = seed.filter((account) => HASH_RE.test(account.passwordHash));
    if (!existsSync(this.file)) {
      if (usableSeed.length > 0) this.persist(usableSeed);
      return usableSeed;
    }
    try {
      const data = JSON.parse(readFileSync(this.file, 'utf8')) as { accounts?: unknown };
      const raw = Array.isArray(data.accounts) ? data.accounts : [];
      const out: StoredAccount[] = [];
      const seen = new Set<string>();
      for (const entry of raw) {
        if (entry === null || typeof entry !== 'object') continue;
        const item = entry as { login?: unknown; password_hash?: unknown; role?: unknown; team?: unknown };
        if (typeof item.login !== 'string' || !LOGIN_RE.test(item.login) || seen.has(item.login)) continue;
        if (typeof item.password_hash !== 'string' || !HASH_RE.test(item.password_hash)) continue;
        if (item.role !== 'admin' && item.role !== 'team') continue;
        const team =
          item.role === 'team' && typeof item.team === 'string' && item.team.length > 0
            ? item.team
            : null;
        if (item.role === 'team' && team === null) continue;
        seen.add(item.login);
        out.push({ login: item.login, passwordHash: item.password_hash, role: item.role, team });
      }
      return out;
    } catch {
      // A corrupt file must not take the surface down. Fall back to the seed; if
      // there is none, the surface is closed rather than open.
      return usableSeed;
    }
  }

  /** Write the whole list atomically. */
  private persist(next: StoredAccount[]): void {
    try {
      mkdirSync(nodePath.dirname(this.file), { recursive: true });
    } catch {
      /* the directory already exists */
    }
    const payload = {
      accounts: next.map((account) => ({
        login: account.login,
        password_hash: account.passwordHash,
        role: account.role,
        ...(account.role === 'team' && account.team !== null ? { team: account.team } : {}),
      })),
    };
    const tmp = `${this.file}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
    renameSync(tmp, this.file);
  }

  private save(): void {
    this.persist(this.accounts);
  }

  private find(login: string): StoredAccount | undefined {
    return this.accounts.find((account) => account.login === login);
  }

  private adminCount(): number {
    return this.accounts.filter((account) => account.role === 'admin').length;
  }

  list(): AccountView[] {
    return this.accounts
      .map(toView)
      .sort((a, b) => a.login.localeCompare(b.login));
  }

  count(): number {
    return this.accounts.length;
  }

  /** Check a login and password, returning the role or null. */
  async verify(login: string, password: string): Promise<Role | null> {
    for (const account of this.accounts) {
      if (account.login !== login) continue;
      const result = await verifyPassword(password, account.passwordHash);
      return result.ok ? { kind: account.role, team: account.team, login: account.login } : null;
    }
    return null;
  }

  /** Create an account. The password is required and is hashed before storing. */
  async create(input: { login?: unknown; password?: unknown; role?: unknown; team?: unknown }): Promise<AccountView> {
    const login = validateLogin(input.login);
    if (this.find(login) !== undefined) throw new AccountError(`account ${login} already exists`);
    const role = validateRole(input.role);
    const team = validateTeam(role, input.team);
    const passwordHash = await hashPassword(validatePassword(input.password));
    const account: StoredAccount = { login, passwordHash, role, team };
    this.accounts.push(account);
    this.save();
    return toView(account);
  }

  /**
   * Update an account in place. A password that is omitted keeps the existing
   * one; role and team are revalidated together so a team account can never be
   * left without a team, and the last admin cannot be demoted.
   */
  async update(input: { login?: unknown; password?: unknown; role?: unknown; team?: unknown }): Promise<AccountView> {
    const login = validateLogin(input.login);
    const account = this.find(login);
    if (account === undefined) throw new AccountError(`no account ${login}`);
    const role = input.role === undefined ? account.role : validateRole(input.role);
    const team = validateTeam(role, input.team === undefined ? account.team : input.team);
    if (account.role === 'admin' && role !== 'admin' && this.adminCount() <= 1) {
      throw new AccountError('cannot demote the last admin');
    }
    if (input.password !== undefined) {
      account.passwordHash = await hashPassword(validatePassword(input.password));
    }
    account.role = role;
    account.team = team;
    this.save();
    return toView(account);
  }

  /** Create the login if it is new, update it otherwise. */
  async upsert(input: { login?: unknown; password?: unknown; role?: unknown; team?: unknown }): Promise<AccountView> {
    const login = validateLogin(input.login);
    return this.find(login) === undefined ? this.create(input) : this.update(input);
  }

  /** Remove an account. Returns false when there was nothing to remove. */
  remove(login: unknown): boolean {
    const name = validateLogin(login);
    const account = this.find(name);
    if (account === undefined) return false;
    if (account.role === 'admin' && this.adminCount() <= 1) {
      throw new AccountError('cannot remove the last admin');
    }
    this.accounts = this.accounts.filter((entry) => entry.login !== name);
    this.save();
    return true;
  }

  /** Change one account's password after checking the current one. */
  async setPassword(login: string, current: unknown, next: unknown): Promise<void> {
    const account = this.find(login);
    if (account === undefined) throw new AccountError('no such account');
    const result = await verifyPassword(typeof current === 'string' ? current : '', account.passwordHash);
    if (!result.ok) throw new AccountError('current password is wrong');
    account.passwordHash = await hashPassword(validatePassword(next));
    this.save();
  }
}
