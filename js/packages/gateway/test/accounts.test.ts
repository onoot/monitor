import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import nodePath from 'node:path';
import { afterEach, describe, it } from 'node:test';

import { AccountError, AccountStore, type StoredAccount } from '../src/accounts.js';
import { hashPassword } from '../src/password.js';

const dirs: string[] = [];

function scratch(): string {
  const dir = mkdtempSync(nodePath.join(tmpdir(), 'ad-accounts-'));
  dirs.push(dir);
  return nodePath.join(dir, 'accounts.json');
}

afterEach(() => {
  while (dirs.length > 0) rmSync(dirs.pop() as string, { recursive: true, force: true });
});

async function seed(overrides: Partial<StoredAccount> = {}): Promise<StoredAccount[]> {
  return [
    {
      login: 'ops',
      passwordHash: await hashPassword('operator-pass'),
      role: 'admin',
      team: null,
      ...overrides,
    },
  ];
}

describe('AccountStore seeding', () => {
  it('persists the config seed on first boot so the surface is not empty', async () => {
    const file = scratch();
    const store = new AccountStore(file, await seed());
    assert.equal(store.count(), 1);
    // The file exists now: the seed was written, not kept only in memory.
    const onDisk = JSON.parse(readFileSync(file, 'utf8')) as { accounts: unknown[] };
    assert.equal(onDisk.accounts.length, 1);
  });

  it('drops seed entries whose hash is not a valid scrypt string', async () => {
    const good = (await seed())[0] as StoredAccount;
    const bad: StoredAccount = { login: 'broken', passwordHash: 'hunter2', role: 'admin', team: null };
    const store = new AccountStore(scratch(), [bad, good]);
    assert.deepEqual(
      store.list().map((account) => account.login),
      ['ops'],
    );
  });

  it('reads the file when it already exists instead of re-seeding', async () => {
    const file = scratch();
    const first = new AccountStore(file, await seed());
    await first.create({ login: 'blue', password: 'blue-team-pass', role: 'team', team: 'blue' });
    // A second store over the same file must see the persisted account, and an
    // empty seed must not wipe it.
    const second = new AccountStore(file, []);
    assert.deepEqual(
      second.list().map((account) => account.login),
      ['blue', 'ops'],
    );
  });

  it('falls back to the seed when the file is corrupt rather than trusting it', async () => {
    const file = scratch();
    writeFileSync(file, '{ this is not json', 'utf8');
    const store = new AccountStore(file, await seed());
    assert.equal((await store.verify('ops', 'operator-pass'))?.kind, 'admin');
  });

  it('skips malformed entries in an otherwise valid file', async () => {
    const file = scratch();
    const passwordHash = await hashPassword('operator-pass');
    writeFileSync(
      file,
      JSON.stringify({
        accounts: [
          { login: 'ops', password_hash: passwordHash, role: 'admin' },
          { login: 'bad role', password_hash: passwordHash, role: 'admin' },
          { login: 'loose', password_hash: passwordHash, role: 'team' },
          { login: 'ops', password_hash: passwordHash, role: 'admin' },
        ],
      }),
      'utf8',
    );
    const store = new AccountStore(file, []);
    assert.deepEqual(
      store.list().map((account) => account.login),
      ['ops'],
    );
  });
});

describe('AccountStore verify', () => {
  it('returns the role for the right password and null otherwise', async () => {
    const store = new AccountStore(scratch(), await seed());
    const role = await store.verify('ops', 'operator-pass');
    assert.deepEqual(role, { kind: 'admin', team: null, login: 'ops' });
    assert.equal(await store.verify('ops', 'wrong'), null);
    assert.equal(await store.verify('nobody', 'operator-pass'), null);
  });

  it('never exposes a hash through the view list', async () => {
    const store = new AccountStore(scratch(), await seed());
    const view = store.list()[0] as Record<string, unknown>;
    assert.equal('passwordHash' in view, false);
    assert.equal('password_hash' in view, false);
  });
});

describe('AccountStore create and update', () => {
  it('hashes the password and persists the account', async () => {
    const file = scratch();
    const store = new AccountStore(file, await seed());
    const created = await store.create({ login: 'red', password: 'red-team-pass', role: 'team', team: 'red' });
    assert.deepEqual(created, { login: 'red', role: 'team', team: 'red' });
    const raw = readFileSync(file, 'utf8');
    assert.ok(!raw.includes('red-team-pass'));
    assert.equal((await new AccountStore(file, []).verify('red', 'red-team-pass'))?.kind, 'team');
  });

  it('refuses to create the same login twice', async () => {
    const store = new AccountStore(scratch(), await seed());
    await assert.rejects(
      store.create({ login: 'ops', password: 'another-pass', role: 'admin' }),
      AccountError,
    );
  });

  it('requires a team for a team account', async () => {
    const store = new AccountStore(scratch(), await seed());
    await assert.rejects(
      store.create({ login: 'red', password: 'red-team-pass', role: 'team' }),
      /needs a team/,
    );
  });

  it('requires a long enough password', async () => {
    const store = new AccountStore(scratch(), await seed());
    await assert.rejects(store.create({ login: 'red', password: 'short', role: 'admin' }), /at least/);
  });

  it('keeps the existing password when an update omits it', async () => {
    const store = new AccountStore(scratch(), await seed());
    await store.update({ login: 'ops', role: 'admin' });
    assert.equal((await store.verify('ops', 'operator-pass'))?.kind, 'admin');
  });

  it('refuses to demote the last admin', async () => {
    const store = new AccountStore(scratch(), await seed());
    await assert.rejects(
      store.update({ login: 'ops', role: 'team', team: 'blue' }),
      /last admin/,
    );
  });
});

describe('AccountStore remove and setPassword', () => {
  it('removes an account and reports whether it existed', async () => {
    const store = new AccountStore(scratch(), await seed());
    await store.create({ login: 'red', password: 'red-team-pass', role: 'team', team: 'red' });
    assert.equal(store.remove('red'), true);
    assert.equal(store.remove('red'), false);
    assert.equal(await store.verify('red', 'red-team-pass'), null);
  });

  it('refuses to remove the last admin', async () => {
    const store = new AccountStore(scratch(), await seed());
    assert.throws(() => store.remove('ops'), /last admin/);
  });

  it('changes a password only when the current one matches', async () => {
    const store = new AccountStore(scratch(), await seed());
    await assert.rejects(store.setPassword('ops', 'wrong', 'a-new-password'), /wrong/);
    await store.setPassword('ops', 'operator-pass', 'a-new-password');
    assert.equal(await store.verify('ops', 'operator-pass'), null);
    assert.equal((await store.verify('ops', 'a-new-password'))?.kind, 'admin');
  });

  it('rejects a bad login shape', async () => {
    const store = new AccountStore(scratch(), await seed());
    await assert.rejects(store.create({ login: 'has space', password: 'long-enough', role: 'admin' }), AccountError);
  });
});
