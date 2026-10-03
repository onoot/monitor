import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { hashPassword, verifyPassword } from '../src/password.js';
import { parseGatewayConfig, GatewayConfigError } from '../src/config.js';

describe('password hashing', () => {
  it('accepts the right password', async () => {
    const stored = await hashPassword('correct horse battery');
    const result = await verifyPassword('correct horse battery', stored);
    assert.equal(result.ok, true);
    assert.equal(result.malformed, false);
  });

  it('rejects a wrong password', async () => {
    const stored = await hashPassword('correct horse battery');
    assert.equal((await verifyPassword('wrong', stored)).ok, false);
  });

  it('uses a fresh salt, so two accounts with one password differ', async () => {
    // Identical hashes would let anyone who read the config see which accounts
    // share a password.
    const a = await hashPassword('same-password');
    const b = await hashPassword('same-password');
    assert.notEqual(a, b);
    assert.equal((await verifyPassword('same-password', a)).ok, true);
    assert.equal((await verifyPassword('same-password', b)).ok, true);
  });

  it('does not store the password in any form', async () => {
    const stored = await hashPassword('plaintext-should-not-appear');
    assert.ok(!stored.includes('plaintext'));
    assert.match(stored, /^[0-9a-f]{32}:[0-9a-f]{128}$/);
  });

  it('reports a truncated hash as malformed, not as a wrong password', async () => {
    // The two mean different things to the operator: one needs the config fixed,
    // the other just needs a retype.
    assert.deepEqual(await verifyPassword('x', 'nocolon'), { ok: false, malformed: true });
    assert.deepEqual(await verifyPassword('x', 'abcd:efgh'), { ok: false, malformed: true });
  });

  it('takes real time, which is the point of the cost', async () => {
    const stored = await hashPassword('timing-check');
    const started = process.hrtime.bigint();
    await verifyPassword('timing-check', stored);
    const ms = Number(process.hrtime.bigint() - started) / 1e6;
    assert.ok(ms > 5, `expected a deliberate delay, took ${ms.toFixed(1)}ms`);
  });
});

describe('accounts in config', () => {
  const base = JSON.stringify({
    listen: { host: '127.0.0.1', port: 0 },
    checker: [{ cidr: '10.0.0.9' }],
    routes: { 'app.local': { service: 'curs', upstream: '127.0.0.1:8083' } },
  });

  it('accepts a hashed account', async () => {
    const passwordHash = await hashPassword('a-good-password');
    const config = parseGatewayConfig(
      JSON.stringify({ ...JSON.parse(base), accounts: [{ login: 'ops', password_hash: passwordHash, role: 'admin' }] }),
    );
    assert.equal(config.accounts.length, 1);
    assert.deepEqual(config.accounts[0]?.role, { kind: 'admin', login: 'ops', team: null });
  });

  it('refuses a plaintext password in the config', () => {
    assert.throws(
      () =>
        parseGatewayConfig(
          JSON.stringify({ ...JSON.parse(base), accounts: [{ login: 'ops', password: 'plaintext', role: 'admin' }] }),
        ),
      GatewayConfigError,
    );
  });

  it('refuses a password_hash that is not a hash', () => {
    // The format is checked so a config cannot quietly hold a password.
    assert.throws(
      () =>
        parseGatewayConfig(
          JSON.stringify({ ...JSON.parse(base), accounts: [{ login: 'ops', password_hash: 'hunter2', role: 'admin' }] }),
        ),
      /scrypt/,
    );
  });

  it('refuses a duplicate login', () => {
    const entry = { login: 'ops', password_hash: `${'a'.repeat(32)}:${'b'.repeat(128)}`, role: 'admin' };
    assert.throws(
      () => parseGatewayConfig(JSON.stringify({ ...JSON.parse(base), accounts: [entry, entry] })),
      /duplicate/,
    );
  });

  it('refuses a team account with no team', () => {
    assert.throws(
      () =>
        parseGatewayConfig(
          JSON.stringify({
            ...JSON.parse(base),
            accounts: [{ login: 'a', password_hash: `${'a'.repeat(32)}:${'b'.repeat(128)}`, role: 'team' }],
          }),
        ),
      /needs a team/,
    );
  });

  it('refuses an unknown role', () => {
    assert.throws(
      () =>
        parseGatewayConfig(
          JSON.stringify({
            ...JSON.parse(base),
            accounts: [{ login: 'a', password_hash: `${'a'.repeat(32)}:${'b'.repeat(128)}`, role: 'superuser' }],
          }),
        ),
      /role must be/,
    );
  });

  it('has no accounts when none are configured', () => {
    assert.deepEqual(parseGatewayConfig(base).accounts, []);
  });
});
