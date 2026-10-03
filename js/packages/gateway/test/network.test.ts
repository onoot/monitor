/**
 * The allowlist precedence rules.
 *
 * These are the tests that matter most in the gateway: a mis-ordered range can
 * block the checker, and a mis-parsed address can classify a stranger as the
 * checker. Both failures are silent, so they are pinned here rather than left to
 * the integration run to discover.
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { NetworkMap, normaliseRemoteAddress } from '../src/network.js';

const NET = {
  requireAllowlist: true,
};

function map(): NetworkMap {
  return new NetworkMap([
    // Deliberately broad, and listed first: it must still lose to the /32 below.
    { kind: 'team', cidr: '10.0.0.0/8', team: 'everyone' },
    { kind: 'checker', cidr: '10.77.0.9' },
    { kind: 'admin', cidr: '10.0.0.1' },
    { kind: 'team', cidr: '10.1.2.0/24', team: 'alpha' },
  ]);
}

describe('principal classification', () => {
  it('gives the checker precedence over an enclosing team range', () => {
    const decision = map().decide('10.77.0.9', NET);
    assert.equal(decision.principal, 'checker');
    assert.equal(decision.isChecker, true);
    assert.equal(decision.team, null);
  });

  it('never blocks or refuses the checker', () => {
    const decision = map().decide('10.77.0.9', NET);
    assert.equal(decision.refuse, false);
  });

  it('prefers the narrowest range inside one kind', () => {
    const decision = map().decide('10.1.2.7', NET);
    assert.equal(decision.principal, 'team');
    assert.equal(decision.team, 'alpha');
  });

  it('falls back to a broad team range and labels the team', () => {
    const decision = map().decide('10.5.5.5', NET);
    assert.equal(decision.principal, 'team');
    assert.equal(decision.team, 'everyone');
  });

  it('recognises admin ahead of team', () => {
    const decision = map().decide('10.0.0.1', NET);
    assert.equal(decision.principal, 'admin');
  });

  it('refuses an unlisted address on the analytics surface', () => {
    const decision = map().decide('198.51.100.4', NET);
    assert.equal(decision.principal, 'unknown');
    assert.equal(decision.refuse, true);
    assert.equal(decision.matched, null);
  });

  it('still lists an on-the-list address as team, eligible for blocking', () => {
    const decision = map().decide('10.1.2.7', NET);
    assert.equal(decision.refuse, false);
    assert.equal(decision.isChecker, false);
  });

  it('lets an unlisted address through when the surface does not require a list', () => {
    const decision = map().decide('198.51.100.4', { requireAllowlist: false });
    assert.equal(decision.principal, 'unknown');
    assert.equal(decision.refuse, false);
  });

  it('flags a narrower own-team subnet carved from a broader team range', () => {
    const m = new NetworkMap([
      { kind: 'team', cidr: '10.1.2.0/24', team: 'alpha' },
      { kind: 'team', cidr: '10.1.2.0/28', team: 'alpha', own: true },
    ]);
    const inside = m.decide('10.1.2.5', NET);
    assert.equal(inside.principal, 'team');
    assert.equal(inside.team, 'alpha');
    assert.equal(inside.own, true);
    // The rest of the opponents' subnet keeps the broad range, so it is not ours.
    assert.equal(m.decide('10.1.2.200', NET).own, false);
  });

  it('never marks a checker or admin as own', () => {
    const m = new NetworkMap([
      { kind: 'team', cidr: '10.1.2.0/24', team: 'alpha', own: true },
      { kind: 'checker', cidr: '10.1.2.9' },
    ]);
    const checker = m.decide('10.1.2.9', NET);
    assert.equal(checker.principal, 'checker');
    assert.equal(checker.own, false);
  });
});

describe('address parsing', () => {
  it('treats an unparseable address as unknown, never as checker', () => {
    const decision = map().decide('not-an-ip', NET);
    assert.equal(decision.principal, 'unknown');
    assert.equal(decision.isChecker, false);
  });

  it('does not let a v4 address match a v6 range', () => {
    const v6 = new NetworkMap([{ kind: 'checker', cidr: '::1' }]);
    assert.equal(v6.decide('10.0.0.1', NET).isChecker, false);
    assert.equal(v6.decide('::1', NET).isChecker, true);
  });

  it('rejects an unparseable cidr loudly at construction', () => {
    assert.throws(() => new NetworkMap([{ kind: 'checker', cidr: 'nonsense' }]));
  });

  it('strips a port from a v4 peer', () => {
    assert.equal(normaliseRemoteAddress('172.23.0.1:52344'), '172.23.0.1');
  });

  it('strips brackets from a v6 peer', () => {
    assert.equal(normaliseRemoteAddress('[fe80::1]:52344'), 'fe80::1');
  });

  it('leaves a bare v6 peer alone', () => {
    assert.equal(normaliseRemoteAddress('fe80::1'), 'fe80::1');
  });
});

describe('operator visibility', () => {
  it('describes every configured range', () => {
    const described = map().describe();
    assert.deepEqual(
      described.map((r) => `${r.kind} ${r.cidr}`),
      [
        'checker 10.77.0.9',
        'admin 10.0.0.1',
        'team 10.0.0.0/8',
        'team 10.1.2.0/24',
      ],
    );
  });

  it('describes the own flag on a range', () => {
    const m = new NetworkMap([{ kind: 'team', cidr: '10.1.2.0/28', team: 'alpha', own: true }]);
    assert.equal(m.describe()[0]?.own, true);
  });
});
