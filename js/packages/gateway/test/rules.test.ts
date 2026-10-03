/**
 * Attack signatures.
 *
 * Both directions are pinned. A rule that fires on ordinary traffic costs the
 * operator real participants' requests, and a rule that misses a disguised probe
 * is worse than no rule at all, so the negative cases carry as much weight here as
 * the positive ones.
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { detect, fullyDecode, shouldBlock, type RuleContext, type RuleHit } from '../src/rules.js';

const OPTIONS = { rateLimitPerSecond: 20, rateBurst: 60 };

function ctx(over: Partial<RuleContext> = {}): RuleContext {
  return {
    method: 'GET',
    path: '/',
    query: '',
    body: '',
    headers: {},
    remoteIp: '10.1.2.3',
    now: 1_760_000_000_000,
    perSecond: 1,
    peakPerSecond: 1,
    ...over,
  };
}

function ids(over: Partial<RuleContext> = {}): string[] {
  return detect(ctx(over), OPTIONS).hits.map((h) => h.id);
}

describe('decoding', () => {
  it('unwraps a single layer', () => {
    assert.equal(fullyDecode('/a%20b'), '/a b');
  });

  it('unwraps two layers so double encoding does not hide', () => {
    assert.equal(fullyDecode('%252e%252e%252f'), '../');
  });

  it('survives a malformed escape instead of throwing', () => {
    assert.equal(fullyDecode('%zz'), '%zz');
  });
});

describe('sql injection', () => {
  it('catches a union select in the query', () => {
    assert.ok(ids({ path: '/items', query: 'id=1 union select 1,2,3' }).some((i) => i.startsWith('sqli')));
  });

  it('catches a tautology', () => {
    assert.ok(ids({ path: '/login', query: "user=admin' or '1'='1" }).some((i) => i.startsWith('sqli')));
  });

  it('catches a stacked query', () => {
    assert.ok(ids({ path: '/x', query: 'a=1; drop table users' }).some((i) => i.startsWith('sqli')));
  });

  it('catches a time-based probe', () => {
    assert.ok(ids({ path: '/x', query: 'id=1 and sleep(5)' }).some((i) => i.startsWith('sqli')));
  });

  it('catches an injection in a post body', () => {
    assert.ok(ids({ method: 'POST', path: '/login', body: "login=admin'--&password=x" }).some((i) => i.startsWith('sqli-body')));
  });

  it('sees through a percent-encoded payload', () => {
    assert.ok(
      ids({ path: '/x', query: 'id=1%20union%20select%201' }).some((i) => i.startsWith('sqli')),
    );
  });

  it('sees through a double-encoded payload', () => {
    assert.ok(
      ids({ path: '/x', query: 'id=1%2520union%2520select%25201' }).some((i) => i.startsWith('sqli')),
    );
  });

  it('does not fire on an ordinary numeric id', () => {
    assert.deepEqual(ids({ path: '/items', query: 'id=42&page=2' }), []);
  });

  it('does not fire on a search for the word select in a help page', () => {
    assert.deepEqual(ids({ path: '/docs', query: 'q=how+to+select+a+row' }), []);
  });
});

describe('command injection', () => {
  it('catches a chained command', () => {
    assert.ok(ids({ path: '/x', query: 'host=127.0.0.1;whoami' }).some((i) => i.startsWith('cmdi')));
  });

  it('catches command substitution', () => {
    assert.ok(ids({ path: '/x', query: 'h=$(id)' }).some((i) => i.startsWith('cmdi')));
  });

  it('catches a pipe to a shell', () => {
    assert.ok(ids({ path: '/x', query: 'h=|sh' }).some((i) => i.startsWith('cmdi')));
  });

  it('does not fire on a normal value', () => {
    assert.deepEqual(ids({ path: '/x', query: 'name=Alice' }), []);
  });
});

describe('exposure probes', () => {
  const cases: Array<[string, string]> = [
    ['/.git/config', 'git metadata directory'],
    ['/.git/HEAD', 'git metadata directory'],
    ['/.env', 'dotenv file'],
    ['/.aws/credentials', 'aws credentials'],
    ['/app/.env.production', 'dotenv file'],
    ['/private/keys', 'private path segment'],
    ['/internal/status', 'private path segment'],
    ['/backup.sql', 'backup or archive file'],
    ['/config.php.bak', 'editor backup file'],
    ['/actuator/env', 'spring actuator endpoint'],
    ['/server.key', 'private key file'],
    ['/WEB-INF/web.xml', 'java deployment descriptor'],
  ];

  for (const [target, reason] of cases) {
    it(`flags ${target} as ${reason}`, () => {
      const result = detect(ctx({ path: target }), OPTIONS);
      const hit = result.hits.find((h) => h.category === 'exposure');
      assert.ok(hit, `expected an exposure hit for ${target}`);
      assert.equal(hit.reason, reason);
    });
  }

  it('blocks an exposure probe outright', () => {
    assert.equal(detect(ctx({ path: '/.git/config' }), OPTIONS).block, true);
  });

  it('catches a traversal-encoded dot git', () => {
    assert.ok(ids({ path: '/x', query: 'p=..%2f.git%2fconfig' }).length > 0);
  });

  it('catches a path traversal to /etc/passwd', () => {
    assert.ok(ids({ path: '/../../etc/passwd' }).some((i) => i === 'traversal'));
  });

  it('does not flag a normal api path that merely mentions config', () => {
    assert.deepEqual(ids({ path: '/api/v1/config' }), []);
  });

  it('does not flag an ordinary json response path', () => {
    assert.deepEqual(ids({ path: '/users/1/profile' }), []);
  });
});

describe('denial of service', () => {
  it('flags a sustained rate above the limit', () => {
    const result = detect(ctx({ perSecond: 45 }), OPTIONS);
    assert.ok(result.hits.some((h) => h.id === 'dos-rate'));
  });

  it('flags a single-second burst above the burst limit', () => {
    const result = detect(ctx({ peakPerSecond: 200 }), OPTIONS);
    assert.ok(result.hits.some((h) => h.id === 'dos-burst'));
  });

  it('blocks a rate flood', () => {
    assert.equal(detect(ctx({ perSecond: 45 }), OPTIONS).block, true);
  });

  it('leaves a normal rate alone', () => {
    assert.deepEqual(ids({ perSecond: 3, peakPerSecond: 8 }), []);
  });
});

describe('blocking policy', () => {
  const hit = (over: Partial<{ id: string; category: RuleHit['category']; severity: RuleHit['severity'] }>): RuleHit => ({
    id: over.id ?? 'x',
    category: over.category ?? 'injection',
    severity: over.severity ?? 'low',
    reason: '',
    where: 'query',
  });

  it('blocks nothing when nothing fired', () => {
    assert.equal(shouldBlock([]), false);
  });

  it('lets a lone low-signal match through so it can be studied', () => {
    assert.equal(shouldBlock([hit({ category: 'injection', severity: 'low' })]), false);
  });

  it('lets a lone medium protocol match through', () => {
    assert.equal(shouldBlock([hit({ category: 'protocol', severity: 'medium' })]), false);
  });

  it('blocks on any critical hit', () => {
    assert.equal(shouldBlock([hit({ severity: 'critical' })]), true);
  });

  it('blocks on a rate hit, because the threshold is operator-set', () => {
    assert.equal(shouldBlock([hit({ category: 'dos', severity: 'medium' })]), true);
  });

  it('blocks on a high-severity exposure probe', () => {
    assert.equal(shouldBlock([hit({ category: 'exposure', severity: 'high' })]), true);
  });

  it('blocks on two hits in the same category', () => {
    assert.equal(
      shouldBlock([
        hit({ category: 'injection', severity: 'low' }),
        hit({ category: 'injection', severity: 'low' }),
      ]),
      true,
    );
  });

  it('does not block on two unrelated low hits', () => {
    assert.equal(
      shouldBlock([
        hit({ category: 'injection', severity: 'low' }),
        hit({ category: 'protocol', severity: 'low' }),
      ]),
      false,
    );
  });
});
