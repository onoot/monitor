/**
 * Live check against the running gateway process.
 *
 * Unlike the in-process check, this talks to the real listeners on 9090 and
 * 8787 with the config as written, so it covers the pieces a unit test cannot:
 * the process staying up, the ports, the accounts from the config file, and the
 * loopback actors standing in for the emulated network.
 */

import http from 'node:http';
import process from 'node:process';

const INGRESS = 9090;
const ANALYTICS = 8787;
const HOST = 'curs.local';

const PASSWORDS: Record<string, string> = {
  ops: 'ops-local-admin-2026',
  alpha: 'alpha-local-2026',
  beta: 'beta-local-2026',
};

let failures = 0;
function check(name: string, ok: boolean, detail: string): void {
  if (!ok) failures += 1;
  process.stdout.write(`${ok ? 'PASS' : 'FAIL'}  ${name}\n        ${detail}\n`);
}

interface Result {
  status: number | null;
  body: string;
  error: string | null;
  headers: http.IncomingHttpHeaders;
}

function request(
  port: number,
  options: {
    path: string;
    host?: string;
    method?: string;
    body?: string;
    contentType?: string;
    auth?: string;
    localAddress?: string;
  },
): Promise<Result> {
  return new Promise((resolve) => {
    const headers: Record<string, string> = { host: options.host ?? HOST };
    if (options.body !== undefined) headers['content-type'] = options.contentType ?? 'application/x-www-form-urlencoded';
    if (options.auth !== undefined) headers.authorization = `Bearer ${options.auth}`;

    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: options.path,
        method: options.method ?? 'GET',
        headers,
        ...(options.localAddress === undefined ? {} : { localAddress: options.localAddress }),
        timeout: 8000,
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c: Buffer) => chunks.push(c));
        res.on('end', () =>
          resolve({
            status: res.statusCode ?? null,
            body: Buffer.concat(chunks).toString('utf8'),
            error: null,
            headers: res.headers,
          }),
        );
      },
    );
    req.on('error', (e: Error) => resolve({ status: null, body: '', error: e.code ?? e.message, headers: {} }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, body: '', error: 'TIMEOUT', headers: {} }); });
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

function dropped(r: Result): boolean {
  return r.status === null && (r.error === 'ECONNRESET' || r.error === 'ECONNREFUSED');
}

async function login(name: string): Promise<string | null> {
  const res = await new Promise<Result>((resolve) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port: ANALYTICS,
        path: '/api/login',
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        timeout: 8000,
      },
      (r) => {
        const c: Buffer[] = [];
        r.on('data', (b: Buffer) => c.push(b));
        r.on('end', () => resolve({ status: r.statusCode ?? null, body: Buffer.concat(c).toString('utf8'), error: null, headers: r.headers }));
      },
    );
    req.on('error', (e: Error) => resolve({ status: null, body: '', error: e.code ?? e.message, headers: {} }));
    req.on('timeout', () => { req.destroy(); resolve({ status: null, body: '', error: 'TIMEOUT', headers: {} }); });
    req.end(JSON.stringify({ login: name, password: PASSWORDS[name] ?? '' }));
  });
  if (res.status !== 200) return null;
  try {
    return (JSON.parse(res.body) as { token: string }).token;
  } catch {
    return null;
  }
}

process.stdout.write('--- ingress, from an address off the list ---\n');
const stranger = await request(INGRESS, { path: '/', host: 'curs.local' });
check('the operator address is allowed', stranger.status === 200, `status=${stranger.status} err=${stranger.error}`);

process.stdout.write('\n--- team traffic (127.0.0.3) ---\n');
const home = await request(INGRESS, { path: '/', localAddress: '127.0.0.3' });
check('team: ordinary request reaches the app', home.status === 200, `status=${home.status}`);

const git = await request(INGRESS, { path: '/.git/config', localAddress: '127.0.0.3' });
check('team: .git probe gets a dropped connection', dropped(git), `status=${git.status} err=${git.error}`);

const sqli = await request(INGRESS, { path: '/user/login', method: 'POST', body: "login=admin' or '1'='1", localAddress: '127.0.0.3' });
check('team: sql injection gets a dropped connection', dropped(sqli), `status=${sqli.status} err=${sqli.error}`);

const realLogin = await request(INGRESS, { path: '/user/login', method: 'POST', body: 'login=analyst&password=analyst123', localAddress: '127.0.0.3' });
check('team: a real login still works through the gateway', realLogin.status === 303 || realLogin.status === 200, `status=${realLogin.status}`);

process.stdout.write('\n--- checker traffic (127.0.0.9) ---\n');
const checkerGit = await request(INGRESS, { path: '/.git/config', localAddress: '127.0.0.9' });
check('checker: the payload that blocks a team passes', checkerGit.status !== null && checkerGit.status !== 403, `status=${checkerGit.status}`);
const checkerSqli = await request(INGRESS, { path: '/user/login', method: 'POST', body: "login=admin' or '1'='1", localAddress: '127.0.0.9' });
check('checker: injection passes', checkerSqli.status !== null, `status=${checkerSqli.status}`);

process.stdout.write('\n--- unlisted address ---\n');
const offList = await request(INGRESS, { path: '/', localAddress: '127.0.0.7' });
check('an address off the list is cut off', dropped(offList), `status=${offList.status} err=${offList.error}`);

process.stdout.write('\n--- routing ---\n');
const unknownHost = await request(INGRESS, { path: '/latest/meta-data/', host: '169.254.169.254' });
check('an undeclared host is not proxied anywhere', unknownHost.status === 404, `status=${unknownHost.status}`);

process.stdout.write('\n--- analytics surface ---\n');
const health = await request(ANALYTICS, { path: '/api/health', host: 'localhost' });
check('health is open', health.status === 200, `status=${health.status} body=${health.body.slice(0, 80)}`);

const noSession = await request(ANALYTICS, { path: '/api/history', host: 'localhost' });
check('no session means no data', noSession.status === 401, `status=${noSession.status}`);

const offListAnalytics = await request(ANALYTICS, { path: '/api/health', host: 'localhost', localAddress: '127.0.0.7' });
check('the analytics surface refuses an unlisted address', dropped(offListAnalytics), `status=${offListAnalytics.status} err=${offListAnalytics.error}`);

const opsToken = await login('ops');
check('admin can log in with the configured password', opsToken !== null, opsToken === null ? 'no token' : 'token issued');

const alphaToken = await login('alpha');
check('a team can log in', alphaToken !== null, alphaToken === null ? 'no token' : 'token issued');

const wrongPassword = await new Promise<number | null>((resolve) => {
  const req = http.request(
    { host: '127.0.0.1', port: ANALYTICS, path: '/api/login', method: 'POST', headers: { 'content-type': 'application/json' }, timeout: 8000 },
    (res) => { res.resume(); res.on('end', () => resolve(res.statusCode ?? null)); },
  );
  req.on('error', () => resolve(null));
  req.on('timeout', () => { req.destroy(); resolve(null); });
  req.end(JSON.stringify({ login: 'ops', password: 'not-the-password' }));
});
check('a wrong password is refused', wrongPassword === 401, `status=${wrongPassword}`);

if (opsToken !== null) {
  const me = await request(ANALYTICS, { path: '/api/me', host: 'localhost', auth: opsToken });
  check('the session identifies the admin', me.status === 200 && (JSON.parse(me.body) as { kind: string }).kind === 'admin', `body=${me.body}`);

  const history = await request(ANALYTICS, { path: '/api/history?limit=200', host: 'localhost', auth: opsToken });
  const attempts = (JSON.parse(history.body) as { attempts: Array<Record<string, unknown>> }).attempts;
  check('history captured the traffic', attempts.length > 0, `${attempts.length} attempts`);

  const principals = [...new Set(attempts.map((a) => String(a.principal)))].sort().join(',');
  check('checker traffic is attributed to the checker', attempts.some((a) => a.ip === '127.0.0.9' && a.principal === 'checker'), `principals=${principals}`);

  const teams = [...new Set(attempts.map((a) => String(a.team)).filter((t) => t !== 'null'))].sort().join(',');
  check('team traffic is attributed to its team', attempts.some((a) => a.team === 'beta'), `teams=${teams}`);

  check('blocked attempts are recorded with a reason', attempts.some((a) => a.outcome === 'blocked' && Array.isArray(a.rules) && (a.rules as string[]).length > 0), `outcomes=${[...new Set(attempts.map((a) => String(a.outcome)))].join(',')}`);
  check('the refused address is recorded for the operator to add', attempts.some((a) => a.outcome === 'refused' && a.ip === '127.0.0.7'), `refused=${attempts.filter((a) => a.outcome === 'refused').length}`);

  const candidates = await request(ANALYTICS, { path: '/api/candidates', host: 'localhost', auth: opsToken });
  const list = (JSON.parse(candidates.body) as { candidates: Array<{ ip: string }> }).candidates;
  check('the unlisted address is offered as a candidate', list.some((c) => c.ip === '127.0.0.7'), `candidates=${list.map((c) => c.ip).join(',')}`);

  const add = await request(ANALYTICS, {
    path: '/api/allowlist',
    method: 'POST',
    host: 'localhost',
    auth: opsToken,
    contentType: 'application/json',
    body: JSON.stringify({ ip: '127.0.0.7', kind: 'team', team: 'gamma' }),
  });
  check('an admin can add the address from the history', add.status === 200, `status=${add.status}`);

  const afterAdd = await request(INGRESS, { path: '/', localAddress: '127.0.0.7' });
  check('the newly added address now gets through', afterAdd.status === 200, `status=${afterAdd.status}`);

  const remove = await request(ANALYTICS, { path: '/api/allowlist?ip=127.0.0.7', method: 'DELETE', host: 'localhost', auth: opsToken });
  check('and can remove it again', remove.status === 200, `status=${remove.status}`);

  const afterRemove = await request(INGRESS, { path: '/', localAddress: '127.0.0.7' });
  check('the removed address is cut off again', dropped(afterRemove), `status=${afterRemove.status} err=${afterRemove.error}`);
}

if (alphaToken !== null) {
  const teamAdd = await request(ANALYTICS, {
    path: '/api/allowlist',
    method: 'POST',
    host: 'localhost',
    auth: alphaToken,
    contentType: 'application/json',
    body: JSON.stringify({ ip: '127.0.0.8', kind: 'team', team: 'alpha' }),
  });
  check('a team cannot change the allowlist', teamAdd.status === 403, `status=${teamAdd.status}`);
}

process.stdout.write(`\n${failures === 0 ? 'ALL LIVE CHECKS PASSED' : `${failures} LIVE CHECK(S) FAILED`}\n`);
process.exit(failures === 0 ? 0 : 1);
