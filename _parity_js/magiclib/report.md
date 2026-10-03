# magiclib — A/D analysis

Generated 2026-10-02T06:24:46+00:00 · 17 source files · 0 runtime records

> Operator note: Flask + PostgreSQL. Local instance only; no checker source available.

## Read this first

- flag_format.pattern is not set: flag put/get cannot be verified and poisoning is disabled.
- No team_networks configured. Runtime IPs will classify as 'unknown' and are never poisoned.
- No checker_networks or checker_ip_pattern configured. Checker traffic cannot be identified; treat all traffic as team traffic for reporting only, never for poisoning.
- No flag pattern configured. Flag put/get verification is unavailable and poisoning stays disabled. Set flagFormat.pattern (xeger syntax) or knownFlags in the service config.
- No flag write path identified in source; confirm the put flow manually.
- No flag read path identified in source; confirm the get flow manually.

## Summary

| Severity | Count |
| --- | ---: |
| critical | 3 |
| high | 5 |
| medium | 1 |
| low | 3 |

| Category | Count |
| --- | ---: |
| INFO_LEAK | 4 |
| AUTH_BYPASS | 3 |
| WEAK_CRYPTO | 2 |
| RATE_LIMIT_MISSING | 2 |
| OPEN_REDIRECT | 1 |

## Instance topology

- Checker `IP_PATTERN` not found in source. Ask the operator; do not assume a default.

| Network role | CIDR | Source |
| --- | --- | --- |
| _none configured_ | | |

## Checker lifecycle (expected traffic)

| Phase | Expected actor | Description |
| --- | --- | --- |
| index | checker | Service availability probe |
| register | checker | Account / entity creation (flag is planted here or later) |
| auth | checker | Login with previously stored credentials |
| operate | both | Normal functional read/write operations |
| put | checker | This round's flag written into the service |
| get_old | checker | Previous round's flag read back |

## Findings

### **CRITICAL**

#### AD-AUTH-001 · Credential read from the request and never verified

- Category: `AUTH_BYPASS` · Confidence: `high` · CWE: CWE-287, CWE-308
- Evidence: `magicapp/routes.py:75`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

`password` is populated from the submitted `password` field in `login_post()` and is never compared, hashed or looked up. Authentication therefore succeeds for any password.

- **Team exploit path**: Log in as any existing username with an arbitrary password. The instance grants `login_post()`'s full session.
- **Checker-breaking**: None. The checker authenticates with its real credentials, so this invisible to scoring and must be found by review.
- **Fix**: Verify the submitted credential against a stored hash.

```
def login_post(): if 'logged' in session and session['logged']: return redirect(url_for('startscreen')) username = request.form.get('username') password = request.form.get('password') user = db.get_user_by_name(username) if user: user_id = user[0] session['user_id'] = user_id session['logged'] = True session['username'] = user[1] next_page = request.args.get('next') if next_page: return redirect(next_page) return redirect(url_for('startscreen')) return redirect(url_for('login', err=1)) @app.rout
```

#### AD-CRYPTO-004 · Password persisted without a hash

- Category: `WEAK_CRYPTO` · Confidence: `high` · CWE: CWE-256, CWE-312
- Evidence: `magicapp/routes.py:47`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

`register_post()` writes a password column with no hashing call in scope. Anyone who reaches the datastore - directly, via SQLi or via traversal - reads every team's plaintext credentials.

- **Team exploit path**: Reach the datastore, dump the table, log in as any team.
- **Checker-breaking**: None for the checker, which uses correct credentials. But combined with any read primitive this is a total compromise of the instance.
- **Fix**: Hash with bcrypt/argon2/scrypt and a per-user salt before storing.

```
def register_post(): if 'logged' in session and session['logged']: return redirect(url_for('startscreen')) username = request.form.get('username') password = request.form.get('password') magic_word = request.form.get('magicword') if db.get_user_by_name(username) != None: return redirect(url_for('register', err=1)) user_id = db.insert_user(username, password, magic_word) if user_id: if isinstance(user_id, tuple): user_id = user_id[0] session['user_id'] = user_id session['logged'] = True session['
```

#### AD-CRYPTO-004 · Password persisted without a hash

- Category: `WEAK_CRYPTO` · Confidence: `high` · CWE: CWE-256, CWE-312
- Evidence: `magicapp/sql.py:54`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

`insert_user()` writes a password column with no hashing call in scope. Anyone who reaches the datastore - directly, via SQLi or via traversal - reads every team's plaintext credentials.

- **Team exploit path**: Reach the datastore, dump the table, log in as any team.
- **Checker-breaking**: None for the checker, which uses correct credentials. But combined with any read primitive this is a total compromise of the instance.
- **Fix**: Hash with bcrypt/argon2/scrypt and a per-user salt before storing.

```
def insert_user(self, username, password, magicword): results = None with self.conn.cursor() as cursor: cursor.execute("INSERT INTO magic (username, password, magicword) VALUES (%s, %s, %s) RETURNING id", (username, password, magicword )) results = cursor.fetchone()[0] return results
```

### **HIGH**

#### AD-AUTH-003 · Session/cookie store key hardcoded

- Category: `AUTH_BYPASS` · Confidence: `medium` · CWE: CWE-798, CWE-347
- Evidence: `config.py:9`
- Pattern source: corpus:altayctf-2019

A static signing key lets a team forge session cookies for arbitrary user ids, escalating privileges across the whole instance.

- **Team exploit path**: Forge a session cookie carrying another user's id.
- **Checker-breaking**: None for the checker, which uses real credentials.
- **Fix**: Load the secret from the environment, rotate per deployment.

```
import os from dotenv import load_dotenv basedir = os.path.abspath(os.path.dirname(__file__)) load_dotenv(os.path.join(basedir, '.env')) class Config(object): SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess' POSTGRES_CONNECT = os.environ.get('POSTGRES_CONNECT') or 'lol' SESSION_PERMANENT = False SESSION_TYPE = 'filesystem'
```

#### AD-AUTH-003 · Session/cookie store key hardcoded

- Category: `AUTH_BYPASS` · Confidence: `medium` · CWE: CWE-798, CWE-347
- Evidence: `magicapp/config.py:9`
- Pattern source: corpus:altayctf-2019

A static signing key lets a team forge session cookies for arbitrary user ids, escalating privileges across the whole instance.

- **Team exploit path**: Forge a session cookie carrying another user's id.
- **Checker-breaking**: None for the checker, which uses real credentials.
- **Fix**: Load the secret from the environment, rotate per deployment.

```
import os from dotenv import load_dotenv basedir = os.path.abspath(os.path.dirname(__file__)) load_dotenv(os.path.join(basedir, '.env')) class Config(object): SECRET_KEY = os.environ.get('SECRET_KEY') or 'you-will-never-guess' POSTGRES_CONNECT = os.environ.get('POSTGRES_CONNECT') or 'lol' SESSION_PERMANENT = False SESSION_TYPE = 'filesystem'
```

#### AD-LEAK-003 · Unscoped SELECT * returns credential-bearing rows

- Category: `INFO_LEAK` · Confidence: `medium` · CWE: CWE-200
- Evidence: `magicapp/sql.py:27`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

A listing endpoint without scoping hands over the whole user table in one request.

- **Team exploit path**: GET the listing and enumerate every team's data.
- **Checker-breaking**: Large result sets can time the instance out.
- **Fix**: Paginate and scope listings to the caller.

```
self.conn.cursor() as cursor: cursor.execute(open("magicapp/schema.sql", "r").read()) def get_all_users(self): results = [] with self.conn.cursor() as cursor: cursor.execute("SELECT * FROM magic") results = cursor.fetchall() if results == [] or results[0] == []: results = None return results def get_user_by_id(self, userid): try: with self.c
```

#### AD-LEAK-003 · Unscoped SELECT * returns credential-bearing rows

- Category: `INFO_LEAK` · Confidence: `medium` · CWE: CWE-200
- Evidence: `magicapp/sql.py:36`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

A listing endpoint without scoping hands over the whole user table in one request.

- **Team exploit path**: GET the listing and enumerate every team's data.
- **Checker-breaking**: Large result sets can time the instance out.
- **Fix**: Paginate and scope listings to the caller.

```
if results == [] or results[0] == []: results = None return results def get_user_by_id(self, userid): try: with self.conn.cursor() as cursor: cursor.execute("SELECT * FROM magic WHERE id = %s", (userid,)) result = cursor.fetchone() return result except Exception as e: logger.error(f"Error getting user by id {userid}: {e}") return
```

#### AD-LEAK-003 · Unscoped SELECT * returns credential-bearing rows

- Category: `INFO_LEAK` · Confidence: `high` · CWE: CWE-200
- Evidence: `magicapp/sql.py:46`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

A listing endpoint without scoping hands over the whole user table in one request.

- **Team exploit path**: GET the listing and enumerate every team's data.
- **Checker-breaking**: Large result sets can time the instance out.
- **Fix**: Paginate and scope listings to the caller.

```
logger.error(f"Error getting user by id {userid}: {e}") return None def get_user_by_name(self, username): try: with self.conn.cursor() as cursor: cursor.execute("SELECT * FROM magic WHERE username = %s", (username,)) result = cursor.fetchone() app.logger.debug(f"DB query result for {username}: {result}") return result # Возвращает кортеж или None
```

### **MEDIUM**

#### AD-LEAK-001 · Debug flag or verbose error surface enabled

- Category: `INFO_LEAK` · Confidence: `medium` · CWE: CWE-209
- Evidence: `run.py:4`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

Stack traces and SQL fragments leak schema, paths and sometimes credentials.

- **Team exploit path**: Send malformed input and read the error body.
- **Checker-breaking**: None.
- **Fix**: Disable debug output in deployed configuration.

```
from magicapp import app if __name__ == '__main__': app.run(debug=True, host='0.0.0.0', port=1337)
```

### **LOW**

#### AD-GEN-001 · No rate limiting / lockout on an authentication endpoint

- Category: `RATE_LIMIT_MISSING` · Confidence: `high` · CWE: CWE-307
- Evidence: `magicapp/routes.py:64`
- Pattern source: corpus:altayctf-2019

Allows credential stuffing against the checker-generated accounts.

- **Team exploit path**: Brute-force the checker's random username/password pair.
- **Checker-breaking**: Brute force can lock the instance out of its own account.
- **Fix**: Throttle per source address; do not permanently lock.

```
isinstance(user_id, tuple): user_id = user_id[0] session['user_id'] = user_id session['logged'] = True session['username'] = username return redirect(url_for('startscreen')) @app.route('/login', methods=['GET']) def login(): if 'logged' in session and session['logged']: return redirect(url_for('index')) return render_template('auth.html', err=request.args.get('err')) @app.route('/login', meth
```

#### AD-GEN-001 · No rate limiting / lockout on an authentication endpoint

- Category: `RATE_LIMIT_MISSING` · Confidence: `high` · CWE: CWE-307
- Evidence: `magicapp/routes.py:70`
- Pattern source: corpus:altayctf-2019

Allows credential stuffing against the checker-generated accounts.

- **Team exploit path**: Brute-force the checker's random username/password pair.
- **Checker-breaking**: Brute force can lock the instance out of its own account.
- **Fix**: Throttle per source address; do not permanently lock.

```
en')) @app.route('/login', methods=['GET']) def login(): if 'logged' in session and session['logged']: return redirect(url_for('index')) return render_template('auth.html', err=request.args.get('err')) @app.route('/login', methods=['POST']) def login_post(): if 'logged' in session and session['logged']: return redirect(url_for('startscreen')) username = request.form.get('username') password = request.form.get('passwo
```

#### AD-GEN-002 · Redirect target taken from the request

- Category: `OPEN_REDIRECT` · Confidence: `high` · CWE: CWE-601
- Evidence: `magicapp/routes.py:1`
- Pattern source: corpus:altayctf-2019

Phishing/credential-relay primitive; mostly noise for A/D but worth listing.

- **Team exploit path**: Craft a link that bounces participants to an attacker page.
- **Checker-breaking**: None.
- **Fix**: Validate redirect targets against an allow-list.

```
from flask import session, render_template, url_for, redirect, request, render_template_string, make_response, send_file, flash, jsonify from magicapp import app, db from flask_session import Session import json import base64 from itertools import cycle from functools import wraps def log
```

## Route inventory

10 routes extracted · 0 take an object id with no auth hint nearby

## Runtime traffic

No request logs configured. Add `request_logs` to the service config.

## Flag flow

- Pattern source: `unconfirmed_heuristic` (known: false)
- Put candidates: 0 · Get candidates: 0

See `flagflow.md` for the full walkthrough.

## Flag poisoning policy

- Enabled: **false**
- Checker traffic: never modify
- Unclassified traffic: never modify
- Team traffic: disabled: no private key available
- Requires: flag_format.pattern in the service config and AD_POISON_SECRET
- **Not available:** AD_POISON_SECRET is not set; refusing to derive the poisoning key from service data. Export a private secret before generating plans.

## Files in this directory

- `report.md` — this document
- `report.json` — full machine-readable report; start here when feeding an agent
- `findings.json` — static findings only
- `findings.csv` — static findings, spreadsheet-friendly
- `requests.csv` — every observed request with bodies and flag hits
- `requests.md` — human-readable request digest
- `flagflow.md` — put/get inference walkthrough
- `poison.json` — poisoning policy and parameters
- `run.json` — run metadata
