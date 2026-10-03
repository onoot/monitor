# Omnyhub — A/D analysis

Generated 2026-10-02T06:24:45+00:00 · 33 source files · 0 runtime records

> Operator note: Express + MongoDB. Local instance only; no checker source available.

## Read this first

- flag_format.pattern is not set: flag put/get cannot be verified and poisoning is disabled.
- No team_networks configured. Runtime IPs will classify as 'unknown' and are never poisoned.
- No checker_networks or checker_ip_pattern configured. Checker traffic cannot be identified; treat all traffic as team traffic for reporting only, never for poisoning.
- No flag pattern configured. Flag put/get verification is unavailable and poisoning stays disabled. Set flag_format.pattern (xeger syntax) or known_flags in the service config.
- No flag write path identified in source; confirm the put flow manually.
- No flag read path identified in source; confirm the get flow manually.

## Summary

| Severity | Count |
| --- | ---: |
| critical | 5 |
| high | 2 |
| medium | 2 |

| Category | Count |
| --- | ---: |
| CRYPTOGRAPHY | 2 |
| AUTH_BYPASS | 2 |
| JWT_VERIFY_MISSING | 1 |
| PRIVILEGE_ESCALATION | 1 |
| SQLI | 1 |
| CHECKER_BREAKING | 1 |
| INFO_LEAK | 1 |

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

#### AD-JWT-001 · JWT decoded without verifying the signature

- Category: `JWT_VERIFY_MISSING` · Confidence: `medium` · CWE: CWE-347, CWE-345
- Evidence: `backend/Public/js/utils/chekAuth.js:14`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

decode() only base64-parses the payload. Any team can mint an admin token without knowing the signing key.

- **Team exploit path**: Craft a token with an elevated claim and replay it.
- **Checker-breaking**: None.
- **Fix**: Call verify() with the algorithm pinned explicitly.

```
authorization || '').replace(/Bearer\s?/, ''); if (!token) { return res.status(403).json({ message: 'Нет доступа' }); } try { // текущая логика: без подписи (decode) const decoded = jwt.decode(token); if (!decoded) { return res.status(403).json({ message: 'Нет доступа' }); } let userId = decoded._id; // Обратная совместимость: если _id не ObjectId, считаем, что это
```

#### AD-JWT-002 · Hardcoded JWT signing secret in the repository

- Category: `CRYPTOGRAPHY` · Confidence: `high` · CWE: CWE-798, CWE-321
- Evidence: `backend/Public/js/Controllers/UserControllers.js:134`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

A literal signing secret is embedded in the code, so it is identical for every deployment and readable by anyone with the source.

- **Team exploit path**: Sign arbitrary tokens offline with the leaked secret. Every token forged this way passes verification, including admin claims.
- **Checker-breaking**: None. Checkers present genuine tokens, so scoring is unaffected while teams mint valid identities for any user.
- **Fix**: Load the secret from the environment, rotate it, and reject tokens signed with anything but the current secret.

```
equest = false; try { const authHeader = req.headers.authorization || ''; const rawToken = authHeader.replace(/Bearer\s?/, ''); if (rawToken) { const decoded = jwt.decode(rawToken, 'secret123'); if (decoded && decoded.isAdmin) { isAdminRequest = true; } } } catch (_) { } const projection = isAdminRequest ? '-passwordHash'
```

#### AD-JWT-002 · Hardcoded JWT signing secret in the repository

- Category: `CRYPTOGRAPHY` · Confidence: `high` · CWE: CWE-798, CWE-321
- Evidence: `backend/Public/js/Controllers/UserControllers.js:162`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

A literal signing secret is embedded in the code, so it is identical for every deployment and readable by anyone with the source.

- **Team exploit path**: Sign arbitrary tokens offline with the leaked secret. Every token forged this way passes verification, including admin claims.
- **Checker-breaking**: None. Checkers present genuine tokens, so scoring is unaffected while teams mint valid identities for any user.
- **Fix**: Load the secret from the environment, rotate it, and reject tokens signed with anything but the current secret.

```
equest = false; try { const authHeader = req.headers.authorization || ''; const rawToken = authHeader.replace(/Bearer\s?/, ''); if (rawToken) { const decoded = jwt.verify(rawToken, 'secret123'); if (decoded && decoded.isAdmin) { isAdminRequest = true; } } } catch (_) {} const projection = isAdminRequest ? '-passwordHash' : '-pass
```

#### AD-PRIV-004 · Privilege flag copied straight out of an unverified token

- Category: `PRIVILEGE_ESCALATION` · Confidence: `medium` · CWE: CWE-863, CWE-345
- Evidence: `backend/Public/js/utils/chekAuth.js:30`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

An administrative flag is taken from the request's own token payload. Combined with a decode-only token check this is a full account takeover primitive: no secret is needed, only the ability to base64 a claim.

- **Team exploit path**: Take any valid token, edit the isAdmin/role claim, re-base64 the payload and replay the request with the forged token.
- **Checker-breaking**: None. The checker uses tokens minted by the service, so it keeps working while teams escalate freely.
- **Fix**: Verify the signature and read privileges from the server-side user record, never from client-supplied token contents.

```
tatus(401).json({ message: 'Нет доступа' }); } req.userId = user._id.toString(); req.isAdmin = Boolean(user.isAdmin); } else { req.userId = userId; req.isAdmin = Boolean(decoded.isAdmin); } return next(); } catch (err) { return res.status(403).json({ message: 'Нет доступа' }); } };
```

#### AD-SQL-001 · SQL statement built by string formatting or concatenation

- Category: `SQLI` · Confidence: `high` · CWE: CWE-89
- Evidence: `backend/Public/js/Controllers/PostConroller.js:110`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

The statement is assembled from runtime values instead of bound parameters, so a team can read or rewrite any row.

- **Team exploit path**: Boolean, UNION or time based injection in the interpolated value.
- **Checker-breaking**: One malformed request from any participant can raise a fatal driver error and the instance stops scoring (IV.5).
- **Fix**: Use parameterised queries exclusively; never interpolate.

```
или нет прав' }); } res.json({ success: true, }); } catch (err) { console.error(err); return res.status(500).json({ message: 'Не удалось удалить статью', }); } }; export const update = async(req,res)=>{ try { const postId = req.params.id; const result = await PostModel.updateOne({ _id: postId, user: req.userId, },{ title: req.body.title, text: req.body.text, imageURL: req.body.ima
```

### **HIGH**

#### AD-AUTH-005 · Optional authentication: the permission flag defaults to permissive

- Category: `AUTH_BYPASS` · Confidence: `high` · CWE: CWE-287, CWE-636
- Evidence: `backend/Public/js/Controllers/UserControllers.js:129`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

The handler starts with the permissive value and only upgrades to the restrictive one when a valid token happens to be present. A request without any credential therefore proceeds down the privileged path instead of being rejected.

- **Team exploit path**: Send the request with no Authorization header. The flag stays at its default and the response is still produced.
- **Checker-breaking**: Usually none: checkers authenticate properly, so the permissive default only affects teams.
- **Fix**: Fail closed: return 401/403 unless the credential validated, and compute the permission once instead of defaulting it.

```
[ { fullName: regex }, { email: regex }, ]; } } // Определяем, является ли запрос от администратора (по токену, если он есть) let isAdminRequest = false; try { const authHeader = req.headers.authorization || ''; const rawToken = authHeader.replace(/Bearer\s?/, ''); if (rawToken) { const decoded = jwt.decode(rawToken, 'secret123'); if (decoded && decoded.isAdmin) { isAdminRequest = true; } } } catch (_) { } const projection = isAdminRequest ? '-passwordHash' : '-passwordHash -cardNumber'; const u
```

#### AD-AUTH-005 · Optional authentication: the permission flag defaults to permissive

- Category: `AUTH_BYPASS` · Confidence: `high` · CWE: CWE-287, CWE-636
- Evidence: `backend/Public/js/Controllers/UserControllers.js:157`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

The handler starts with the permissive value and only upgrades to the restrictive one when a valid token happens to be present. A request without any credential therefore proceeds down the privileged path instead of being rejected.

- **Team exploit path**: Send the request with no Authorization header. The flag stays at its default and the response is still produced.
- **Checker-breaking**: Usually none: checkers authenticate properly, so the permissive default only affects teams.
- **Fix**: Fail closed: return 401/403 unless the credential validated, and compute the permission once instead of defaulting it.

```
log(err); res.status(500).json({ message: 'Не удалось получить пользователей', }); } }; export const getById = async (req, res) => { try { const { id } = req.params; let isAdminRequest = false; try { const authHeader = req.headers.authorization || ''; const rawToken = authHeader.replace(/Bearer\s?/, ''); if (rawToken) { const decoded = jwt.verify(rawToken, 'secret123'); if (decoded && decoded.isAdmin) { isAdminRequest = true; } } } catch (_) {} const projection = isAdminRequest ? '-passwordHash'
```

### **MEDIUM**

#### AD-CHK-005 · Registration-time uniqueness constraint on a per-round value

- Category: `CHECKER_BREAKING` · Confidence: `high` · CWE: CWE-1023
- Evidence: `backend/Public/js/models/Users.js:11`
- Pattern source: corpus:AltayCTF-2018 checkers

If a checker-visible unique field collides between rounds (fixed login, fixed email, fixed slug) the second round cannot register.

- **Team exploit path**: N/A - jury-side.
- **Checker-breaking**: YES. Round N+1 registration fails outright.
- **Fix**: Make the checker's random values part of the uniqueness scope.

```
import mongoose from 'mongoose' const UserSchema = new mongoose.Schema({ fullName:{ type: String, required: true, }, email:{ type: String, required: true, unique: true, }, passwordHash:{ type:String, required: true, }, avatarURL:String, cardNumber: { type: String, default: '', }, isAdmin: { type: Boolean, defa
```

#### AD-LEAK-002 · Wildcard CORS on a state-changing or authenticated endpoint

- Category: `INFO_LEAK` · Confidence: `high` · CWE: CWE-942
- Evidence: `backend/Public/js/index.js:29`
- Pattern source: corpus:altayctf-2019

Any origin may drive authenticated requests, widening cross-team attack surface.

- **Team exploit path**: Host a page that calls the instance with the victim's cookies.
- **Checker-breaking**: None.
- **Fix**: Reflect only trusted origins.

```
.log('✅ DB super - успешное подключение к MongoDB')) .catch((err) => console.log('❌ DB ne super - ошибка подключения:', err)); const app = express(); // Разрешаем CORS app.use((req, res, next) => { res.header('Access-Control-Allow-Origin', '*'); res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization'); res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH'); if (req.metho
```

## Route inventory

13 routes extracted · 1 take an object id with no auth hint nearby

| Method | Path | Location |
| --- | --- | --- |
| GET | `/users/:id` | `backend/Public/js/index.js:78` |

These are candidates only: confirm at runtime before reporting as IDOR.

## Runtime traffic

No request logs configured. Add `request_logs` to the service config.

## Flag flow

- Pattern source: `unconfirmed_heuristic` (known: False)
- Put candidates: 0 · Get candidates: 0

See `flagflow.md` for the full walkthrough.

## Flag poisoning policy

- Enabled: **False**
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
