# AltayCoin — A/D analysis

Generated 2026-10-02T06:24:46+00:00 · 33 source files · 0 runtime records

> Operator note: NestJS + PostgreSQL. Local instance only; no checker source available.

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
| high | 2 |

| Category | Count |
| --- | ---: |
| AUTH_BYPASS | 1 |
| WEAK_CRYPTO | 1 |

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

### **HIGH**

#### AD-AUTH-002 · Unauthenticated GET table

- Category: `AUTH_BYPASS` · Confidence: `low` · CWE: CWE-306
- Evidence: `backend/src/users/users.controller.ts:16`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

The route declaration has no authentication decorator, middleware or session check in its surrounding lines, while the path points at per-user or global data.

- **Team exploit path**: Call the endpoint directly without any session or token.
- **Checker-breaking**: Usually none: checkers keep using authenticated endpoints, so teams read the data freely while scoring continues.
- **Fix**: Apply the same auth guard used by the neighbouring routes.

```
GET table
```

#### AD-CRYPTO-003 · Deterministic secret derived only from public data

- Category: `WEAK_CRYPTO` · Confidence: `high` · CWE: CWE-330, CWE-640
- Evidence: `backend/src/users/users.service.ts:279`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

Invites, slugs, dialog tokens or session keys computed from the login alone are guessable by anyone who knows the victim's username.

- **Team exploit path**: Recompute the value for a known username and use it.
- **Checker-breaking**: A predictable format is a prerequisite for the checker, which scrapes such values out of responses. Changing the format silently breaks the checker; leaking the value to teams does not.
- **Fix**: Issue unpredictable server-side random tokens.

```
or) { } const data = { "login": body.login, "password": createHash("sha256").update(body.pass).digest("hex"), "info": body.userinfo, "invitecode": createHash("sha256").update(body.login).digest("hex"), "inviter": body.invitecode, "level": 1, "coin": coin, "energy": { "energy": 1000, "energyGeneric": 5, "maxEnergy": 1000 }, "c
```

## Route inventory

12 routes extracted · 0 take an object id with no auth hint nearby

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
