# curs — A/D analysis

Generated 2026-10-02T06:24:46+00:00 · 12 source files · 16 runtime records

> Operator note: Go + Gin + MySQL. Local instance only; no checker source available.

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
| critical | 2 |
| high | 1 |

| Category | Count |
| --- | ---: |
| WEAK_CRYPTO | 1 |
| SQLI | 1 |
| AUTH_BYPASS | 1 |

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

#### AD-CRYPTO-004 · Password persisted without a hash

- Category: `WEAK_CRYPTO` · Confidence: `high` · CWE: CWE-256, CWE-312
- Evidence: `app/routing.go:77`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

`insertUser()` writes a password column with no hashing call in scope. Anyone who reaches the datastore - directly, via SQLi or via traversal - reads every team's plaintext credentials.

- **Team exploit path**: Reach the datastore, dump the table, log in as any team.
- **Checker-breaking**: None for the checker, which uses correct credentials. But combined with any read primitive this is a total compromise of the instance.
- **Fix**: Hash with bcrypt/argon2/scrypt and a per-user salt before storing.

```
func insertUser(c *gin.Context) { login := c.PostForm("login") password := c.PostForm("password") var existingUser User err := db.QueryRow("SELECT login FROM users WHERE login = ?", login).Scan(&existingUser.Login) if err == nil { renderMessage(c, "register.html", http.StatusConflict, "error", fmt.Sprintf("Логин '%s' уже существует.", login), nil) return } else if err != sql.ErrNoRows { renderMessage(c, "register.html", http.StatusInternalServerError, "error", fmt.Sprintf("Ошибка проверки сущест
```

#### AD-SQL-001 · SQL statement built by string formatting or concatenation

- Category: `SQLI` · Confidence: `high` · CWE: CWE-89
- Evidence: `app/routing.go:125`
- Pattern source: corpus:altayctf-2019, local:AltayCoin/Curs/Magiclib/Omnyhub

The statement is assembled from runtime values instead of bound parameters, so a team can read or rewrite any row.

- **Team exploit path**: Boolean, UNION or time based injection in the interpolated value.
- **Checker-breaking**: One malformed request from any participant can raise a fatal driver error and the instance stops scoring (IV.5).
- **Fix**: Use parameterised queries exclusively; never interpolate.

```
gister.html", http.StatusOK, "success", "Пользователь успешно создан", nil) } func loginUser(c *gin.Context, db *sql.DB) { login := c.PostForm("login") password := c.PostForm("password") var user User query := fmt.Sprintf("SELECT id, login, password, role FROM users WHERE login = '%s' AND password = '%s'", login, password) err := db.QueryRow(query).Scan(&user.Id, &user.Login, &user.Password, &user.Role) if err != nil { if err == sql.ErrNoRow
```

### **HIGH**

#### AD-AUTH-002 · Unauthenticated GET /dashboard

- Category: `AUTH_BYPASS` · Confidence: `low` · CWE: CWE-306
- Evidence: `app/main.go:38`
- Pattern source: local:AltayCoin/Curs/Magiclib/Omnyhub

The route declaration has no authentication decorator, middleware or session check in its surrounding lines, while the path points at per-user or global data.

- **Team exploit path**: Call the endpoint directly without any session or token.
- **Checker-breaking**: Usually none: checkers keep using authenticated endpoints, so teams read the data freely while scoring continues.
- **Fix**: Apply the same auth guard used by the neighbouring routes.

```
GET /dashboard
```

## Route inventory

7 routes extracted · 0 take an object id with no auth hint nearby

## Runtime traffic

| Actor | Requests | Distinct routes | Flag reads | Flag writes | IPs |
| --- | ---: | ---: | ---: | ---: | --- |
| unknown | 16 | 7 | 0 | 0 | `172.23.0.1` |

Full request/response detail: `requests.csv`, `requests.md`.

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
