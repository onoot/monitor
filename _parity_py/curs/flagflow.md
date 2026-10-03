# curs — flag flow

- Pattern source: `unconfirmed_heuristic`
- Pattern confirmed: False

## Warnings

- No flag pattern configured. Flag put/get verification is unavailable and poisoning stays disabled. Set flag_format.pattern (xeger syntax) or known_flags in the service config.
- No flag write path identified in source; confirm the put flow manually.
- No flag read path identified in source; confirm the get flow manually.

## Put (write) candidates (0)

_none identified_

## Get (read) candidates (0)

_none identified_

## Storage hints (1)

- storage `C:\Users\Home\Desktop\Новая папка\services\curs\app\db.go:10` — `db, err := sql.Open("mysql", "root:secret@tcp(db:3306)/curs")`

## Exposure hints (0)

_none identified_
