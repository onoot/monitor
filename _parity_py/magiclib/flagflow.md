# magiclib — flag flow

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

## Storage hints (2)

- storage `C:\Users\Home\Desktop\Новая папка\services\magiclib\magicapp\routes.py:139` — `error_page = open('magicapp/templates/404.html').read().replace('_PATH_', request.path)`
- storage `C:\Users\Home\Desktop\Новая папка\services\magiclib\magicapp\sql.py:22` — `cursor.execute(open("magicapp/schema.sql", "r").read())`

## Exposure hints (0)

_none identified_
