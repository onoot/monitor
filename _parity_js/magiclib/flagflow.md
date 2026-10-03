# magiclib — flag flow

- Pattern source: `unconfirmed_heuristic`
- Pattern confirmed: false

## Warnings

- No flag pattern configured. Flag put/get verification is unavailable and poisoning stays disabled. Set flagFormat.pattern (xeger syntax) or knownFlags in the service config.
- No flag write path identified in source; confirm the put flow manually.
- No flag read path identified in source; confirm the get flow manually.

## Put (write) candidates (0)

_none identified_

## Get (read) candidates (0)

_none identified_

## Storage hints (2)

- storage `magicapp/routes.py:139` — `error_page = open('magicapp/templates/404.html').read().replace('_PATH_', request.path)`
- storage `magicapp/sql.py:22` — `cursor.execute(open("magicapp/schema.sql", "r").read())`

## Exposure hints (0)

_none identified_
