#!/bin/sh
# The checker loop: run every registered checker against the gateway, again and
# again, so flags keep flowing into the dashboard. One round is enough to be
# useful; the interval leaves the operator room to watch the result.
set -eu

host="${AD_CHECKER_HOST:-10.78.0.254}"
rounds="${AD_CHECKER_ROUNDS:-2}"
interval="${AD_CHECKER_INTERVAL:-60}"

echo "checker: target ${host}, ${rounds} round(s), every ${interval}s"
while true; do
  python tools/run_checkers.py --host "$host" --rounds "$rounds" || true
  sleep "$interval"
done
