#!/bin/sh
# One probe from inside the emulated stand network, from a chosen address.
#
# The address is the point: the gateway classifies peers by their real IP, so a
# check that runs from the wrong source would prove nothing. Usage:
#
#   stand-probe.sh <ip> <host> <method> <path> [body]
#
# Prints the HTTP status, or 000 when the connection was dropped, which is what a
# blocked or unlisted peer sees.

set -eu

IP="$1"
HOST="$2"
METHOD="$3"
PATH_="$4"
BODY="${5:-}"

exec curl -s -o /dev/null -w '%{http_code}' \
  -H "Host: $HOST" \
  --max-time 10 \
  -X "$METHOD" \
  ${BODY:+--data "$BODY"} \
  "http://10.77.0.254:9090$PATH_"
