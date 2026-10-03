#!/usr/bin/env bash
# Interpose the gateway on the real service ports with netfilter, so that no
# service or client configuration has to change. A packet destined to the host's
# public port P is REDIRECTed onto the gateway's listener at P+redirect_offset
# (the offset comes out of the same gateway.json, so this script can never drift
# from what the gateway bound). The connection keeps the caller's IP, which is
# how the gateway still classifies checker/admin/team correctly.
#
# Work on a Linux host. Docker Desktop / Windows has no PREROUTING access; the
# hostname mode of the stand covers that environment instead.
#
#   bash deploy/iptables-forward.sh apply    # install (idempotent: rebuilds the chain)
#   bash deploy/iptables-forward.sh dump     # show what is installed
#   bash deploy/iptables-forward.sh flush    # remove everything this script made
#
# Env:
#   AD_GATEWAY_CONFIG  path to gateway.json (default /opt/ad-gateway/config/gateway.json)
#   AD_FORWARD_IFACE   restrict the job to one interface, else all
#
set -euo pipefail

CONFIG=${AD_GATEWAY_CONFIG:-/opt/ad-gateway/config/gateway.json}
# Per-service additions made in the UI (`services.json`). Lives next to the
# capture data; the default mirrors the install layout.
STATE=${AD_STATE_DIR:-$(dirname "$CONFIG")/../data/state}
IFACE=${AD_FORWARD_IFACE:-}
CHAIN=AD_FORWARD
MODE=${1:-apply}

[ -f "$CONFIG" ] || { echo "forward-ports: no config at $CONFIG" >&2; exit 2; }

# Emit "PUBLIC_PORT TARGET_PORT" lines, one per port to interpose: the config's
# own ingress_ports, the services added in the UI, and the protected ports that
# are refused rather than routed (skipped when allow_protected_ports is on).
lines() {
  node -e '
    const fs = require("fs");
    const c = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
    const stateFile = process.argv[3];
    const off = typeof c.redirect_offset === "number" ? c.redirect_offset : 10000;
    const seen = new Set();
    const emit = (p) => {
      const port = Number(p);
      if (!Number.isInteger(port) || port < 1 || seen.has(port)) return;
      seen.add(port);
      console.log(port, port + off);
    };
    for (const p of Object.keys(c.ingress_ports || {})) emit(p);
    if (c.allow_protected_ports !== true) {
      for (const p of Object.keys(c.protected_ports || {})) emit(p);
    }
    try {
      const s = JSON.parse(fs.readFileSync(stateFile, "utf8"));
      for (const entry of (s.services || [])) {
        if (entry && Number.isInteger(entry.port)) emit(entry.port);
      }
    } catch {
      // no saved services yet, or a corrupt file; nothing to add
    }
  ' "$CONFIG" "$STATE/services.json"
}

chain_exists() { iptables -t nat -L "$CHAIN" >/dev/null 2>&1; }

flush() {
  if chain_exists; then
    RULES=$(iptables -t nat -S PREROUTING | grep -F " -j $CHAIN" | sed 's/^-A /-D /' | head -n 40)
    if [ -n "$RULES" ]; then
      while IFS= read -r rule; do iptables -t nat "$rule"; done <<< "$RULES"
    fi
    iptables -t nat -F "$CHAIN" || true
    iptables -t nat -X "$CHAIN" || true
  fi
}

case "$MODE" in
  flush)
    flush
    echo "forward-ports: flushed"
    ;;

  dump)
    echo "PREROUTING -> $CHAIN:"
    iptables -t nat -S PREROUTING | grep -F "$CHAIN" || echo "  (none)"
    echo "chain:"
    iptables -t nat -L "$CHAIN" -n 2>/dev/null || echo "  (chain absent)"
    echo "config:"
    lines | while read -r p t; do echo "  $p -> $t"; done
    ;;

  apply)
    flush
    iptables -t nat -N "$CHAIN"
    [ -z "$IFACE" ] || IFARG="-i $IFACE"
    while read -r p t; do
      if [ -n "$p" ] && [ -n "$t" ]; then
        # shellcheck disable=SC2086
        iptables -t nat -A "$CHAIN" $IFARG -p tcp --dport "$p" -j REDIRECT --to-ports "$t"
        echo "forward-ports: $p -> $t"
      fi
    done <<< "$(lines)"
    iptables -t nat -I PREROUTING 1 -j "$CHAIN"
    echo "forward-ports: PREROUTING -> $CHAIN installed"
    ;;

  *)
    echo "usage: iptables-forward.sh apply|dump|flush" >&2
    exit 2
    ;;
esac