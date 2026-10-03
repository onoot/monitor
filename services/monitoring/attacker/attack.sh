#!/bin/sh
# The attacker loop: an address inside a team range that keeps making the kind
# of request the rules exist to catch. Every probe should be blocked, and that is
# the point -- the same probe from the checker is let through.
set -u

target="${ATTACK_TARGET:-10.65.9.254}"
# The routed service ports. An override with ATTACK_PORT probes only that one;
# otherwise every port a watched service publishes is probed, so a blocked entry
# appears as soon as any of them is launched, whichever the operator started.
ports="${ATTACK_PORT:-${ATTACK_PORTS:-1337 8083 8080 4444}}"
interval="${ATTACK_INTERVAL:-10}"

echo "attacker: probing http://${target}:{${ports}} every ${interval}s"
while true; do
  for port in $ports; do
    for path in /.git/config /config.php.bak /../../etc/passwd "/?q=1%27%20OR%20%271%27%3D%271"; do
      code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://${target}:${port}${path}")
      echo "attacker: ${port}${path} -> ${code}"
    done
  done
  sleep "$interval"
done
