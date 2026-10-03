#!/usr/bin/env bash
# Install the gateway to /opt/ad-gateway as a systemd service on a real host.
#
# Requirements on the target: git, nodejs (>=20) + npm.
#
#   AD_OPS=... AD_ALPHA=... AD_BETA=... bash deploy/install-linux.sh
#
# 1. builds the engine and the gateway from this source
# 2. installs the compiled packages to /opt/ad-gateway
# 3. fills config from deploy/competition.template.json via setup.js
# 4. installs the systemd unit and starts the service
#
set -euo pipefail

TARGET=${AD_TARGET:-/opt/ad-gateway}
PORT_INGRESS=${AD_PORT_INGRESS:-9090}
PORT_ANALYTICS=${AD_PORT_ANALYTICS:-8787}
TEMPLATE=${AD_TEMPLATE:-deploy/competition.template.json}
ACCOUNTS=("${AD_OPS:+ops}" "${AD_ALPHA:+alpha}" "${AD_BETA:+beta}")
if [ "${#ACCOUNTS[@]}" -eq 0 ] || [ -z "$TEMPLATE" ]; then
  echo "install-linux: set AD_OPS (and AD_ALPHA/AD_BETA) and point AD_TEMPLATE at the filled template" >&2
  exit 2
fi

HERE="$(cd "$(dirname "$0")/.." && pwd)"
cd "$HERE/js"

echo "install: building engine and gateway"
# tsc and tsx are dev dependencies, so install everything before building.
npm ci
npx tsc -p packages/engine/tsconfig.json
npx tsc -p packages/gateway/tsconfig.json

echo "install: installing to $TARGET"
install -d -m 0755 "$TARGET"/config "$TARGET"/data
install -d -m 0755 "$TARGET"/node_modules/@ad
cp -r node_modules/@ad/engine "$TARGET"/node_modules/@ad/
cp -r packages/gateway/dist "$TARGET"/dist
cp packages/gateway/package.json "$TARGET"/package.json
# The engine is consumed from its dist; ship the manifest the runtime expects.
cp packages/engine/package.json "$TARGET"/node_modules/@ad/engine/package.json

echo "install: generating config"
# Build the fully-qualified output path first; setup.js resolves paths itself.
CONFIG_OUT="$TARGET/config/gateway.json"
node "$TARGET/dist/setup.js" --template "$HERE/$TEMPLATE" --out "$CONFIG_OUT"
chown -R node:node "$TARGET"

echo "install: installing systemd unit"
install -m 0644 "$HERE/deploy/gateway.service" /etc/systemd/system/ad-gateway.service
systemctl daemon-reload
systemctl enable ad-gateway
systemctl start ad-gateway

# Wait for the config to be parsed, then drop the netfilter rules if the
# operator wants the port-redirection mode (services keep their own ports and
# everything reaching them is intercepted on the way).
if [ "${AD_APPLY_FORWARD:-0}" = "1" ]; then
  echo "install: applying port redirection"
  AD_GATEWAY_CONFIG="$CONFIG_OUT" bash "$HERE/deploy/iptables-forward.sh" apply || echo "install: warning: iptables step failed" >&2
fi

echo "install: done. Check with: systemctl status ad-gateway"
echo "  ingress   http://<host>:$PORT_INGRESS/"
echo "  operator  http://<host>:$PORT_ANALYTICS/ (login: ops)"