# The monitoring service: the gateway and its own analytics surface in one process.
#
# Built from the workspace sources rather than from a published image, so the
# image is the code under review and not something that can drift from it. Only
# the two packages the gateway needs are copied in: the engine, for address
# parsing, and the gateway itself. The dashboard, the scanner and the parity
# harness are not needed to watch traffic.

FROM node:24-alpine AS build

WORKDIR /build

# The manifests first, so a layer that only changes source is not invalidated by
# an install step that did not change.
COPY js/package.json js/package-lock.json ./
COPY js/packages/engine/package.json packages/engine/
COPY js/packages/gateway/package.json packages/gateway/

# `npm ci` needs the whole workspace manifest to resolve the local links, so the
# remaining package manifests come along.
COPY js/packages/server/package.json packages/server/
COPY js/packages/web/package.json packages/web/

RUN npm ci --omit=dev --ignore-scripts \
  && npm install --no-save typescript@5.7 @types/node@24

COPY js/packages/engine packages/engine
COPY js/packages/gateway packages/gateway

RUN npx tsc -p packages/engine/tsconfig.json \
  && npx tsc -p packages/gateway/tsconfig.json \
  && npm prune --omit=dev


FROM node:24-alpine AS runtime

# tini reaps the process and forwards signals, so `docker stop` reaches node
# instead of waiting out the kill timeout. The docker CLI and the compose plugin
# are here so the operator can bring a watched service project up with its own
# compose file from the dashboard, against the host socket mounted at run time.
RUN apk add --no-cache tini docker-cli docker-cli-compose

ENV NODE_ENV=production

WORKDIR /app

COPY --from=build /build/node_modules ./node_modules
COPY --from=build /build/packages/engine/package.json ./node_modules/@ad/engine/package.json
COPY --from=build /build/packages/engine/dist ./node_modules/@ad/engine/dist
COPY --from=build /build/packages/gateway/dist ./dist

# No config is copied in, deliberately. The allowlist and the upstreams are
# mounted at run time, so one image serves the stand, a rehearsal and the real
# network, and no address list is ever baked into a layer. Started without the
# mount, the service refuses to come up rather than coming up with a guess.
ENV AD_GATEWAY_CONFIG=/app/config/gateway.json

# Runs as root, deliberately, because it holds the host Docker socket: on a
# stand that is a button for the operator to start the services, and the socket
# is root-equivalent anyway. On a locked-down host, mount the socket only when
# the launch feature is wanted, or run the whole container in a dedicated group
# that owns the socket.
USER root

EXPOSE 9090 8787

HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "const r=require('node:http').get({host:'127.0.0.1',port:8787,path:'/api/health',timeout:4000},(s)=>process.exit(s.statusCode===200?0:1));r.on('error',()=>process.exit(1));r.on('timeout',()=>{r.destroy();process.exit(1)})"

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/index.js"]
