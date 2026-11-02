#!/usr/bin/env bash
# Integration checks use a disposable local Compose project. Nothing is published or deployed.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${OZPB_IMAGE:?Set the image ID built from the tested revision}"
: "${OZPB_PROXY_IMAGE:?Set the proxy image ID built from the tested revision}"
WORK="$(mktemp -d)"
PROJECT="ozpb-check-$$"
export OZPB_CONFIG_DIR="$WORK"
export OZPB_HOSTNAME=localhost OZPB_BIND_IP=127.0.0.1
OZPB_TLS_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
export OZPB_TLS_PORT
export OZPB_RPC_ALLOWLIST=https://soroban-testnet.stellar.org OZPB_REGISTRY_MIN_VERSION=4
export OZPB_HTTP_REQUESTS_PER_MINUTE=3 OZPB_HTTP_MAX_BODY_BYTES=4096
compose=(docker compose -p "$PROJECT" -f deployment/compose.yaml)
cleanup() {
    "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT
# First validate the compiler without credentials or egress. If the public fixture fails,
# its bounded compiler diagnostics can be reported without exposing an API request.
docker run --rm --network none --read-only --user 10001:10001 --cap-drop ALL \
    --security-opt no-new-privileges --cpus 2 --memory 4g --memory-swap 4g --pids-limit 256 \
    --tmpfs /tmp/ozpb:size=536870912,uid=10001,gid=10001,mode=0700,noexec,nosuid,nodev \
    --tmpfs /var/cache/ozpb:size=2147483648,uid=10001,gid=10001,mode=0700,exec,nosuid,nodev \
    "$OZPB_IMAGE" /opt/ozpb/verify-offline.sh
umask 077
openssl rand -hex 32 >"$WORK/bearer-token"
cp docs/examples/registry-roots.json docs/examples/registry.signed.json "$WORK/"
printf '%s\n' '{"testnet":{"rpc_url":"https://soroban-testnet.stellar.org","network_passphrase":"Test SDF Network ; September 2015"}}' >"$WORK/rpc-sources.json"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=localhost \
    -addext subjectAltName=DNS:localhost -keyout "$WORK/tls.key" -out "$WORK/tls.crt" >/dev/null 2>&1
# Files are read-only to the unprivileged containers; the parent directory stays owner-only.
chmod 0444 "$WORK"/*
"${compose[@]}" config --quiet
"${compose[@]}" up -d api
"${compose[@]}" run --rm --no-deps tls caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1
"${compose[@]}" up -d --wait
# No periodic health check: readiness uses unauthenticated requests only during this test.
for attempt in {1..30}; do
    if [ "$(curl --silent --cacert "$WORK/tls.crt" -o /dev/null -w '%{http_code}' "https://localhost:$OZPB_TLS_PORT/v1/mcp" || true)" = 401 ]; then
        break
    fi
    sleep 1
done
python3 scripts/check-hosted-endpoint.py "https://localhost:$OZPB_TLS_PORT/v1/mcp" \
    --token-file "$WORK/bearer-token" --ca-file "$WORK/tls.crt" --body-limit 4096 --quota 3
"${compose[@]}" down --remove-orphans >/dev/null
# New containers give the tool session a fresh quota and enough body capacity for artifacts.
export OZPB_HTTP_REQUESTS_PER_MINUTE=10 OZPB_HTTP_MAX_BODY_BYTES=8388608
"${compose[@]}" up -d --wait
for attempt in {1..30}; do
    if [ "$(curl --silent --cacert "$WORK/tls.crt" -o /dev/null -w '%{http_code}' "https://localhost:$OZPB_TLS_PORT/v1/mcp" || true)" = 401 ]; then
        break
    fi
    sleep 1
done
python3 scripts/check-hosted-build.py "https://localhost:$OZPB_TLS_PORT/v1/mcp" \
    --token-file "$WORK/bearer-token" --ca-file "$WORK/tls.crt" --spec docs/examples/subscription-spec.json
"${compose[@]}" down --remove-orphans >/dev/null
