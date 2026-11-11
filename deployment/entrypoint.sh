#!/bin/sh
set -eu
umask 077
mode=${1:-serve}
if [ "$mode" != serve-host ]; then
    mkdir -p "$CARGO_HOME" "$OZPB_BUILD_CACHE_DIR" "$TMPDIR"
    cp /opt/ozpb/cargo-config.toml "$CARGO_HOME/config.toml"
fi
if [ "$mode" != serve ] && [ "$mode" != serve-host ]; then
    exec "$@"
fi
if [ "$#" -gt 1 ]; then
    echo 'serve takes no arguments' >&2
    exit 1
fi
# File inputs keep credentials out of Compose interpolation, image layers, and argv.
# The current binary requires this environment variable; compiler subprocesses clear it.
config_dir=${OZPB_HTTP_CONFIG_DIR:-/run/ozpb}
case "$config_dir" in /*) ;; *) echo 'configuration directory must be absolute' >&2; exit 1 ;; esac
token_file=$config_dir/bearer-token
if [ ! -f "$token_file" ] || [ "$(wc -c < "$token_file")" -gt 129 ]; then
    echo 'a bounded bearer-token file is required' >&2
    exit 1
fi
OZPB_HTTP_BEARER_TOKEN=$(cat "$token_file")
case "$OZPB_HTTP_BEARER_TOKEN" in
    *[!A-Za-z0-9._~-]*|'') echo 'bearer-token must contain 32 to 128 URL-safe characters' >&2; exit 1 ;;
esac
if [ "${#OZPB_HTTP_BEARER_TOKEN}" -lt 32 ] || [ "${#OZPB_HTTP_BEARER_TOKEN}" -gt 128 ]; then
    echo 'bearer-token must contain 32 to 128 URL-safe characters' >&2
    exit 1
fi
export OZPB_HTTP_BEARER_TOKEN
OZPB_REGISTRY_ROOTS_JSON=$(cat "$config_dir/registry-roots.json")
OZPB_REGISTRY_SNAPSHOT_JSON=$(cat "$config_dir/registry.signed.json")
OZPB_RPC_SOURCES_JSON=$(cat "$config_dir/rpc-sources.json")
export OZPB_REGISTRY_ROOTS_JSON OZPB_REGISTRY_SNAPSHOT_JSON OZPB_RPC_SOURCES_JSON
# Loopback by default, for the TLS proxy beside it. An ingress that reaches the server over the
# network sets OZPB_HTTP_LISTEN (for example 0.0.0.0:8080) together with OZPB_HTTP_ALLOWED_HOSTS,
# the public names it forwards; the server refuses a routable address without them.
listen=${OZPB_HTTP_LISTEN:-127.0.0.1:8080}
case "$listen" in
    *[!0-9A-Fa-f.:\[\]]*|'') echo 'OZPB_HTTP_LISTEN must be an IP address and port' >&2; exit 1 ;;
esac
exec /usr/local/bin/ozpb-mcp-server --http "$listen"
