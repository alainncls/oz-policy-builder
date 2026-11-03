#!/usr/bin/env bash
# Launch the MCP server with the development registry trust configured, for an editor or agent
# session started in this repository (see `.mcp.json`).
#
# `synthesize_policy` refuses to run until OZPB_REGISTRY_ROOTS_JSON and OZPB_REGISTRY_MIN_VERSION
# are set, and that refusal is deliberate: the server verifies a request's registry snapshot
# against roots the *operator* configured, so a request cannot bring its own trust root. This
# wrapper supplies the committed development roots — suitable for a local session and for the
# demo, and not a production trust configuration.
#
# The roots are read from the committed file rather than pasted into `.mcp.json`, so there is one
# copy to keep correct instead of two.
#
# It also configures one RPC source, named `testnet`, for the tools that read through an operator
# source rather than a URL in the request (`check_policy_call_surface`, `prepare_install_intent`,
# `assemble_install_transaction`, `check_against_policy`, `capture_target`, and
# `record_transaction`/`record_simulation` unless a request gives its own URL; `prepare_dry_run`
# validates it without reading). Testnet only: the passphrase is fixed here and any
# `OZPB_RPC_SOURCES_JSON` already in the environment is replaced. The endpoint defaults to SDF's
# public testnet RPC; `OZPB_DEV_TESTNET_RPC_URL` may name another plain `https://` endpoint for
# the same network; the reads compare the network an endpoint reports with that passphrase.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTNET_RPC_URL="${OZPB_DEV_TESTNET_RPC_URL:-https://soroban-testnet.stellar.org}"
# Strict enough that the value cannot leave its JSON string: host, optional port and path only.
if [[ ! "$TESTNET_RPC_URL" =~ ^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~/-]*)?$ ]]; then
    echo "mcp-server-dev.sh: OZPB_DEV_TESTNET_RPC_URL must be a plain https:// URL" \
        "(host, port, path)" >&2
    exit 2
fi
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${CLAUDE_PLUGIN_DATA:-$HERE}/target}"
# Resolve the caller's target before the build switches to the pinned checkout. The exec
# below must use exactly the directory Cargo writes, including for a relative override.
case "$CARGO_TARGET_DIR" in
    /*) ;;
    *) CARGO_TARGET_DIR="$PWD/$CARGO_TARGET_DIR" ;;
esac
export CARGO_TARGET_DIR
BIN="$CARGO_TARGET_DIR/release/ozpb-mcp-server"
if [ -n "${CLAUDE_PLUGIN_DATA:-}" ] || [ ! -x "$BIN" ]; then
    # Cargo refreshes a plugin binary after source updates; the plugin manifest
    # puts its target dir in persistent plugin data. A project checkout with an
    # existing binary keeps the fast path. Stdout belongs to MCP alone. The build runs from
    # the checkout because rustup reads rust-toolchain.toml from cargo's directory, and a
    # client starts this wrapper wherever its session is.
    (cd "$HERE" && cargo build --locked --release -p ozpb-mcp-server >&2)
fi
export OZPB_REGISTRY_ROOTS_JSON="$(cat "$HERE/docs/examples/registry-roots.json")"
# Local draft-only wallet bridge. Hosted HTTP MCP never enables this interface.
export OZPB_WALLET_HANDOFF_URL="${OZPB_WALLET_HANDOFF_URL:-http://127.0.0.1:4317}"
export OZPB_REGISTRY_MIN_VERSION="${OZPB_REGISTRY_MIN_VERSION:-4}"
# The snapshot a request may omit, so an agent holding a recording can synthesize without
# transcribing a signed document. Verified against the roots above either way.
export OZPB_REGISTRY_SNAPSHOT_JSON="$(cat "$HERE/docs/examples/registry.signed.json")"
export OZPB_RPC_SOURCES_JSON="{\"testnet\":{\"rpc_url\":\"$TESTNET_RPC_URL\",\"network_passphrase\":\"Test SDF Network ; September 2015\"}}"
exec "$BIN" "$@"
