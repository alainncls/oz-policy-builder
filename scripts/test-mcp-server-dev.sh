#!/usr/bin/env bash
# The development wrapper hands the server exactly one RPC source, for testnet, whatever the
# caller's environment says, and refuses an endpoint override that is not a plain https URL.
#
# It runs the real wrapper against a stand-in server binary that prints the source map it was
# started with, so nothing is built and no endpoint is contacted.
set -uo pipefail
cd "$(dirname "$0")/.."

WRAPPER="$PWD/scripts/mcp-server-dev.sh"
TESTNET="Test SDF Network ; September 2015"
fail=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/release"
cat > "$WORK/release/ozpb-mcp-server" <<'EOF'
#!/usr/bin/env bash
printf '%s' "${OZPB_RPC_SOURCES_JSON-unset}"
EOF
chmod +x "$WORK/release/ozpb-mcp-server"

# Without CLAUDE_PLUGIN_DATA and with an executable binary in place, the wrapper does not build.
run() { env -u CLAUDE_PLUGIN_DATA -u OZPB_DEV_TESTNET_RPC_URL -u OZPB_RPC_SOURCES_JSON \
    CARGO_TARGET_DIR="$WORK" "$@" bash "$WRAPPER" 2>/dev/null; }

expect_sources() {
    local name="$1" url="$2" got="$3"
    if ! python3 -c '
import json, sys
url, passphrase, got = sys.argv[1:]
assert json.loads(got) == {"testnet": {"rpc_url": url, "network_passphrase": passphrase}}, got
' "$url" "$TESTNET" "$got" 2>/dev/null; then
        echo "FAIL: $name: the server was started with sources $got" >&2
        fail=1
    fi
}

expect_sources "default" "https://soroban-testnet.stellar.org" "$(run)"
expect_sources "endpoint override" "https://rpc.example.test/soroban" \
    "$(run OZPB_DEV_TESTNET_RPC_URL=https://rpc.example.test/soroban)"
expect_sources "a caller's source map is replaced" "https://soroban-testnet.stellar.org" \
    "$(run OZPB_RPC_SOURCES_JSON='{"mainnet":{"rpc_url":"https://rpc.example.test","network_passphrase":"Public Global Stellar Network ; September 2015"}}')"

# Each of these must stop the wrapper before the server starts: plain http, a value that would
# rewrite the JSON (here into a mainnet passphrase), whitespace, a userinfo part, and a query.
for bad in 'http://rpc.example.test' \
    'https://x","network_passphrase":"Public Global Stellar Network ; September 2015' \
    'https://rpc.example.test/a b' 'https://user@rpc.example.test' 'https://rpc.example.test/?a=1'; do
    if out="$(run OZPB_DEV_TESTNET_RPC_URL="$bad")"; then
        echo "FAIL: override '$bad' was accepted (server started with $out)" >&2
        fail=1
    fi
done

# A plugin session starts the wrapper from the user's directory, and rustup picks the toolchain
# from the directory cargo runs in: the build has to run from this checkout, or the pin in
# rust-toolchain.toml is ignored and a cold build compiles everything with another compiler.
mkdir -p "$WORK/bin" "$WORK/elsewhere"
cat > "$WORK/bin/cargo" <<EOF
#!/usr/bin/env bash
pwd -P > "$WORK/cargo-cwd"
EOF
chmod +x "$WORK/bin/cargo"
(cd "$WORK/elsewhere" && run CLAUDE_PLUGIN_DATA="$WORK/plugin-data" PATH="$WORK/bin:$PATH" >/dev/null)
if [ "$(cat "$WORK/cargo-cwd" 2>/dev/null)" != "$(pwd -P)" ]; then
    echo "FAIL: the plugin build ran in '$(cat "$WORK/cargo-cwd" 2>/dev/null)', not this checkout" >&2
    fail=1
fi

if [ "$fail" -ne 0 ]; then
    exit 1
fi
echo "mcp-server-dev.sh: testnet-only RPC source and pinned-toolchain build OK"
