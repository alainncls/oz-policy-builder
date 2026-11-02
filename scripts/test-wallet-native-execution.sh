#!/usr/bin/env bash
# The wallet's local execution layers against the actual CLI and native worker.
#   account_wasm: the wallet validates the CLI preparation, retains the worker's `--prepare`
#     frame, signs only offline-domain requests and recomputes agreement from the CLI's
#     reference expectations.
#   captured_target: `capture-target` reads the recorded testnet capture responses, replayed by
#     a local endpoint, through the wallet toolchain; the wallet checks the capture against the
#     rule's call and the worker's `--prepare-captured`/`--captured` frames against both.
# Offline: preparation's RPC source is a named placeholder it does not contact, and the capture
# endpoint is loopback replay. The delegate is the runtime process test's public seed. No
# network write and no real key.
set -euo pipefail
cd "$(dirname "$0")/.."

# The development registry's root is operator input, as for the testnet harness: the spec must
# name the root of the signed snapshot it is checked against, and generation covers that field.
: "${OZPB_REGISTRY_SNAPSHOT_ROOT:?set it to the root of docs/examples/registry.signed.json}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    # The worker still checks the exact pinned account hash.
    cp "$OZPB_ACCOUNT_WASM" "$work/pinned-account.wasm"
else
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$work/pinned-account.wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
pin_registry() {
    python3 - "$1" "$OZPB_REGISTRY_SNAPSHOT_ROOT" docs/examples/registry.signed.json <<'PY'
import json, re, sys
path, root, registry = sys.argv[1:]
if not re.fullmatch(r"[0-9a-f]{64}", root):
    raise SystemExit("OZPB_REGISTRY_SNAPSHOT_ROOT must be 64 lowercase hex characters")
spec = json.load(open(path))
policy = spec["rules"][0]["policies"][0]["generated"]
templates = json.load(open(registry))["snapshot"]["templates"]
spec["registry_snapshot"] = root
policy["capability_schema"] = templates[policy["template_family"]]["capability_schema"]
open(path, "w").write(json.dumps(spec, separators=(",", ":")))
PY
}
python3 scripts/native-execution-fixture.py spec "$work"
pin_registry "$work/spec.json"
# The captured layer's rule pays the recorded testnet transfer's recipient and amount from its
# account, read from the recorded authorization root (scripts/captured-target-fixture.py).
mkdir "$work/testnet"
cp "$work/pinned-account.wasm" "$work/testnet/pinned-account.wasm"
( cd wallet && node --input-type=module -e '
import { readFileSync, writeFileSync } from "node:fs";
import { Address, xdr } from "@stellar/stellar-sdk";
const sim = JSON.parse(readFileSync("../crates/source-rpc/tests/captured-testnet/target-capture/simulateTransaction.json", "utf8"));
const call = xdr.SorobanAuthorizationEntry.fromXDR(sim.results[0].auth[0], "base64").rootInvocation.function.contractFn;
const [account, recipient] = call.args.slice(0, 2).map((arg) => Address.fromScAddress(arg.address).toString());
if (call.args[2].i128.hi !== 0n) throw new Error("unexpected recorded amount");
writeFileSync(process.argv[1], JSON.stringify({ account, recipient, amount: call.args[2].i128.lo.toString(),
  observed_ledger: sim.latestLedger }));
' "$work/testnet/call.json" )
python3 scripts/captured-target-fixture.py testnet "$work/testnet" "$work/testnet/call.json"
pin_registry "$work/testnet/spec.json"

target() { cargo metadata --format-version 1 --no-deps --manifest-path "$1" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'; }
cargo build --locked --quiet -p ozpb-cli
cargo build --locked --quiet --manifest-path execution-runtime/Cargo.toml
cli="$work/ozpb"
runtime="$work/ozpb-execution-runtime"
# Private copies: a concurrent build into a shared target directory cannot replace them mid-run.
cp "$(target Cargo.toml)/debug/ozpb" "$cli"
cp "$(target execution-runtime/Cargo.toml)/debug/ozpb-execution-runtime" "$runtime"

( cd contracts/golden-transfer-policy && cargo fetch --locked )
"$cli" generate --spec "$work/spec.json" --rule 0 --out "$work/generated"
"$cli" generate --spec "$work/testnet/spec.json" --rule 0 --out "$work/testnet/generated"
printf '%s\n' '{"synthetic-fixture":{"rpc_url":"https://rpc.invalid/","network_passphrase":"Test SDF Network ; September 2015"}}' \
    > "$work/rpc-sources.json"

OZPB_NATIVE_E2E_CLI="$cli" OZPB_NATIVE_E2E_RUNTIME="$runtime" OZPB_NATIVE_E2E_WORK="$work" \
    node --test --test-reporter=spec wallet/tests/native-e2e.test.mjs | tee "$work/result.log"
for name in \
    'the wallet runs the actual worker and accepts only its independently checked report' \
    'the actual worker report is refused against a changed independent expectation' \
    'the actual worker preparation is refused for another proposed rule ID' \
    'the actual worker report is refused when a boundary ledger differs from the CLI suite'; do
    grep -qF "✔ $name" "$work/result.log" || {
        echo "required wallet native execution test did not run and pass: $name" >&2
        exit 1
    }
done

OZPB_CAPTURED_E2E_CLI="$cli" OZPB_CAPTURED_E2E_RUNTIME="$runtime" OZPB_CAPTURED_E2E_WORK="$work/testnet" \
    node --test --test-reporter=spec wallet/tests/captured-e2e.test.mjs | tee "$work/captured.log"
for name in \
    'the wallet captures the recorded testnet transfer through the actual CLI and accepts the actual worker report' \
    "the actual captured worker report is refused against another review's amount" \
    'the actual captured worker preparation is refused for another capture' \
    'the actual capture is refused for a review naming another call'; do
    grep -qF "✔ $name" "$work/captured.log" || {
        echo "required wallet captured execution test did not run and pass: $name" >&2
        exit 1
    }
done
