#!/usr/bin/env bash
# `ozpb dry-run` end to end: the actual CLI preparation, the actual native worker and the CLI's
# own offline-domain signer, driven by one command.
#
# 1. The native fixture: the account-Wasm layer must pass with the original permitted and at
#    least five derived denials reverted, the live layer must stay unavailable, key files that
#    are not 0600 or not the spec delegate's are refused, and no form of the key is in any output.
# 2. The recorded testnet capture: the same command with --capture-request also runs the
#    captured-target layer, capturing through the CLI's capture path from a local endpoint that
#    replays the recorded responses for the public Pollywallet sample account.
#
# Offline: preparation contacts no RPC source, and the only endpoint is the local replay. The
# delegate key is the runtime process test's public seed, written to 0600 files in this run's
# temporary directory; it is synthetic test material, never a wallet key.
set -euo pipefail
cd "$(dirname "$0")/.."

# The development registry's root is operator input, as for the testnet harness: the spec must
# name the root of the signed snapshot it is checked against, and generation covers that field.
: "${OZPB_REGISTRY_SNAPSHOT_ROOT:?set it to the root of docs/examples/registry.signed.json}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/testnet"

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    # The CLI and the worker both still check the exact pinned account hash.
    cp "$OZPB_ACCOUNT_WASM" "$work/pinned-account.wasm"
else
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$work/pinned-account.wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
cp "$work/pinned-account.wasm" "$work/testnet/pinned-account.wasm"

target() { cargo metadata --format-version 1 --no-deps --manifest-path "$1" \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["target_directory"])'; }
# Private copies: a concurrent build into a shared target directory cannot replace them mid-run.
cli="$work/ozpb"
runtime="$work/ozpb-execution-runtime"
if [ -n "${OZPB_BIN:-}" ]; then
    cp "$OZPB_BIN" "$cli"
else
    cargo build --locked --quiet -p ozpb-cli
    cp "$(target Cargo.toml)/debug/ozpb" "$cli"
fi
if [ -n "${OZPB_NATIVE_WORKER:-}" ]; then
    cp "$OZPB_NATIVE_WORKER" "$runtime"
else
    cargo build --locked --quiet --manifest-path execution-runtime/Cargo.toml
    cp "$(target execution-runtime/Cargo.toml)/debug/ozpb-execution-runtime" "$runtime"
fi
unset OZPB_NATIVE_WORKER

# The recorded testnet capture's call, for the second fixture's rule.
OZPB_TARGET_CAPTURE_OUT="$work/testnet" cargo test --locked --quiet -p ozpb-source-rpc \
    --test target_capture_conformance a_captured_native_transfer_response_set >/dev/null
python3 scripts/native-execution-fixture.py spec "$work"
python3 scripts/captured-target-fixture.py testnet "$work/testnet" "$work/testnet/call.json"
( cd contracts/golden-transfer-policy && cargo fetch --locked )

# Each fixture: the registry root, the generated policy, the request, the source ledger, and
# three key files: the delegate's (0600), the delegate's readable by others (0644), and another
# key (0600).
for fixture in "$work:synthetic-fixture" "$work/testnet:testnet"; do
    dir="${fixture%%:*}"
    source_name="${fixture#*:}"
    python3 - "$dir/spec.json" "$OZPB_REGISTRY_SNAPSHOT_ROOT" docs/examples/registry.signed.json <<'PY'
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
    "$cli" generate --spec "$dir/spec.json" --rule 0 --out "$dir/generated"
    python3 - "$dir" "$source_name" docs/examples/registry.signed.json <<'PY'
import base64, json, os, secrets, sys
from pathlib import Path
work, source, registry = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
spec = json.loads((work / "spec.json").read_text())
generated = work / "generated"
manifest = json.loads((generated / "build-manifest.json").read_text())
wasm = (generated / "generated_sub_transfer_r0.wasm").read_bytes()
files = {name: (generated / name).read_text() for name in [
    "Cargo.toml", "rust-toolchain.toml", "rustfmt.toml", "src/lib.rs", "src/contract.rs"]}
request = {
    "candidate": {
        "spec": spec, "rule_index": 0,
        "binding_set": {
            "schema": "policy-binding-set/v1", "spec_hash": manifest["spec_hash"],
            "network_id": spec["network_id"],
            "bindings": [{
                "rule_index": 0, "policy_index": 0,
                "contract_address": "CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6",
                "observed_wasm_hash": manifest["wasm_hash"],
                "recognition": {"kind": "verified_generated_manifest", "build_manifest": manifest},
                "resolution_reference": "CLI dry-run end-to-end test",
            }],
        },
        "signed_registry_snapshot": json.loads(Path(registry).read_text()),
        "account_address": spec["smart_account"]["address"],
        "network_id": spec["network_id"], "rpc_source": source,
    },
    "artifact": {
        "spec": spec, "rule_index": 0, "claimed_generated_files": files,
        "claimed_wasm_base64": base64.b64encode(wasm).decode(),
        "claimed_build_manifest": manifest,
    },
    "candidate_context_rule_id": 3, "run_nonce": secrets.token_hex(32),
}
(work / "request.json").write_text(json.dumps(request))
(work / "ledger.json").write_text(json.dumps({
    "protocol_version": 30, "sequence": 1000, "timestamp": "100000", "base_reserve": 5000000,
    "min_temp_entry_ttl": 16, "min_persistent_entry_ttl": 4096, "max_entry_ttl": 631200}))

def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc

def secret_seed(seed):
    raw = bytes([18 << 3]) + seed
    raw += crc16(raw).to_bytes(2, "little")
    return base64.b32encode(raw).decode().rstrip("=")

def write(name, text, mode):
    path = work / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text + "\n")
    os.chmod(path, mode)

delegate = bytes([42]) * 32
write("delegate.key", secret_seed(delegate), 0o600)
write("delegate-open.key", secret_seed(delegate), 0o644)
write("other.key", secret_seed(bytes([7]) * 32), 0o600)
# Every form of the delegate's secret the outputs are searched for.
(work / "secret-forms.txt").write_text("\n".join(
    [secret_seed(delegate), delegate.hex(), base64.b64encode(delegate).decode()]) + "\n")
PY
done
printf '%s\n' '{"synthetic-fixture":{"rpc_url":"https://rpc.invalid/","network_passphrase":"Test SDF Network ; September 2015"}}' \
    > "$work/rpc-sources.json"

dry_run() {
    "$cli" dry-run --request "$work/request.json" \
        --registry-roots docs/examples/registry-roots.json --registry-min-version 3 \
        --rpc-sources "$work/rpc-sources.json" --native-worker "$runtime" \
        --account-wasm "$work/pinned-account.wasm" --source-ledger "$work/ledger.json" \
        --delegate-key-file "$1"
}

dry_run "$work/delegate.key" > "$work/report.json" 2> "$work/stderr.log" || {
    cat "$work/stderr.log" >&2
    echo "ozpb dry-run did not meet the permit/deny bar over the native fixture" >&2
    exit 1
}
python3 - "$work/report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
layers = {layer["id"]: layer for layer in report["layers"]}
assert [layer["id"] for layer in report["layers"]] == [
    "reference", "account_wasm", "captured_target", "live_enforcement"], report["layers"]
account = layers["account_wasm"]
assert account["status"] == "passed", account["reason"]
execution = account["execution"]
cases = execution["cases"]
assert account["cases"] == len(cases) > 0
assert all(case["agree"] for case in cases)
denials = [c for c in cases if not c["expected_permit"] and not c["permitted"] and c["agree"]]
assert all(c["refused_by"] in ("account", "policy") and c["state_unchanged"] for c in denials)
assert any(c["class"] == "original" and c["permitted"] for c in cases)
assert [c["name"] for c in execution["controls"]] == [
    "signature_bit", "nonce_binding", "payload_binding", "context_rule_binding", "nonce_replay"]
assert all(c["passed"] for c in execution["controls"])
assert execution["stateful"]["passed"] and execution["stateful"]["successful_calls"] == 12
assert execution["execution_network_id"] != execution["source_network_id"]
acceptance = report["acceptance"]
assert acceptance["meets_minimum"] and acceptance["original_permitted"], acceptance
assert acceptance["required_reverted_denials"] == 5
[accepted] = acceptance["executed_layers"]
assert accepted["layer"] == "account_wasm" and accepted["reverted_denials"] == len(denials) >= 5
assert layers["captured_target"]["status"] == "unavailable"
assert layers["captured_target"]["reason"] == "captured_target_not_requested"
assert layers["live_enforcement"]["status"] == "unavailable"
assert layers["live_enforcement"]["reason"] == "wallet_owner_consent_required"
assert report["complete"] is False
print(f"account_wasm passed: {len(cases)} cases, {len(denials)} reverted denials, "
      f"original permitted; live layer unavailable")
PY

# Refused key files: no report, a nonzero exit, and the reason on stderr.
for case in "delegate-open.key:must have mode 0600" "other.key:not the spec's delegate"; do
    file="${case%%:*}"
    reason="${case#*:}"
    if dry_run "$work/$file" > "$work/refused-$file.out" 2> "$work/refused-$file.err"; then
        echo "ozpb dry-run accepted the key file $file" >&2
        exit 1
    fi
    grep -qF "$reason" "$work/refused-$file.err" || {
        cat "$work/refused-$file.err" >&2
        echo "ozpb dry-run refused $file without saying: $reason" >&2
        exit 1
    }
    [ ! -s "$work/refused-$file.out" ] || {
        echo "ozpb dry-run printed a report for the refused key file $file" >&2
        exit 1
    }
done

# The captured-target layer, through a local endpoint replaying the recorded capture. The test
# writes its report and output streams into the fixture directory, so they are searched below.
OZPB_DRY_RUN_E2E_WORK="$work/testnet" OZPB_DRY_RUN_E2E_CLI="$cli" \
    OZPB_DRY_RUN_E2E_WORKER="$runtime" \
    cargo test --locked -p ozpb-cli --test dry_run_cli -- --ignored | tee "$work/captured.log"
grep -qx "test dry_run_runs_the_captured_layer_through_a_replayed_capture ... ok" \
    "$work/captured.log" || {
    echo "required CLI dry-run test did not run and pass: captured layer" >&2
    exit 1
}

# No form of the delegate's secret in any report, output or error stream.
while IFS= read -r form; do
    if grep -rqF -- "$form" "$work"/report.json "$work"/stderr.log "$work"/refused-* \
        "$work"/testnet/dry-run.*; then
        echo "a form of the delegate secret appears in the dry-run output" >&2
        exit 1
    fi
done < "$work/secret-forms.txt"
echo "ozpb dry-run end to end: passed"
