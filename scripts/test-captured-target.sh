#!/usr/bin/env bash
# Captured-target execution with the actual pinned account and generated policy Wasm.
# Captures of a locally built SDK-30 native SAC fixture (capped, uncapped and self-paying
# rules) and the recorded testnet responses replayed through capture_native_target. No RPC
# call, network write or real key is involved.
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/testnet" "$work/uncapped" "$work/self-recipient"

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    cp "$OZPB_ACCOUNT_WASM" "$work/pinned-account.wasm"
else
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$work/pinned-account.wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
for variant in testnet uncapped self-recipient; do
    cp "$work/pinned-account.wasm" "$work/$variant/pinned-account.wasm"
done
( cd contracts/golden-transfer-policy && cargo fetch --locked )

python3 scripts/captured-target-fixture.py fixture "$work"
cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/spec.json" --rule 0 --out "$work/generated"
python3 scripts/native-execution-fixture.py job "$work"
for variant in uncapped self-recipient; do
    python3 scripts/captured-target-fixture.py "fixture-$variant" "$work/$variant"
    cargo run --locked --quiet -p ozpb-cli -- generate \
        --spec "$work/$variant/spec.json" --rule 0 --out "$work/$variant/generated"
    python3 scripts/native-execution-fixture.py job "$work/$variant"
done

OZPB_TARGET_CAPTURE_OUT="$work/testnet" cargo test --locked -p ozpb-source-rpc \
    --test target_capture_conformance a_captured_native_transfer_response_set
python3 scripts/captured-target-fixture.py testnet "$work/testnet" "$work/testnet/call.json"
cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/testnet/spec.json" --rule 0 --out "$work/testnet/generated"
python3 scripts/native-execution-fixture.py job "$work/testnet"

OZPB_CAPTURED_TEST_JOB="$work/job.json" \
OZPB_CAPTURED_UNCAPPED_JOB="$work/uncapped/job.json" \
OZPB_CAPTURED_SELF_RECIPIENT_JOB="$work/self-recipient/job.json" \
OZPB_TESTNET_NATIVE_JOB="$work/testnet/job.json" \
OZPB_TESTNET_CAPTURE="$work/testnet/capture.json" \
OZPB_TESTNET_CAPTURED_REPORT="${OZPB_TESTNET_CAPTURED_REPORT:-$work/testnet/report.json}" \
    cargo test --manifest-path execution-runtime/Cargo.toml --locked \
    --lib --test captured_target --test process -- --include-ignored \
    --skip process_runs_the_complete_interactive_protocol \
    --skip sdk28_generated_wasm_refuses_a_muxed_form_of_allowed_contract_address_on_host30 | tee "$work/result.log"
for test in \
    captured::tests::strict_source_answers_only_declared_keys_and_logs_the_rest \
    captured::tests::classify_flags_every_unexpected_difference \
    captured_sac_executes_real_target_balances_and_policy_denial_rollback \
    captured_state_decides_the_target_outcome \
    captured_prepare_refuses_modified_header_config_scope_and_incomplete_closure \
    captured_uncapped_rule_executes_without_a_counter \
    captured_state_overlapping_the_candidate_is_refused \
    captured_recorded_testnet_state_executes \
    process_runs_the_captured_target_protocol; do
    grep -qx "test $test ... ok" "$work/result.log" || {
        echo "required captured-target test did not run and pass: $test" >&2
        exit 1
    }
done
