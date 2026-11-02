#!/usr/bin/env bash
# Build the exact recognized account and a signable generated policy, then run
# the full delegated-auth and committed-state test. Artifacts stay in a temp dir.
set -euo pipefail
cd "$(dirname "$0")/.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
account_wasm="$work/pinned-account.wasm"
spending_wasm="$work/pinned-spending-policy.wasm"

# The account pin is byte-exact and reproduces only from one build host. An
# overriding artifact built elsewhere fails the test's hash assertion, which
# alone does not name that cause.
account_host_note() {
    echo "the pinned account Wasm reproduces byte-for-byte only when built on an" >&2
    echo "aarch64-apple-darwin host; on other hosts it differs only in function order" >&2
    echo "(rust-lang/cargo#8140, fix pending in rust-lang/cargo#17522)" >&2
}

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    # A local artifact may save a cold source build. The test still asserts the
    # exact pinned hash; the scheduled gate leaves this override unset.
    cp "$OZPB_ACCOUNT_WASM" "$account_wasm"
else
    # This reproduces the recorded public tag/commit, compiler and CLI pins,
    # hash, and account export set before releasing the artifact to the test.
    # On a mismatch its diagnosis names the build host and the host the account
    # pin needs.
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$account_wasm" \
        OZPB_VERIFIED_SPENDING_POLICY_WASM_OUT="$spending_wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi

# The prediction model recognizes the old policy hash, not the current native library.
# Reproduce that exact Wasm too; a caller-supplied optimization is hash-checked by the test.
if [ -n "${OZPB_SPENDING_POLICY_WASM:-}" ]; then
    cp "$OZPB_SPENDING_POLICY_WASM" "$spending_wasm"
elif [ ! -f "$spending_wasm" ]; then
    OZPB_VERIFIED_SPENDING_POLICY_WASM_OUT="$spending_wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
export OZPB_SPENDING_POLICY_WASM="$spending_wasm"
( cd contracts && cargo test --locked -p ozpb-differential \
    --test policy_prediction -- --ignored ) | tee "$work/prediction.log"
for test in rolling_window_and_amount_boundaries_agree_with_pinned_policy \
    history_capacity_is_applied_after_upstream_cleanup; do
    grep -qx "test $test ... ok" "$work/prediction.log" || {
        echo "required pinned-policy prediction test did not run and pass: $test" >&2
        exit 1
    }
done

python3 - docs/examples/subscription-spec.json "$work/signable-spec.json" <<'PY'
import json
import sys

source, dest = sys.argv[1:]
with open(source, encoding="utf-8") as file:
    spec = json.load(file)
signers = spec["rules"][0]["authorization"]["signers"]
assert len(signers) == 1
assert signers[0]["delegated"]["address"] == "GADQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOBYHA4DQOZPI"
# Public key for the fixed test seed [42; 32]. The matching private key exists
# only in the test process and never becomes part of a generated artifact.
signers[0]["delegated"]["address"] = "GAMX62ZD4FWIKMWGVPEDR6WNL2TYTPQMO2ZJEAZUAON7VCZ5G2GWDF7W"
with open(dest, "w", encoding="utf-8") as file:
    json.dump(spec, file, separators=(",", ":"))
PY

# The generated crate builds offline from the committed generated-contract lockfile, so a
# fresh machine (or CI runner) needs those exact dependencies in the cargo cache first.
( cd contracts/golden-transfer-policy && cargo fetch --locked )
cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/signable-spec.json" --rule 0 --out "$work/generated-policy"

# The Rust test checks this generated Wasm against its reviewed hash, derived
# with rustc 1.91.1, stellar-cli 27.0.0#5a7c5fe and the pinned locks.

export OZPB_ACCOUNT_WASM="$account_wasm"
export OZPB_POLICY_WASM="$work/generated-policy/generated_sub_transfer_r0.wasm"
if ! ( cd contracts && cargo test --locked -p ozpb-differential \
    --test account_wasm_auth -- --ignored --exact pinned_account_wasm_full_authorization ) \
    | tee "$work/test.log"; then
    if grep -q 'account Wasm hash differs from pin' "$work/test.log"; then
        account_host_note
    fi
    exit 1
fi
grep -qx 'test pinned_account_wasm_full_authorization ... ok' "$work/test.log" || {
    echo "the required full-authorization test did not run and pass" >&2
    exit 1
}

# The same two artifacts: direct calls to the policy under alternate account rules, the
# call-surface check over the resulting account state, and state across ledgers.
( cd contracts && cargo test --locked -p ozpb-differential \
    --test account_wasm_invariants -- --ignored ) | tee "$work/invariants.log"
for test in \
    grant_rule_cannot_reach_its_policy_and_rule_zero_is_listed_authority \
    policy_address_rule_can_uninstall_and_call_surface_refuses_it \
    policy_address_rule_held_by_another_key_is_listed_with_its_signer \
    alternate_contract_rule_cannot_reach_policy_methods \
    archived_counter_denies_until_restored \
    extended_rule_validity_does_not_outlive_the_compiled_expiry \
    stale_policy_state_is_refused_not_adopted \
    grant_survives_inactivity_until_its_shortest_ttl \
    failed_composition_rolls_back_the_permitting_policy \
    weak_account_rule_can_create_a_policy_reset_rule \
    weak_management_can_revive_an_expired_rule_without_resetting_its_counter \
    overlapping_real_account_grants_have_independent_caps \
    weak_account_rule_cannot_widen_the_grant_signers_but_can_strip_its_policy \
    weak_account_rule_can_take_over_a_protected_rule_by_adding_its_signer \
    expired_weak_rules_are_noted_and_revived_only_through_live_management \
    archived_management_rule_is_restored_and_used_in_one_transaction \
    weak_account_rule_reaches_the_policy_and_the_code_through_wrapper_methods \
    revoke_then_recreate_never_overlaps_and_bounds_aggregate_use; do
    grep -qx "test $test ... ok" "$work/invariants.log" || {
        echo "required state-invariant test did not run and pass: $test" >&2
        exit 1
    }
done

# Build the small target from reviewed source. Its hash is asserted in the
# joined test, and no Wasm artifact is checked into the repository.
bash scripts/check-build-input-pins.sh
target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
case "$target_dir" in
    /*) ;;
    *) target_dir="$PWD/$target_dir" ;;
esac
CARGO_TARGET_DIR="$target_dir" stellar contract build --locked \
    --manifest-path contracts/authorized-target-fixture/Cargo.toml \
    --package ozpb-authorized-target-fixture
export OZPB_TARGET_WASM="$target_dir/wasm32v1-none/release/ozpb_authorized_target_fixture.wasm"

( cd contracts && cargo test --locked -p ozpb-differential \
    --test candidate_authorization -- --ignored --exact \
    signed_candidate_executes_captured_target_and_denies_adjacent_amount ) \
    | tee "$work/candidate.log"
grep -qx 'test signed_candidate_executes_captured_target_and_denies_adjacent_amount ... ok' \
    "$work/candidate.log" || {
    echo "the required signed candidate target test did not run and pass" >&2
    exit 1
}

# Reuse the already verified public account artifact; build the worker's own
# candidate fixture and require actual protocol-29 authorization and framing.
OZPB_ACCOUNT_WASM="$account_wasm" bash scripts/test-native-execution.sh
OZPB_ACCOUNT_WASM="$account_wasm" bash scripts/test-atomic-live-helper.sh

# The same artifact against captured native-SAC target state: a locally built capture and
# the recorded testnet responses, replayed offline.
OZPB_ACCOUNT_WASM="$account_wasm" bash scripts/test-captured-target.sh
