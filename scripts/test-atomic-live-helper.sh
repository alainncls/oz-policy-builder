#!/usr/bin/env bash
# Real owner/delegate authorization and SAC effects in an isolated protocol-30 host.
# This script neither contacts an RPC nor produces live signatures/submissions.
set -euo pipefail
cd "$(dirname "$0")/.."
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [ -n "${OZPB_ACCOUNT_WASM:-}" ]; then
    cp "$OZPB_ACCOUNT_WASM" "$work/pinned-account.wasm"
else
    OZPB_VERIFIED_ACCOUNT_WASM_OUT="$work/pinned-account.wasm" \
        env -u CARGO_TARGET_DIR bash scripts/verify-pinned-upstream.sh
fi
python3 scripts/atomic-live-helper-fixture.py "$work"
# Generation builds offline from the committed generated-contract lockfile, so a fresh machine
# needs those exact dependencies in the cargo cache first; building the CLI does not fetch them.
( cd contracts/golden-transfer-policy && cargo fetch --locked )
cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/spec.json" --rule 0 --out "$work/generated"
cargo run --locked --quiet -p ozpb-cli -- generate \
    --spec "$work/spec-uncapped.json" --rule 0 --out "$work/generated-uncapped"
stellar contract build --locked --manifest-path contracts/atomic-live-helper/Cargo.toml \
    --package ozpb-atomic-live-helper --out-dir "$work"
mv "$work/ozpb_atomic_live_helper.wasm" "$work/atomic-helper.wasm"
# The Rust test asserts the reviewed helper hash; this pins the export set of the same bytes,
# so no relay, admin or upgrade entry point can appear without a reviewed change here.
python3 scripts/check-wasm-exports.py "$work/atomic-helper.wasm" \
    contracts/atomic-live-helper/exports.txt \
    "$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' \
        "$work/atomic-helper.wasm")"
export OZPB_ATOMIC_TEST_DIR="$work"
cargo test --manifest-path execution-runtime/Cargo.toml --locked --test atomic_helper -- \
    --include-ignored | tee "$work/result.log"
for test in \
    atomic_helper_installs_and_transfers_with_separate_real_v2_owner_and_delegate_auth \
    atomic_helper_adjacent_policy_denial_rolls_back_installation_target_and_nonces \
    atomic_helper_refuses_missing_owner_or_delegate_and_preserves_all_state \
    atomic_helper_refuses_substituted_or_altered_signatures_and_preserves_all_state \
    atomic_helper_refuses_expired_signatures_or_grant_and_preserves_all_state \
    atomic_helper_guards_refuse_out_of_scope_candidates_and_preserve_all_state \
    atomic_helper_refuses_a_transfer_not_authorized_by_the_candidate_rule \
    atomic_helper_refuses_a_policy_without_an_observable_counter \
    counter_guard_is_satisfied_by_an_unexecuted_candidate_context \
    permit_case_authorizations_install_and_transfer_without_the_helper; do
    grep -qx "test $test ... ok" "$work/result.log" || {
        echo "required atomic helper test did not run and pass: $test" >&2
        exit 1
    }
done
