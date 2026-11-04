#!/usr/bin/env bash
# Codegen determinism and committed-source checks shared by CI and the release gate.
# A Cargo test filter exits 0 on zero matches. Use full names and require exactly one pass.
set -euo pipefail
cd "$(dirname "$0")/.."
if [ "${UPDATE_GOLDEN+x}" = x ]; then
    echo "  CODEGEN CHECK REFUSED: unset UPDATE_GOLDEN before checking committed crates" >&2
    exit 2
fi

expected='test result: ok\. 1 passed;'
for name in generation_is_byte_deterministic \
            golden_crate_matches_committed_output \
            soroswap_crate_matches_committed_output; do
    test_name="tests::$name"
    if ! output="$(cargo test --locked -q -p ozpb-codegen --lib "$test_name" -- --exact 2>&1)"; then
        echo "  CODEGEN CHECK FAILED: $test_name" >&2
        printf '%s\n' "$output" | tail -20 >&2
        exit 1
    fi
    if [[ ! "$output" =~ $expected ]]; then
        echo "  CODEGEN CHECK ASSERTED NOTHING: $test_name did not pass exactly once" >&2
        printf '%s\n' "$output" | tail -20 >&2
        exit 1
    fi
    echo "  $test_name: one passing test"
done
