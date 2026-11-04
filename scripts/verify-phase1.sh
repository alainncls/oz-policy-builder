#!/usr/bin/env bash
# Phase 1 acceptance gate (architecture §10 Phase 1 verifiable outcome):
# a recorded transfer becomes a compilable Rust policy, byte-identical across two cold
# runs, agreeing with the reference evaluator including zero-signer + strict-set denial.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=release
case "${1:-}" in
    "") ;;
    --offline) MODE=offline ;;
    *) echo "usage: bash scripts/verify-phase1.sh [--offline]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "usage: bash scripts/verify-phase1.sh [--offline]" >&2
    exit 2
fi

# python3 is required in BOTH modes: the quoted-hash gate below runs unconditionally, so a
# machine without it must hear that from this check, not from a raw command-not-found later.
command -v python3 >/dev/null 2>&1 || { echo "this gate requires python3 in every mode" >&2; exit 1; }
if [ "$MODE" = release ]; then
    for tool in stellar cargo-deny cargo-machete; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "release gate requires $tool; use --offline only for the explicitly reduced gate" >&2
            exit 1
        }
    done
else
    echo "OFFLINE MODE: stellar-cli build/reproducibility and cargo-deny license gates will not run"
fi

# A review records `git status --short` beside this gate's result, so the gate must not edit the
# tree it checks: a lockfile cargo rewrote along the way would read as the reviewer's own change.
# Snapshot tracked content now and compare at the end. Only at the root of a checkout with a
# commit (asked of git, not by comparing paths, which differ in case on macOS), so a source
# archive unpacked inside some other repository is not compared against that repository.
tracked_state() { git diff HEAD --binary --no-ext-diff --no-textconv | git hash-object --stdin; }
TRACKED_BEFORE=""
if prefix="$(git rev-parse --show-prefix 2>/dev/null)" && [ -z "$prefix" ] \
    && git rev-parse -q --verify HEAD >/dev/null; then
    TRACKED_BEFORE="$(tracked_state)"
fi

echo "== 1. dependency rules (evaluator ↛ codegen; cores transport-free) =="
bash scripts/check-dep-rules.sh
bash scripts/test-check-dep-rules.sh

echo "== 1b. publication, build-input and quoted-hash invariants =="
bash scripts/check-publication-allowlist.sh
bash scripts/check-build-input-pins.sh
python3 scripts/check-quoted-hashes.py
python3 scripts/test-check-wasm-exports.py

# clippy also carries the hash-determinism gate: `clippy.toml` disallows `HashMap`/`HashSet`
# (per-process iteration order) and floats (no faithful JSON form, absent from `ScVal`) so the
# rule that keeps serialized bytes stable is checked rather than stated in a comment.
#
# Both workspaces, because the root `Cargo.toml` excludes `contracts` and `--workspace` therefore
# never reaches it. `clippy.toml` does apply there — clippy walks up to the repository root to
# find it — so a single invocation would leave this gate reporting a pass while the contracts
# workspace held a banned type. That is the shape of defect this gate exists to prevent, and CI
# lints the two workspaces separately for the same reason.
#
# `--all` covers only the current workspace. The two generated crates are excluded from
# `contracts` so they can carry standalone release profiles. Name both explicitly for fmt and
# clippy, as CI does; compiling one as a dependency does not lint or reliably format it.
#
# Every command below that resolves a workspace passes --locked, so a lockfile that no longer
# matches its manifests fails here instead of being rewritten in the tree under review. fmt does
# not resolve, and cargo-machete has no such flag; step 9 catches whatever still writes.
echo "== 2. fmt + clippy (fmt/clippy gates are part of the contract, §4.11) =="
cargo fmt --all --check
( cd contracts && cargo fmt --all --check )
( cd contracts/golden-transfer-policy && cargo fmt --all --check )
( cd contracts/soroswap-swap-policy && cargo fmt --all --check )
cargo clippy --locked --workspace --all-targets -- -D warnings
( cd contracts && cargo clippy --locked --all-targets -- -D warnings )
( cd contracts/golden-transfer-policy && cargo clippy --locked --all-targets -- -D warnings )
( cd contracts/soroswap-swap-policy && cargo clippy --locked --all-targets -- -D warnings )

echo "== 3. host workspace test suite (TDD) =="
cargo test --locked --workspace

echo "== 4. contracts: differential suite (evaluator vs real compiled policy) =="
( cd contracts && cargo test --locked -p ozpb-differential )

echo "== 5. determinism: codegen is byte-identical and both committed crates are in step =="
# The shared CI/release check runs each full test name with --exact and requires one passing
# test. Cargo exits 0 when a filter matches nothing, so a successful process alone is vacuous.
bash scripts/check-codegen-fixtures.sh
# The end-to-end shell path additionally proves the CLI emits those same bytes, but it
# compiles the policy, so it needs the toolchain.
if [ "$MODE" = release ]; then
    rm -rf target/det-a target/det-b
    cargo run --locked -q -p ozpb-cli -- generate --spec docs/examples/subscription-spec.json --rule 0 --out target/det-a
    cargo run --locked -q -p ozpb-cli -- generate --spec docs/examples/subscription-spec.json --rule 0 --out target/det-b
    # Every emitted source file, digested together. The crate root is a header and a `pub mod`
    # declaration, so hashing it alone would compare the half that does not vary with the rule —
    # a determinism check that passes because it is looking at the wrong file.
    #
    # `cd` into each `src/` first, so the names `shasum` prints are relative. Digesting its output
    # from here instead folds the output directory's own name into the result, and the two digests
    # then differ for identical content: a check that fails unconditionally, which is the other
    # way to be looking at the wrong thing. Measured both ways before settling on this one.
    digest_sources() {
        local count
        count=$(find "$1" -name '*.rs' | wc -l | tr -d ' ')
        [ "$count" -gt 0 ] || { echo "  no generated sources in $1 to compare" >&2; return 1; }
        ( cd "$1" && find . -name '*.rs' | sort | xargs shasum -a 256 ) \
            | shasum -a 256 | cut -d' ' -f1
    }
    A=$(digest_sources target/det-a/src)
    B=$(digest_sources target/det-b/src)
    [ "$A" = "$B" ] || { echo "  CLI CODEGEN NON-DETERMINISTIC"; exit 1; }
    echo "  CLI end-to-end byte-identical across all emitted sources: $A"
else
    echo "  OFFLINE: end-to-end CLI compile check not run"
fi

echo "== 6. wasm reproducibility (requires stellar-cli) =="
if [ "$MODE" = release ]; then
    # A note, not a gate: this compares two builds made with whatever CLI is installed, so its
    # verdict holds at any version. But `stellar contract build` stamps its own version into the
    # wasm (`cliver` in contractmetav0), so the hash printed below is only *this* CLI's — it will
    # not equal the recorded hashes, or CI's, on a different one. Gates whose verdict does depend
    # on the version (scripts/verify-pinned-upstream.sh) fail instead of noting.
    #
    # Advisory means advisory: `set -euo pipefail` is in force, so both probes are allowed to fail
    # and are read afterwards. Otherwise a reformatted documentation table would abort this gate
    # after clippy and the whole test suite had already passed, for a line that is only ever
    # informational.
    EXPECTED_CLI="$(bash scripts/recorded-build-inputs.sh stellar-cli 2>/dev/null || true)"
    HAVE_CLI="$(stellar --version 2>/dev/null | awk 'NR==1 {print $2}' || true)"
    if [ -z "$EXPECTED_CLI" ]; then
        echo "  note: could not read the recorded stellar-cli version, so whether this CLI matches"
        echo "        the one the recorded hashes were built with is undetermined"
    elif [ "$HAVE_CLI" != "$EXPECTED_CLI" ]; then
        echo "  note: stellar-cli ${HAVE_CLI:-unknown} (this repo pins $EXPECTED_CLI);" \
             "the hash below is this CLI's alone"
    fi
    # The golden crate is EXCLUDED from the contracts workspace (it carries its own
    # [profile.release], which a workspace member would not get), so it is its own workspace
    # root and `stellar contract build` writes to ITS target dir — not contracts/target.
    #
    # This gate used to hash contracts/target/..., which the rebuild never touches: that copy
    # comes from the differential suite building the crate as a dev-dependency. It compared one
    # untouched file with itself and passed unconditionally. The two copies do not even have the
    # same hash, because they are built in different contexts.
    G=contracts/golden-transfer-policy
    W="$G/target/wasm32v1-none/release/generated_sub_transfer_r0.wasm"
    ( cd "$G" && stellar contract build --locked >/dev/null 2>&1 )
    H1=$(shasum -a 256 "$W" | cut -d' ' -f1)
    ( cd "$G" && cargo clean >/dev/null 2>&1 )
    # Non-vacuity: if the artifact survives the clean, the rebuild below proves nothing.
    [ -f "$W" ] && { echo "  cargo clean did not remove the wasm — this gate would be vacuous"; exit 1; }
    ( cd "$G" && stellar contract build --locked >/dev/null 2>&1 )
    H2=$(shasum -a 256 "$W" | cut -d' ' -f1)
    [ "$H1" = "$H2" ] && echo "  wasm byte-identical across a full clean rebuild: $H1" \
        || { echo "  WASM DIFFERS: $H1 vs $H2"; exit 1; }

    echo "== 6b. real builder boundary + metadata reconciliation tests =="
    cargo test --locked -p ozpb-build-runner -- --ignored --test-threads=1
else
    echo "  OFFLINE: wasm reproducibility not run"
    echo "  OFFLINE: ignored real-builder tests not run"
fi

echo "== 7. license & supply-chain gate (permissive-license requirement, §4.11) =="
if [ "$MODE" = release ]; then
    bash scripts/check-licenses.sh
else
    echo "  OFFLINE: cargo-deny license/supply-chain gate not run"
fi

echo "== 8. unused dependencies =="
if [ "$MODE" = release ]; then
    bash scripts/check-unused-deps.sh
else
    echo "  OFFLINE: cargo-machete unused-dependency gate not run"
fi

echo "== 9. the gate left tracked files as it found them =="
if [ -z "$TRACKED_BEFORE" ]; then
    echo "  not run: not at the root of a git checkout"
elif [ "$(tracked_state)" != "$TRACKED_BEFORE" ]; then
    echo "  THIS GATE MODIFIED TRACKED FILES (the list includes any edits made before the run):" >&2
    git status --short --untracked-files=no >&2
    exit 1
else
    echo "  tracked files unchanged"
fi

if [ "$MODE" = release ]; then
    echo "ALL PHASE 1 RELEASE GATES PASSED"
else
    echo "ALL OFFLINE PHASE 1 GATES PASSED (release-only toolchain gates not run)"
fi
