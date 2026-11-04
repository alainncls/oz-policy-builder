#!/usr/bin/env bash
# Automatable Phase 2 checks. Passing is not acceptance of the full §10 milestone.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE=release
case "${1:-}" in
    "") ;;
    --offline) MODE=offline ;;
    *) echo "usage: bash scripts/verify-phase2.sh [--offline]" >&2; exit 2 ;;
esac
if [ "$#" -gt 1 ]; then
    echo "usage: bash scripts/verify-phase2.sh [--offline]" >&2
    exit 2
fi

command -v python3 >/dev/null 2>&1 || { echo "this gate requires python3 in every mode" >&2; exit 1; }
# Same tracked-file comparison as the Phase 1 gate, over this whole command.
tracked_state() { git diff HEAD --binary --no-ext-diff --no-textconv | git hash-object --stdin; }
TRACKED_BEFORE=""
if prefix="$(git rev-parse --show-prefix 2>/dev/null)" && [ -z "$prefix" ] \
    && git rev-parse -q --verify HEAD >/dev/null; then
    TRACKED_BEFORE="$(tracked_state)"
fi
if [ "$MODE" = release ]; then
    for tool in stellar cargo-deny cargo-machete; do
        command -v "$tool" >/dev/null 2>&1 || {
            echo "release gate requires $tool; use --offline only for the explicitly reduced gate" >&2
            exit 1
        }
    done
    bash scripts/verify-phase1.sh
else
    echo "OFFLINE MODE: reduced checks; Cargo may still fetch dependencies"
    bash scripts/verify-phase1.sh --offline
fi

python3 scripts/test-check-phase2-evidence.py
bash scripts/check-phase2-evidence.sh

if [ "$MODE" = release ]; then
    echo "== W3: committed Soroswap policy builds to Wasm =="
    # A fresh output directory prevents an old artifact from satisfying the output check.
    WASM_DIR="$(mktemp -d)"
    trap 'rm -rf "$WASM_DIR"' EXIT
    stellar contract build --locked --manifest-path contracts/soroswap-swap-policy/Cargo.toml \
        --out-dir "$WASM_DIR"
    python3 - "$WASM_DIR/generated_soroswap_swap_r0.wasm" <<'PY'
import sys
from pathlib import Path

wasm = Path(sys.argv[1])
if not wasm.is_file() or wasm.read_bytes()[:8] != b"\x00asm\x01\x00\x00\x00":
    sys.exit("W3 build did not produce a WebAssembly module in the fresh output directory")
print("W3 Wasm build produced a module (compilation evidence, not live execution)")
PY
else
    echo "OFFLINE: W3 Wasm build not run; Phase 1 release-only checks were also omitted"
fi

echo "== the gate left tracked files as it found them =="
if [ -z "$TRACKED_BEFORE" ]; then
    echo "  not run: not at the root of a git checkout"
elif [ "$(tracked_state)" != "$TRACKED_BEFORE" ]; then
    echo "  THIS GATE MODIFIED TRACKED FILES (the list includes any edits made before the run):" >&2
    git status --short --untracked-files=no >&2
    exit 1
else
    echo "  tracked files unchanged"
fi

echo "AUTOMATED PHASE 2 CHECKS PASSED ($MODE mode)"
echo "This is not full Tranche 2 acceptance. Live wallet installation/revocation, hosted service,"
echo "and end-to-end W1/W2/W3 walkthrough evidence require separate review."
echo "See docs/TRANCHE-2-VERIFICATION.md."
