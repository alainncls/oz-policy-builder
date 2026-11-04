#!/usr/bin/env python3
"""Construct a synthetic native-execution test job; this is not a trust receipt."""
import base64
import hashlib
import json
from pathlib import Path
import sys

root = Path(__file__).resolve().parent.parent
mode, work_arg = sys.argv[1:]
work = Path(work_arg)
account = (work / "pinned-account.wasm").read_bytes()
if mode == "spec":
    spec = json.loads((root / "docs/examples/subscription-spec.json").read_text())
    spec["smart_account"]["observed_code_hash"] = hashlib.sha256(account).hexdigest()
    rule = spec["rules"][0]
    rule["authorization"]["signers"] = [{
        "delegated": {"address": "GAMX62ZD4FWIKMWGVPEDR6WNL2TYTPQMO2ZJEAZUAON7VCZ5G2GWDF7W"}
    }]
    rule["policies"] = [p for p in rule["policies"] if "generated" in p]
    assert len(rule["policies"]) == 1
    (work / "spec.json").write_text(json.dumps(spec, separators=(",", ":")))
elif mode == "job":
    spec = json.loads((work / "spec.json").read_text())
    generated = work / "generated"
    manifest = json.loads((generated / "build-manifest.json").read_text())
    wasm = (generated / "generated_sub_transfer_r0.wasm").read_bytes()
    assert hashlib.sha256(wasm).hexdigest() == manifest["wasm_hash"]
    files = {name: (generated / name).read_text() for name in [
        "Cargo.toml", "rust-toolchain.toml", "rustfmt.toml", "src/lib.rs", "src/contract.rs"
    ]}
    candidate = {
        "spec": spec, "rule_index": 0,
        "binding_set": {
            "schema": "policy-binding-set/v1", "spec_hash": manifest["spec_hash"],
            "network_id": spec["network_id"],
            "bindings": [{
                "rule_index": 0, "policy_index": 0,
                "contract_address": "CAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCQKBIFAUCRUA6",
                "observed_wasm_hash": manifest["wasm_hash"],
                "recognition": {"kind": "verified_generated_manifest", "build_manifest": manifest},
                "resolution_reference": "synthetic native execution test",
            }],
        },
        "signed_registry_snapshot": json.loads((root / "docs/examples/registry.signed.json").read_text()),
        "account_address": spec["smart_account"]["address"],
        "network_id": spec["network_id"], "rpc_source": "synthetic-fixture",
    }
    job = {
        "schema": 1,
        "request": {
            "candidate": candidate,
            "artifact": {
                "spec": spec, "rule_index": 0, "claimed_generated_files": files,
                "claimed_wasm_base64": base64.b64encode(wasm).decode(),
                "claimed_build_manifest": manifest,
            },
            "candidate_context_rule_id": 7, "run_nonce": "11" * 32,
        },
        "account_wasm_base64": base64.b64encode(account).decode(),
        "ledger": {
            "protocol_version": 30, "sequence": 1000, "timestamp": "100000",
            "base_reserve": 5000000, "min_temp_entry_ttl": 16,
            "min_persistent_entry_ttl": 4096, "max_entry_ttl": 631200,
        },
    }
    (work / "job.json").write_text(json.dumps(job, separators=(",", ":")) + "\n")
else:
    raise SystemExit("expected spec or job")
