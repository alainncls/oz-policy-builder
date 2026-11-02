---
name: policy-builder-install
description: >-
  Hand off a grant the user has confirmed on the policy-builder skill's Confirm-before-deploy
  card: print the ozpb-grant-proposal/v1 artifact for the user's wallet to import, or the
  user-run deploy and unsigned-assembly path. Never deploys, signs or submits.
disable-model-invocation: true
---

# Hand off a confirmed grant

The user started this skill; you cannot start it yourself. It hands off a grant the user has
already confirmed. It never deploys, signs or submits anything, never asks for a secret key, and
does not decide that an installation is acceptable: the wallet that holds the owner key does.

## 1. Check the confirmation

Look back through this conversation. Continue only if all of these hold:

- the last `synthesize_policy` call succeeded, and its spec is the grant being handed off;
- after that call you showed the complete Confirm-before-deploy card for that spec (every
  label of the policy-builder skill's card, with every address and hash in full);
- after that card the user replied with just `confirm` (or "yes, I confirm"), nothing added;
- nothing happened after the confirmation: no other message from the user (starting this skill
  aside), no new `synthesize_policy` call, decision, dry-run report or authority result.

Otherwise show the card again for the current spec, ask for `confirm`, and wait. Anything other
than an explicit confirmation is not one. An authority refusal on the card stops the handoff
whatever the user replies.

## 2. Choose the path

Use the wallet proposal only when every one of these holds for the confirmed spec:

- it came from `record_transaction` on a confirmed transaction of the user's wallet account,
  on testnet;
- one rule; one delegated `G…` signer; predicate `any_of` with `strict_signer_set: true`;
- an expiry ledger and a call cap of 1 to 512 calls (the wallet does not take unlimited
  calls or no expiry);
- every argument constraint is exact (`eq_*`): no widening, no adapter-derived constraint;
- the only policy is the generated scope policy (no spending limit);
- the only call is the native XLM Stellar Asset contract's `transfer` from `SELF` to a
  `G…` recipient, with an exact positive i128 amount;
- the grant name is lowercase letters, digits and hyphens, starting with a letter, at most 20
  characters.

The local wallet integration accepts this proposal through **Import a grant proposal**. The
account must be the wallet's own recognized account. The wallet records the transaction again
by hash while RPC retains it, and requires expiry within 17,280 ledgers of its current ledger.
For execution checks and installation, use the automation delegate created by that wallet
backend session; an external delegate can be imported for inspection but cannot complete those
checks. The wallet decides; a refusal is final, not something to work around.

Manual import also accepts caps up to 10,000 for inspection, but caps above 512 cannot complete
the wallet's execution checks or installation. For a larger cap, use the user-run path in
section 4; do not send it back to wallet import as an installation workaround. Reducing the cap
changes the grant and requires synthesis again, a new complete card and a new confirmation.

For anything else, use the user-run path in section 4.

## 3. The wallet proposal

Read `../policy-builder/references/wallet-proposal.md` for the exact schema and field mapping.
Print the proposal as one fenced JSON block for manual paste/file import. The connected flow
in the main policy-builder skill uses the same format and does not require starting this skill.

## 4. The user-run path

For a grant the wallet does not take, print these steps for the user to run with their own keys
and tools. You run none of them. `<network>` is the network the user recorded on, whose ID is
the spec's `network_id` (`testnet` in the development setup); stop if you cannot tell which.

1. Offer to write the confirmed `spec` to `spec.json` unchanged.
2. For each rule `i`: `ozpb generate --spec spec.json --rule <i> --out generated-r<i>`, then
   `ozpb verify` on that output (`docs/DEVELOPERS.md`). In `generated-r<i>/build-manifest.json`,
   `spec_hash` must equal the confirmed spec hash; note its `wasm_hash`.
3. Upload the verified Wasm with the user's own key. The hash it prints must equal `wasm_hash`:

   ```sh
   stellar contract upload --wasm generated-r<i>/<the .wasm file> \
     --source-account <your key name> --network <network>
   ```
4. Deploy by that hash, so the instance runs exactly the verified code (no constructor
   arguments):

   ```sh
   stellar contract deploy --wasm-hash <wasm_hash> \
     --source-account <your key name> --network <network>
   ```
5. A composed spending limit needs an instance of the reviewed policy whose code hash is the
   spec's `capability`, for example `stellar contract deploy --wasm-hash <capability> …` when
   that code is on the network. Its limit and period are set at installation.
6. When the user gives you the deployed addresses, build the binding set
   (`policy-binding-set/v1`: generated policies as `verified_generated_manifest` with their build
   manifest, a reviewed policy as `reviewed_registry`), call `check_policy_call_surface`, and show
   a new Confirm-before-deploy card with its authority list. Only after the user confirms that
   card, call `assemble_install_transaction` with the user's fee payer, fee ceiling and a validity
   window of at most 120 ledgers.
7. Read its `restoration` field first. `separate_transaction_reassemble_required` means the
   response holds only a restore transaction, not an installation: after the user's wallet has
   run that restoration, the authority check and assembly start again, with a new card. For
   `none` or `automatic_within_invocation`, the unsigned XDR is an installation draft for a
   wallet, not something to sign as is: it carries the owner's authorization unsigned, as
   recorded. A wallet must validate every field, recheck authority, build the owner
   authorization and enforce-simulate before signing (`docs/INSTALL-ASSEMBLY.md`);
   `stellar tx sign` alone does none of that. Say so, and stop.


For a transcript-checkable file handoff, use the structured file-write tool with the full JSON
content, or a single literal `cat > proposal.json <<'EOF'` heredoc ending at `EOF`. Shell pipes,
substitutions, generators and later commands make the written bytes unverifiable to the checker.
For unsigned assembly use the structured MCP tool with `intent_request` equal to the successful
current authority-check request. The checker cannot verify the contents of a CLI request file
and flags that path for manual review.
