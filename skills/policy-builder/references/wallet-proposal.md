# Wallet proposal format

Construct exactly this object from the confirmed tool outputs. For direct delivery serialize it
as `send_wallet_proposal.proposal_json`; for manual import print one fenced `json` block:

```json
{
  "schema": "ozpb-grant-proposal/v1",
  "network_id": "<spec.network_id>",
  "transaction_hash": "<tx_hash of the record_transaction call>",
  "decisions": {
    "grant_name": "<decisions.grant_name>",
    "delegate": "<decisions.delegate_signers[0].delegated.address>",
    "valid_until_ledger": 0,
    "max_calls": 0,
    "unlimited_calls_acknowledged": false
  },
  "expected_grant": {
    "account": "<spec.smart_account.address>",
    "rules": [
      {
        "context": {
          "type": "<rule.context.type>",
          "contract": "<rule.context.contract>",
          "target_code_hash": null
        },
        "calls": [{ "fn": "<call.fn>", "args": [{ "i": 0, "c": {} }] }],
        "authorization": {},
        "valid_until_ledger": 0,
        "max_calls": 0,
        "policy_kinds": ["<policy kind>"]
      }
    ]
  },
  "spec_hash": "<synthesize_policy spec_hash>"
}
```

Copy every value from the tool calls in this conversation, exactly; never retype one from
memory, shorten it, or fill one in:

- `network_id` and `spec_hash`: the confirmed `synthesize_policy` output.
- `transaction_hash`: the `tx_hash` passed to the `record_transaction` call whose bundle that
  synthesis used, in lowercase.
- `decisions`: the decisions passed to that `synthesize_policy` call. `delegate` is the one
  delegated address; `unlimited_calls_acknowledged` is `false` when the field was absent.
- `expected_grant`: the spec's grant projection. `account` is `smart_account.address`. For each
  rule, in order: `context` is the rule's `type` and `contract`, and `target_code_hash` is the
  rule's `target_code_hash.hash`, or `null` when it has none (a Stellar Asset contract), so the
  wallet can refuse a target whose code changed;
  `calls` is `allowed_calls` with each call's `fn` and each argument's `i` and `c` only (no
  `prov`, no `justified_by`); `authorization` is the rule's `authorization` unchanged;
  `valid_until_ledger` is `valid_until.ledger` or `null`; `max_calls` is the
  `call_count_per_installation` cap or `null`; `policy_kinds` is each policy's `kind`, in order.

No other field. Explain briefly how the wallet treats the unverified proposal:

- as untrusted: it records the transaction again through its own RPC, synthesizes again with
  its own toolchain from its own decisions document, compares the grant projection, and
  refuses any difference, any widening and any spending limit. Spec hashes are shown but need
  not match, because two acquisitions can observe different context;
- it shows the delegate, expiry and cap for approval and owns deployment consent, the owner
  signature and submission.

