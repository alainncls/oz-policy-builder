# Direct local agent-to-wallet handoff

The Policy Builder can deliver a confirmed grant proposal from Claude to an open wallet
session without copying proposal JSON or invoking a second skill. This supports the existing
exact native-XLM testnet transfer shape, with a call cap of at most 512 so the native
execution checks can run. Manual import accepts up to 10,000 for inspection, but a cap above
512 cannot complete the current worker checks. Claude and the wallet backend must run on the same
computer. A remote hosted MCP server cannot reach a user's local wallet; no relay or general
wallet-connection protocol is supplied.

## Use it

1. Open the applied Pollywallet Policy Builder using the local wallet launcher's session URL.
   Create or attach the recognized account. Keep that session URL private.
2. Select **Connect Claude**. The wallet creates its automation delegate if needed and shows
   a one-time pairing code. Paste only that code into Claude and ask it to connect the wallet.
3. Describe the grant. Claude uses the returned public account, delegate and wallet limits
   when clarifying the decisions, then generates and checks the policy. Review the full final
   permission card and explicitly confirm it.
4. Claude calls `send_wallet_proposal`. The wallet shows that an unverified proposal arrived;
   it does not replace the current candidate or start checks merely because a draft arrived.
5. Select **Review proposal from Claude**. The wallet independently records the transaction,
   regenerates the artifact and compares every supported permission, using the same import
   path as manual JSON/file import. Review the result, then continue through the existing
   deployment, execution-check and passkey installation approvals.
6. Select **Disconnect Claude** when finished. Disconnecting draft delivery does not revoke
   an installed on-chain grant; the existing grant removal and recovery controls remain.

The pairing code expires after five minutes and can be redeemed once. The resulting connection
expires after thirty minutes without renewal by polling. Each pending draft expires after five
minutes. Explicit disconnect or reconnect invalidates the previous pairing, connection and
pending draft. Closing or reloading the browser is not a reliable revocation mechanism; server
expiry remains authoritative. Disconnect before changing the attached account or delegate.

Manual **Import a grant proposal** remains available. The human-invoked install skill is the
fallback for an unavailable local connection or a grant outside this wallet's supported shape.
For a previously dismissed or expired proposal, reconnect and obtain a fresh complete card
and confirmation before sending it again; do not modify formatting to bypass a receipt.

## Authority and data boundaries

| Credential | Purpose | Where it goes |
| --- | --- | --- |
| Wallet browser session bearer | Existing wallet actions | Wallet browser and local backend only; never Claude/MCP |
| One-time pairing code | Exchange for draft delivery to the selected account/delegate | User provides it to the local MCP session; five-minute expiry |
| Draft capability | Stage a bounded unverified proposal | Retained privately inside that MCP session; never returned in tool results |
| Delegate signing capability | Existing wallet execution checks | Wallet backend/browser control path only; never the agent bridge |

Pairing checks that the selected delegate capability belongs to the backend. The bridge exposes
only `POST /agent/connect` and `POST /agent/proposal`; neither can dispatch arbitrary wallet
operations. Native requests require the exact literal loopback Host and no browser Origin.
The existing browser Host, Origin and full-session bearer checks are unchanged. Native body
reads have separate bounded admission and cannot hold the privileged wallet action lock.

A delivered proposal is raw JSON, at most 16 KiB, checked by the existing strict duplicate-key
and schema parser and bound to the paired account and delegate. Delivery does not compile,
read RPC, deploy, request a signature, install, or clear an existing candidate. Wallet review
consumes the pending draft before starting independent import. A failed import cannot revive it.

The content hash identifies a delivery. Identical retries return the existing receipt without
re-enqueueing, including after claim, dismissal or expiry. At most one draft and eight receipt
records are retained per connection. A `pending` receipt means staged; `claimed` means the user
started wallet review, not that verification passed. Session expiry/re-pair clears this bounded
memory-only state. No durable proposal service or custody is introduced.

Chat confirmation is enforced by the skill and checked by the transcript checker; a tool input
cannot prove human consent. The wallet's independent verification and owner signature remain
the enforceable installation boundary.

## Operator setup and verification

The development stdio launcher sets `OZPB_WALLET_HANDOFF_URL=http://127.0.0.1:4317`, matching the
current local wallet backend. A direct stdio launch can set that variable explicitly. Only an
HTTP literal `127.0.0.1` origin with no credentials, query, fragment or path is accepted. The
model cannot select a destination. Redirects and proxy environment inheritance are disabled;
response bodies are bounded and transport errors are redacted. Hosted HTTP MCP never enables
this local bridge, even if the environment variable is present.

A container has its own loopback network unless explicitly configured otherwise. Do not assume
that running MCP in a container or on another machine connects it to the browser user's wallet.
Use the supported same-machine setup or manual import.

Run the wallet tests with `OZPB_MCP_BIN` pointing to the built `ozpb-mcp-server` to include the
actual stdio MCP → real wallet HTTP → production browser client/controller tests. CI builds
that binary and enables those tests. They cover separate MCP sessions, one-time pairing,
proposal staging without privileged effects, explicit review, retry after claim, disconnect,
failed reconnect, redirect refusal, proxy exclusion and credential redaction.

For the applied wallet UI, start it on an isolated localhost port and run:

```sh
OZPB_BROWSER_CHANNEL=chrome node scripts/test-wallet-agent-browser.mjs http://localhost:3109
```

This drives the real UI with controlled RPC/build dependencies. It checks pairing, arrival,
review, verified import, consumed-draft retries and disconnect. It is not live-chain evidence
or an attestation of human approval. Existing wallet execution/signature suites cover their
separate boundaries; this transport does not broaden the supported grant shape.
