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
4. Claude calls `send_wallet_proposal`, and Claude Code asks you to approve that call;
   neither the plugin nor the skill pre-approves it. The wallet shows that an unverified
   proposal arrived; it does not replace the current candidate or start checks merely because
   a draft arrived.
5. Select **Review proposal from Claude**. The wallet independently records the transaction,
   regenerates the artifact and compares every supported permission, using the same import
   path as manual JSON/file import. Review the result, then continue through the existing
   deployment, execution-check and passkey installation approvals.
6. Select **Disconnect Claude** when finished. Disconnecting draft delivery does not revoke
   an installed on-chain grant; the existing grant removal and recovery controls remain.

The pairing code expires after five minutes and can be redeemed once. The resulting connection
expires thirty minutes after pairing; polling does not extend it. Each pending draft expires
after five minutes, so review it soon after it arrives. Explicit disconnect or reconnect
invalidates the previous pairing, connection and pending draft. Closing or reloading the
browser is not a reliable revocation mechanism; server expiry remains authoritative.
Disconnect before changing the attached account or delegate.

Keep the wallet page open from **Connect Claude** until you review the proposal. The page
holds the automation delegate's handle only in memory, and reopening it starts a new page
session from the launcher URL. A reopened page shows that Claude is still connected, or that an
earlier pairing code is still valid, and whether a draft is waiting, and keeps that notice up to
date until the connection ends; it cannot review that draft. Select **Disconnect Claude**, or
**Connect Claude**, which replaces the connection with a new automation delegate. Claude then
has to synthesize the grant again for the new delegate and show a new card. Each such
connection uses one of the backend's eight automation-delegate slots; restarting the wallet
backend frees them and also ends every connection.

Manual **Import a grant proposal** remains available. The human-invoked install skill is the
fallback for an unavailable local connection or a grant outside this wallet's supported shape.
For a cap above 512, use that skill's section 4 user-run deployment path, not manual wallet
import: larger caps can be imported for inspection but cannot complete execution checks or
installation. Alternatively agree on a lower cap, synthesize again and confirm the new card.
For a previously dismissed or expired proposal, reconnect and obtain a fresh complete card
and confirmation before sending it again; do not modify formatting to bypass a receipt.

## When the wallet refuses

The wallet answers a refused native request with one closed reason and never echoes the
request. The MCP tools turn the reason into a code that says what the agent does next, and a
fixed message; no other reply text reaches the conversation.

| Code | Wallet reasons | What happens next |
| --- | --- | --- |
| `E_WALLET_BUSY` | `busy`, `capacity` | Retry once with identical input after a few seconds; if still busy, the user finishes the current wallet action. |
| `E_WALLET_DRAFT_PENDING` | `draft_pending` | An earlier, different proposal from the same session is waiting; nothing was sent. If the new grant replaces it, the user dismisses it in the wallet, or, on a page reopened since pairing, disconnects and connects again. |
| `E_WALLET_PAIRING_REQUIRED` | `pairing_refused`, `connection_unavailable`, `delivery_limit` | The code was wrong, used or expired, or the connection expired, was replaced or received eight proposals. The user selects Connect Claude for a fresh code. |
| `E_WALLET_PROPOSAL_REFUSED` | `proposal_invalid`, `delegate_mismatch`, `call_limit` | The content was refused: malformed, not for the connected account, an unsupported shape, another delegate, or more than 512 calls. Reconnecting does not help. |
| `E_WALLET_UNAVAILABLE` | anything else | No bridge on this server (always so for hosted MCP), no answer, or a reply that was not understood. After an unanswered send, retry the identical proposal once; otherwise use manual import. |

A caller without the draft capability always gets `connection_unavailable` from
`/agent/proposal`, before the wallet looks at the body or its own activity, so it learns
nothing about a proposal, the pending draft or whether the wallet is busy. `/agent/connect`
gives every refused pairing code the same `pairing_refused`, whether no pairing exists, it
expired or the code is wrong, and checks the code without using it up before saying `busy`, so
only the holder of a valid code learns that the browser holds the wallet. The `capacity` answer
reflects only how many native requests are in flight. Any reply from the user after a refusal
needs the complete card again and a new confirmation before the next send; the transcript
checker flags a send whose bytes differ from an earlier send under the same confirmation that
may have staged a draft: one that succeeded, got no answer, or failed with any code other than
`E_WALLET_BUSY`, `E_WALLET_DRAFT_PENDING`, `E_WALLET_PAIRING_REQUIRED` or
`E_WALLET_PROPOSAL_REFUSED`; a send the user declined at the approval prompt never ran. Typing
`confirm` again under the same card does not count as a new confirmation.

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

The checker accepts a delegate the user never typed only when it is the one the policy
builder's own `connect_wallet` reported for the current connection, since the user chose that
delegate by pairing.

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
