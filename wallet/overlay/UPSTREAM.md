# Pollywallet integration attribution

The integration patch targets [kalepail/pollywallet](https://github.com/kalepail/pollywallet)
commit `853b102983699726f918b68d8e42edbba74e65b9`, licensed under Apache-2.0.
The original checkout retains its LICENSE. The patch adds a route/navigation entry, an
explicit verifier option to its existing passkey helper, and local Vite proxy/dependency
configuration. It also pins the outer wallet SDK to 16.4.1 with its frozen lockfile so protocol-30 ledger headers decode during funding. Existing passkey callers retain their verifier default. This dedicated local
checkout disables upstream AI, sandbox service bindings, container startup, remote bindings
and the development inspector; Policy Builder uses its own local backend.

The new Policy Builder integration files are part of gateway-fm/oz-policy-builder under
Apache-2.0 OR MIT; their license texts and NOTICE accompany the nested package.
No upstream deployment, registry endorsement, or account-code compatibility is implied.
