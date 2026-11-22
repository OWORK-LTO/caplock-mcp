# Changelog

## 0.4.0 — Server-initiated request policy (behavior change)

- **Breaking default:** server-initiated requests other than `ping` (e.g. `sampling/createMessage`, `elicitation/create`, `roots/list`) are no longer relayed to the host. The proxy answers the server with JSON-RPC error -32601 and writes a `server_request_blocked` audit record. Use `--allow-server-requests` to restore relaying for servers that legitimately need them.
- Interop check now asserts CAPLOCK's own drift error, stderr message and audit record for a tampered server (not just any failure).
- Added a regression test for the default-deny policy (27 tests).

## 0.3.2 — Envelope and timeout hardening

- `tools/list` results returned to the host now contain only the verified `tools` array and `nextCursor`; unsigned members (e.g. `instructions`, `_meta`) are dropped.
- A forwarded request (e.g. a slow `tools/call`) that exceeds `--timeout` now receives a JSON-RPC error (-32001), is cancelled upstream, and any late upstream response is discarded; the session stays up. An unanswered inventory (`tools/list`) request remains fatal.
- Default `StdioProxy`/`run_proxy` timeout aligned with the CLI default (120 s).
- Declared `Discovery.cursor` as a dataclass field.
- Added regression tests for envelope stripping and non-fatal call timeout.
- Windows: replaced `select()` on pipes in the cancellation test with a portable reader (verified failing on Windows 3.15.2, 25/26 before fix).
- Lint: sorted imports; intentional fail-closed `except Exception` sites marked `# noqa: BLE001`.

## 0.3.1 — JSON-RPC response correlation hardening

- Reject unsolicited upstream JSON-RPC responses instead of forwarding them to the host.
- Track server-initiated requests and permit only matching host responses.
- Reject active request-ID collisions across host, proxy-internal and upstream-initiated requests.
- Added adversarial regression tests for forged response injection, legitimate server-initiated request/response handling and ID collisions.

## 0.3.0 — Runtime enforcement

- Added a stdio MCP enforcement proxy that intercepts `tools/list` and `tools/call`.
- Added complete paginated tool-inventory verification before exposure and before each call.
- Added strict JSON-RPC framing and duplicate-key rejection, bounded message/inventory sizes, request timeouts and upstream process cleanup.
- Added Ed25519 signing-key fingerprints and out-of-band pin checking.
- Introduced lockfile v2 with monotonic sequence numbers and signed predecessor hashes.
- Added persistent anti-rollback state, explicit bootstrap and cross-process state locking.
- Added local structured audit events without tool arguments or outputs.
- Added subprocess integration tests for clean operation, drift, pagination, per-call revalidation, key mismatch, cancellation and timeout behaviour.

## 0.2.1

- Corrected documentation to remove claims about MCP discovery adapters that were not implemented in that release.
- Retained local Ed25519 manifest signing and drift verification.
