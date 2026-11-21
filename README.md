# CAPLOCK

**Cryptographic integrity and runtime change control for MCP tool definitions.**

CAPLOCK is an open-source, local enforcement proxy for Model Context Protocol (MCP) servers. It signs an operator-approved tool inventory and mediates a host's stdio connection to the upstream server. The proxy exposes tool definitions and forwards tool calls only when the complete live inventory matches the signed baseline, the signing key is pinned and the baseline passes local anti-rollback checks.

CAPLOCK is licensed under Apache-2.0.

## Security properties

- Ed25519-signed capability baselines.
- SHA-256 hashes of complete tool-definition objects, including descriptions, input/output schemas, annotations and metadata present in the definition.
- Out-of-band public-key fingerprint pinning.
- Stable operator-assigned server identity binding.
- Complete paginated `tools/list` inventory verification.
- `tools/list` is blocked on drift or any verification failure.
- Every `tools/call` triggers a fresh full inventory check before the call is forwarded.
- Added, removed, changed, duplicate or malformed tool definitions are rejected.
- Monotonic signed lockfile sequence and predecessor hash.
- Persistent local anti-rollback state with atomic updates.
- Structured local JSONL audit events. Tool arguments and returned content are not logged.
- Diagnostics are written to stderr; stdout is reserved for MCP JSON-RPC messages.

## What CAPLOCK does not prove

A signed, unchanged definition is not proof that the implementation behind the tool is safe, authentic or unchanged. CAPLOCK does not sandbox upstream code, inspect tool-call arguments for business-policy violations, validate tool outputs, protect a compromised host, or stop an operator who controls the signing key from approving a malicious definition. The proxy protects only connections that are actually routed through it.

Current runtime adapter: **local stdio MCP proxy**. Streamable HTTP is not implemented in this release. Independent security assessment has not been completed; do not treat this release as independently certified or production-secure.

## Install from source

Requires Python 3.10+.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install .
```

For development and tests:

```bash
python -m pip install -e '.[dev]'
pytest -q
```

## 1. Create a signing keypair

```bash
caplock keygen --private-key caplock-private.pem --public-key caplock-public.pem
```

Keep the private key offline or in a secrets manager. It is needed for approval updates, not runtime verification. Never commit it to source control.

## 2. Create the initial approved baseline

Create a JSON file containing the complete `tools/list` result or its `result.tools` array. Example:

```json
{
  "tools": [
    {
      "name": "weather",
      "description": "Get current weather",
      "inputSchema": {
        "type": "object",
        "properties": {"city": {"type": "string"}},
        "required": ["city"]
      }
    }
  ]
}
```

Then sign it:

```bash
caplock snapshot tools.json \
  --lock caplock.lock.json \
  --private-key caplock-private.pem \
  --server-id weather-production
```

The first baseline is sequence 1. The `server-id` is an operator-assigned identity; use the same value in the proxy configuration.

## 3. Pin the public key out of band

```bash
caplock fingerprint --public-key caplock-public.pem
```

Record the complete `SHA256:...` fingerprint through a separate trusted channel and place it in deployment configuration that is protected independently of the lockfile and public-key file. Do not obtain the expected fingerprint from the same untrusted location as the key being checked.

## 4. Put the proxy between the host and the MCP server

Configure the MCP host to launch CAPLOCK instead of launching the upstream server directly:

```bash
caplock proxy \
  --lock /absolute/path/caplock.lock.json \
  --public-key /absolute/path/caplock-public.pem \
  --server-id weather-production \
  --trusted-key-fingerprint 'SHA256:REPLACE_WITH_OUT_OF_BAND_PIN' \
  --state /absolute/path/protected-state/weather-production.json \
  --audit /absolute/path/audit/weather-production.jsonl \
  --bootstrap \
  -- python -m your_mcp_server
```

The command after `--` is executed directly without a shell. Configure the host's stdio transport to run this complete command. Ensure the lockfile, public key, pinned fingerprint, state directory and audit directory are protected from untrusted modification. The private signing key must not be available to the proxy process.

The proxy verifies every page of the upstream tool inventory before returning a `tools/list` result. It performs a fresh complete inventory verification before each `tools/call`. The default per-request upstream timeout is 120 seconds and can be adjusted with `--timeout`. Any changed capability, invalid signature, key mismatch, identity mismatch, stale/rolled-back baseline, malformed message, upstream timeout or process failure blocks the affected operation. An inventory request that times out, protocol uncertainty or transport failure ends the proxy; a forwarded request (such as a long tool call) that exceeds the timeout is answered with an error and cancelled upstream while the session continues. Only the verified `tools` array and `nextCursor` are returned from `tools/list`. For protocol uncertainty or transport failure, the proxy exits rather than attempting fail-open recovery. The inventory check and subsequent upstream execution are not atomic: a malicious server can change its implementation or advertised behaviour after discovery, and definition pinning cannot prove the behaviour of the code behind an unchanged definition.

## 5. Review and approve legitimate changes

First compare a new manifest against the current signed baseline:

```bash
caplock verify new-tools.json \
  --lock caplock.lock.json \
  --public-key caplock-public.pem
```

Review the reported additions, removals and changed tool names and inspect the full definitions. Only after explicit operator review, sign the new manifest:

```bash
caplock snapshot new-tools.json \
  --lock caplock.lock.json \
  --private-key caplock-private.pem \
  --server-id weather-production
```

When the lock path already contains a valid v2 baseline signed by the same key and for the same server identity, CAPLOCK increments the sequence and links the new lock to the prior lock hash. It refuses implicit migration from an older lock format or replacement with a lock signed by a different key. Deploy the new lockfile to the proxy only after review.

## Anti-rollback state and bootstrap

The proxy refuses to start trusting a baseline when local anti-rollback state is absent. On first deployment, independently review the signed baseline, confirm the pinned key fingerprint, then pass `--bootstrap` once to establish the local trust anchor. Remove `--bootstrap` from the persistent host configuration after that initial successful verification. Thereafter CAPLOCK accepts the same lock or its direct signed successor only. Older locks, same-sequence replacements and broken predecessor chains are rejected.

If state is missing on a new machine or after recovery, the proxy blocks until an operator explicitly bootstraps the reviewed baseline. Protect and back up the state file and its containing directory. Deleting state removes local rollback history; the explicit bootstrap requirement prevents silent re-anchoring. Bootstrap is a trust decision, not a routine recovery switch.

## Exit and failure behaviour

- `0`: clean verification or normal proxy shutdown.
- `1`: malformed input, signature/key/trust failure, protocol failure, timeout or upstream process failure.
- `2`: manifest drift from the `verify` command.

The proxy uses JSON-RPC error responses for detected drift and verification failures where the connection remains usable. For uncertain transport/protocol state it terminates the proxy. Do not configure an MCP host fallback that connects directly to the upstream server after CAPLOCK exits.

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q
python -m compileall -q src
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
