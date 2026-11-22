# Security policy and threat boundary

## Reporting

Do not publish exploitable vulnerabilities in an issue. Contact the maintainers privately with reproduction steps, affected version, impact and suggested remediation. A security response process and contact address must be configured by the repository owner before public production deployment; this source package does not invent a contact address.

## Protected assets

- The operator-approved MCP tool-definition baseline.
- The Ed25519 signing private key.
- The separately pinned public-key fingerprint.
- The local anti-rollback state.
- The integrity of the host-to-proxy-to-server stdio path.

## Trust assumptions

1. The operator's signing key is not compromised.
2. The expected public-key fingerprint is provisioned through a trusted channel and protected separately from the public-key file and lockfile.
3. The proxy executable, its Python runtime and its host configuration are not modified by an attacker.
4. The host is configured to use the proxy and has no direct fallback route to the upstream server.
5. Local state and audit directories are writable only by the trusted runtime account and administrators.

## In scope

- Added, removed or modified tool definitions.
- Tampered lockfiles and invalid signatures.
- Wrong public key or signing-key fingerprint.
- Wrong configured server identity.
- Duplicate tool names and duplicate JSON object keys.
- Paginated inventories, including changes on later pages.
- Replay of an older lockfile or a broken successor chain.
- Missing state for an unanchored successor baseline.
- Tool calls attempted without a successful current inventory verification.
- Malformed protocol messages, timeouts and upstream process failure.

## Out of scope

- Server-initiated *requests* other than `ping` are denied by default (`--allow-server-requests` to relay). Server *notifications* are still relayed without content inspection.
- `resources/*` and `prompts/*` content is not integrity-checked.
- Malicious implementation behind an unchanged tool definition.
- A malicious authorised signer or compromised signing key.
- A compromised host that bypasses the proxy.
- Publisher identity or remote endpoint authenticity established solely by a local signature.
- Tool argument authorisation, output validation, data-loss prevention or sandboxing.
- Streamable HTTP transport; this release implements stdio only.
- Protection against an attacker with sufficient privileges to modify the proxy, pinned configuration and local state.

## Operational requirements

- Store the signing private key offline or in a secrets manager.
- Provision and verify the public-key fingerprint out of band.
- Protect lockfile, public-key, fingerprint configuration and anti-rollback state.
- Do not delete anti-rollback state during routine upgrades.
- Do not add direct-host fallback when the proxy fails.
- Review every baseline update before signing.
- Treat local JSONL audit records as operational logs, not as a cryptographically tamper-proof transparency log.

## Assurance status

The project test suite is not an independent security assessment. Before production-security claims, obtain independent source review, protocol fuzzing, adversarial testing, dependency/build-provenance review and penetration testing. Publish findings and remediation status.
