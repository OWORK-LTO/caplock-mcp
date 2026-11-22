from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import (
    CaplockError,
    create_lock,
    generate_keys,
    public_key_fingerprint,
    verify_lock,
)
from .proxy import ProxyError, run_proxy


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="caplock",
        description="Sign and verify MCP tool-definition baselines."
    )
    sub = p.add_subparsers(dest="command", required=True)

    keys = sub.add_parser("keygen", help="Generate an Ed25519 signing keypair.")
    keys.add_argument("--private-key", type=Path, default=Path("caplock-private.pem"))
    keys.add_argument("--public-key", type=Path, default=Path("caplock-public.pem"))

    fingerprint = sub.add_parser("fingerprint", help="Print the Ed25519 public-key fingerprint for out-of-band pinning.")
    fingerprint.add_argument("--public-key", type=Path, required=True)

    snap = sub.add_parser("snapshot", help="Create a signed tool-definition lockfile.")
    snap.add_argument("manifest", type=Path)
    snap.add_argument("--lock", type=Path, default=Path("caplock.lock.json"))
    snap.add_argument("--private-key", type=Path, required=True)
    snap.add_argument("--server-id", required=True, help="Stable, operator-assigned MCP server identity.")

    ver = sub.add_parser("verify", help="Verify signature and compare current tools with baseline.")
    ver.add_argument("manifest", type=Path)
    ver.add_argument("--lock", type=Path, default=Path("caplock.lock.json"))
    ver.add_argument("--public-key", type=Path, required=True)
    ver.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")

    proxy = sub.add_parser("proxy", help="Run a fail-closed stdio MCP enforcement proxy.")
    proxy.add_argument("--lock", type=Path, required=True)
    proxy.add_argument("--public-key", type=Path, required=True)
    proxy.add_argument("--server-id", required=True)
    proxy.add_argument("--trusted-key-fingerprint", required=True,
                       help="Out-of-band pinned fingerprint from `caplock fingerprint`.")
    proxy.add_argument("--timeout", type=float, default=120.0)
    proxy.add_argument("--state", type=Path, help="Protected local anti-rollback state file.")
    proxy.add_argument("--audit", type=Path, help="Append-only local JSONL audit log.")
    proxy.add_argument("--bootstrap", action="store_true", help="Explicitly trust-anchor a sequence >1 baseline when local state is absent.")
    proxy.add_argument("--allow-server-requests", action="store_true",
                       help="Relay server-initiated requests (sampling, elicitation, roots). Denied by default.")
    proxy.add_argument("upstream", nargs=argparse.REMAINDER,
                       help="Upstream server command, preceded by --")

    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "keygen":
            generate_keys(args.private_key, args.public_key)
            print(f"Created private key: {args.private_key}")
            print(f"Created public key:  {args.public_key}")
            print("Keep the private key offline or in a secrets manager. Never commit it.")
            return 0

        if args.command == "fingerprint":
            print(public_key_fingerprint(args.public_key))
            return 0

        if args.command == "snapshot":
            lock = create_lock(args.manifest, args.lock, args.private_key, args.server_id)
            print(f"Signed {lock['tool_count']} tool definitions for {lock['server_id']} (sequence {lock['sequence']}).")
            print(f"Lockfile: {args.lock}")
            return 0

        if args.command == "proxy":
            command = args.upstream[1:] if args.upstream and args.upstream[0] == "--" else args.upstream
            if not command:
                raise CaplockError("Provide an upstream command after --.")
            if args.timeout <= 0:
                raise CaplockError("--timeout must be greater than zero.")
            return run_proxy(command, args.lock, args.public_key, args.server_id,
                             args.trusted_key_fingerprint, args.timeout,
                             args.state, args.audit, args.bootstrap, args.allow_server_requests)

        if args.command == "verify":
            result = verify_lock(args.manifest, args.lock, args.public_key)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print(f"{result['status']}: signature valid; server={result['server_id']}")
                for key in ("added", "removed", "changed"):
                    if result[key]:
                        print(f"{key.upper()}: {', '.join(result[key])}")
                if result["status"] == "PASS":
                    print("No tool-definition drift detected.")
                else:
                    print("BLOCK: review and approve the changed capability set before use.")
            return 0 if result["status"] == "PASS" else 2

    except (CaplockError, ProxyError) as exc:
        print(f"CAPLOCK ERROR: {exc}", file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
