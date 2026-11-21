from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

FORMAT = "caplock-lock-v2"


class CaplockError(Exception):
    """Expected user-facing CAPLOCK error."""


def canonical_json(value: Any) -> bytes:
    """Deterministic JSON encoding for the supported JSON data model.

    This is a stable application encoding, not a claim of full RFC 8785
    compatibility. NaN and Infinity are rejected.
    """
    try:
        return json.dumps(
            value, sort_keys=True, separators=(",", ":"),
            ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise CaplockError(f"Input is not valid canonical JSON data: {exc}") from exc


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CaplockError(f"Duplicate JSON object key: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise CaplockError(f"Invalid non-finite JSON number: {value}")


def load_json(path: Path) -> Any:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except FileNotFoundError:
        raise CaplockError(f"File not found: {path}")
    except UnicodeDecodeError as exc:
        raise CaplockError(f"Input is not valid UTF-8: {path}") from exc
    except json.JSONDecodeError as exc:
        raise CaplockError(f"Invalid JSON in {path}: {exc}") from exc
    except OSError as exc:
        raise CaplockError(f"Cannot read {path}: {exc}") from exc


def extract_tools(document: Any) -> list[dict[str, Any]]:
    """Accept either a raw tools/list result or an MCP JSON-RPC result."""
    if not isinstance(document, dict):
        raise CaplockError("Manifest root must be a JSON object.")

    tools = document.get("tools")
    if tools is None and isinstance(document.get("result"), dict):
        tools = document["result"].get("tools")

    if not isinstance(tools, list):
        raise CaplockError("Expected a 'tools' array (or result.tools array).")

    names: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise CaplockError(f"Tool at index {index} must be an object.")
        name = tool.get("name")
        if not isinstance(name, str) or not name.strip():
            raise CaplockError(f"Tool at index {index} has no valid name.")
        if name in names:
            raise CaplockError(f"Duplicate tool name: {name}")
        names.add(name)
        # Preserve all fields: descriptions, schemas, annotations and metadata
        # can materially change what an agent is instructed or permitted to do.
        normalized.append(tool)

    return sorted(normalized, key=lambda item: item["name"])


def tool_hash(tool: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(tool)).hexdigest()


def manifest_hash(tools: list[dict[str, Any]]) -> str:
    return hashlib.sha256(canonical_json(tools)).hexdigest()


def generate_keys(private_path: Path, public_path: Path) -> None:
    import os

    if private_path.resolve() == public_path.resolve():
        raise CaplockError("Private and public key paths must be different.")
    if private_path.exists() or public_path.exists():
        raise CaplockError("Refusing to overwrite an existing key. Choose new paths.")
    private = Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    created_private = False
    created_public = False
    try:
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        created_private = True
        with os.fdopen(fd, "wb") as handle:
            handle.write(private_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        fd = os.open(public_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        created_public = True
        with os.fdopen(fd, "wb") as handle:
            handle.write(public_bytes)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if created_private:
            try:
                private_path.unlink()
            except OSError:
                pass
        if created_public:
            try:
                public_path.unlink()
            except OSError:
                pass
        raise


def _load_private(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except Exception as exc:
        raise CaplockError(f"Cannot load private key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise CaplockError("Private key must be Ed25519.")
    return key


def _load_public(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except Exception as exc:
        raise CaplockError(f"Cannot load public key {path}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise CaplockError("Public key must be Ed25519.")
    return key


def signed_payload(lock: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in lock.items() if key != "signature"}


def lock_digest(lock: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(lock)).hexdigest()


def create_lock(
    manifest_path: Path, lock_path: Path, private_key_path: Path, server_id: str
) -> dict[str, Any]:
    if not isinstance(server_id, str) or not server_id.strip() or len(server_id) > 256:
        raise CaplockError("server_id must be a non-empty string of at most 256 characters.")
    document = load_json(manifest_path)
    tools = extract_tools(document)
    private = _load_private(private_key_path)
    sequence = 1
    previous_hash = None
    if lock_path.exists():
        previous = load_json(lock_path)
        if not isinstance(previous, dict) or previous.get("format") != FORMAT:
            raise CaplockError("Existing lockfile is not a supported v2 baseline; refusing implicit migration.")
        try:
            previous_signature = base64.b64decode(previous["signature"]["value"], validate=True)
            private.public_key().verify(previous_signature, canonical_json(signed_payload(previous)))
        except Exception as exc:
            raise CaplockError("Existing lockfile is not signed by the supplied private key; refusing update.") from exc
        if previous.get("server_id") != server_id:
            raise CaplockError("Existing lockfile belongs to a different server identity.")
        prior_tools = previous.get("tools")
        if not isinstance(prior_tools, list):
            raise CaplockError("Existing lockfile inventory is malformed; refusing to extend its chain.")
        prior_definitions: list[dict[str, Any]] = []
        prior_names: set[str] = set()
        for item in prior_tools:
            if not isinstance(item, dict):
                raise CaplockError("Existing lockfile contains a malformed tool record.")
            name, digest, definition = item.get("name"), item.get("sha256"), item.get("definition")
            if (not isinstance(name, str) or not isinstance(digest, str)
                    or not isinstance(definition, dict) or definition.get("name") != name
                    or name in prior_names or tool_hash(definition) != digest):
                raise CaplockError("Existing lockfile tool inventory failed integrity checks.")
            prior_names.add(name)
            prior_definitions.append(definition)
        prior_definitions.sort(key=lambda item: item["name"])
        prior_count = previous.get("tool_count")
        if (not isinstance(prior_count, int) or isinstance(prior_count, bool)
                or prior_count != len(prior_definitions)
                or previous.get("manifest_sha256") != manifest_hash(prior_definitions)):
            raise CaplockError("Existing lockfile aggregate inventory failed integrity checks.")
        prior_sequence = previous.get("sequence")
        if not isinstance(prior_sequence, int) or isinstance(prior_sequence, bool) or prior_sequence < 1:
            raise CaplockError("Existing lockfile has an invalid sequence number.")
        sequence = prior_sequence + 1
        previous_hash = lock_digest(previous)

    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    key_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw_public).digest()).decode("ascii").rstrip("=")
    lock: dict[str, Any] = {
        "format": FORMAT,
        "server_id": server_id,
        "signing_key_fingerprint": key_fingerprint,
        "sequence": sequence,
        "previous_lock_sha256": previous_hash,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "manifest_sha256": manifest_hash(tools),
        "tool_count": len(tools),
        "tools": [
            {"name": tool["name"], "sha256": tool_hash(tool), "definition": tool}
            for tool in tools
        ],
    }
    signature = private.sign(canonical_json(lock))
    lock["signature"] = {
        "algorithm": "Ed25519",
        "encoding": "base64",
        "value": base64.b64encode(signature).decode("ascii"),
    }
    import os
    import tempfile
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".caplock-lock-", dir=str(lock_path.parent))
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_json(lock) + b"\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, lock_path)
        try:
            directory_fd = os.open(lock_path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError:
            pass
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return lock


def verify_tools(
    tools: list[dict[str, Any]], lock_path: Path, public_key_path: Path,
    expected_server_id: str | None = None,
    expected_key_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Verify a signed baseline against an already-discovered complete tool inventory."""
    lock = load_json(lock_path)
    if not isinstance(lock, dict) or lock.get("format") != FORMAT:
        raise CaplockError("Unsupported or malformed CAPLOCK lockfile.")
    sig = lock.get("signature")
    if not isinstance(sig, dict) or sig.get("algorithm") != "Ed25519":
        raise CaplockError("Lockfile has no supported Ed25519 signature.")
    try:
        signature = base64.b64decode(sig["value"], validate=True)
        public_key = _load_public(public_key_path)
        public_key.verify(signature, canonical_json(signed_payload(lock)))
    except CaplockError:
        raise
    except Exception as exc:
        raise CaplockError("LOCKFILE SIGNATURE INVALID: baseline may be altered or key is wrong.") from exc

    lock_server_id = lock.get("server_id")
    if not isinstance(lock_server_id, str) or not lock_server_id.strip() or len(lock_server_id) > 256:
        raise CaplockError("Lockfile server identity is malformed.")
    if expected_server_id is not None and lock_server_id != expected_server_id:
        raise CaplockError("Lockfile server identity does not match configured server identity.")
    raw_public = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    actual_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw_public).digest()).decode("ascii").rstrip("=")
    if lock.get("signing_key_fingerprint") != actual_fingerprint:
        raise CaplockError("Lockfile signing-key fingerprint does not match verification key.")
    if expected_key_fingerprint is not None and actual_fingerprint != expected_key_fingerprint:
        raise CaplockError("TRUST KEY MISMATCH: configured public-key fingerprint does not match pinned fingerprint.")
    sequence = lock.get("sequence")
    previous_hash = lock.get("previous_lock_sha256")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise CaplockError("Lockfile sequence number is invalid.")
    if sequence == 1 and previous_hash is not None:
        raise CaplockError("Initial lockfile must not have a predecessor hash.")
    if sequence > 1 and (not isinstance(previous_hash, str) or len(previous_hash) != 64 or any(c not in "0123456789abcdef" for c in previous_hash)):
        raise CaplockError("Lockfile predecessor hash is missing or malformed.")

    stored_tools = lock.get("tools")
    if not isinstance(stored_tools, list):
        raise CaplockError("Lockfile tool inventory is malformed.")

    baseline: dict[str, str] = {}
    baseline_definitions: list[dict[str, Any]] = []
    for item in stored_tools:
        if not isinstance(item, dict):
            raise CaplockError("Lockfile contains a malformed tool record.")
        name, digest, definition = item.get("name"), item.get("sha256"), item.get("definition")
        if not isinstance(name, str) or not isinstance(digest, str) or not isinstance(definition, dict):
            raise CaplockError("Lockfile contains an incomplete tool record.")
        if name in baseline or definition.get("name") != name:
            raise CaplockError("Lockfile contains duplicate or inconsistent tool identities.")
        if tool_hash(definition) != digest:
            raise CaplockError(f"Lockfile tool hash is inconsistent: {name}")
        baseline[name] = digest
        baseline_definitions.append(definition)

    baseline_definitions.sort(key=lambda item: item["name"])
    stored_count = lock.get("tool_count")
    if not isinstance(stored_count, int) or isinstance(stored_count, bool) or len(baseline) != stored_count:
        raise CaplockError("Lockfile tool inventory count is inconsistent.")
    stored_manifest_hash = lock.get("manifest_sha256")
    if not isinstance(stored_manifest_hash, str) or len(stored_manifest_hash) != 64 or any(c not in "0123456789abcdef" for c in stored_manifest_hash):
        raise CaplockError("Lockfile aggregate manifest hash is malformed.")
    if manifest_hash(baseline_definitions) != stored_manifest_hash:
        raise CaplockError("Lockfile aggregate manifest hash is inconsistent.")

    if not isinstance(tools, list):
        raise CaplockError("Live tool inventory must be an array.")
    current_tools = extract_tools({"tools": tools})
    current = {tool["name"]: tool_hash(tool) for tool in current_tools}
    added = sorted(set(current) - set(baseline))
    removed = sorted(set(baseline) - set(current))
    changed = sorted(name for name in set(current) & set(baseline) if current[name] != baseline[name])
    clean = not (added or removed or changed)
    return {
        "status": "PASS" if clean else "DRIFT",
        "signature_valid": True,
        "server_id": lock.get("server_id"),
        "sequence": sequence,
        "previous_lock_sha256": previous_hash,
        "lock_sha256": lock_digest(lock),
        "baseline_sha256": lock.get("manifest_sha256"),
        "current_sha256": manifest_hash(current_tools),
        "added": added,
        "removed": removed,
        "changed": changed,
        "tool_count_baseline": lock.get("tool_count"),
        "tool_count_current": len(current),
    }


def verify_lock(
    manifest_path: Path, lock_path: Path, public_key_path: Path
) -> dict[str, Any]:
    document = load_json(manifest_path)
    return verify_tools(extract_tools(document), lock_path, public_key_path)


def _exclusive_state_lock(state_path: Path):
    """Cross-process advisory lock protecting anti-rollback read/modify/write."""
    import os
    from contextlib import contextmanager

    @contextmanager
    def locked():
        lock_path = state_path.with_suffix(state_path.suffix + ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(lock_path, flags, 0o600)
        os.chmod(lock_path, 0o600)
        try:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_EX)
                unlock = lambda: fcntl.flock(fd, fcntl.LOCK_UN)
            except ImportError:
                # Windows fallback: lock one byte in a dedicated lock file.
                import msvcrt
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                unlock = lambda: (os.lseek(fd, 0, os.SEEK_SET), msvcrt.locking(fd, msvcrt.LK_UNLCK, 1))
            try:
                yield
            finally:
                unlock()
        finally:
            os.close(fd)
    return locked()


def enforce_rollback_state(
    lock_path: Path, state_path: Path, expected_server_id: str,
    bootstrap: bool = False, expected_lock_sha256: str | None = None,
) -> dict[str, Any]:
    """Pin the accepted signed-lock lineage in protected local state.

    Missing state accepts sequence 1 only. Higher sequences require explicit
    bootstrap, which should be used only after out-of-band baseline review.
    Cross-process locking prevents concurrent proxy instances from accepting
    competing successors based on the same previous state.
    """
    import os
    import tempfile

    state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with _exclusive_state_lock(state_path):
        lock = load_json(lock_path)
        if not isinstance(lock, dict) or lock.get("format") != FORMAT:
            raise CaplockError("Cannot establish rollback state for an unsupported lockfile.")
        if lock.get("server_id") != expected_server_id:
            raise CaplockError("Rollback state server identity mismatch.")
        sequence = lock.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise CaplockError("Invalid lockfile sequence for rollback protection.")
        digest = lock_digest(lock)
        if expected_lock_sha256 is not None and digest != expected_lock_sha256:
            raise CaplockError("LOCKFILE CHANGED DURING VERIFICATION: refusing a time-of-check/time-of-use race.")
        predecessor = lock.get("previous_lock_sha256")

        had_state = state_path.exists()
        if had_state:
            state = load_json(state_path)
            if not isinstance(state, dict) or state.get("server_id") != expected_server_id:
                raise CaplockError("Rollback state is malformed or belongs to another server.")
            old_sequence, old_digest = state.get("sequence"), state.get("lock_sha256")
            if not isinstance(old_sequence, int) or not isinstance(old_digest, str):
                raise CaplockError("Rollback state is incomplete.")
            if sequence == old_sequence and digest == old_digest:
                return {"status": "CURRENT", "sequence": sequence, "lock_sha256": digest}
            if sequence <= old_sequence:
                raise CaplockError("ROLLBACK BLOCKED: lockfile is older than or conflicts with the last accepted baseline.")
            if sequence != old_sequence + 1 or predecessor != old_digest:
                raise CaplockError("CHAIN BLOCKED: new lockfile is not the direct signed successor of the accepted baseline.")
        else:
            if not bootstrap:
                raise CaplockError("UNANCHORED BASELINE: no local trust state exists; review the baseline and explicitly bootstrap once.")

        state = {
            "format": "caplock-state-v1",
            "server_id": expected_server_id,
            "sequence": sequence,
            "lock_sha256": digest,
            "accepted_at": datetime.now(timezone.utc).isoformat(),
        }
        fd, temporary = tempfile.mkstemp(prefix=".caplock-state-", dir=str(state_path.parent))
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(canonical_json(state) + b"\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, state_path)
            try:
                directory_fd = os.open(state_path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError:
                pass
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        return {"status": "ADVANCED" if had_state else "BOOTSTRAPPED", "sequence": sequence, "lock_sha256": digest}


def public_key_fingerprint(public_key_path: Path) -> str:
    public = _load_public(public_key_path)
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
