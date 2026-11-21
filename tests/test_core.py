import json
from pathlib import Path

import pytest

from caplock.core import CaplockError, create_lock, generate_keys, verify_lock


def write_manifest(path: Path, tools):
    path.write_text(json.dumps({"tools": tools}), encoding="utf-8")


def test_signed_snapshot_passes_and_detects_drift(tmp_path):
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    manifest = tmp_path / "tools.json"
    lock = tmp_path / "caplock.lock.json"
    generate_keys(private, public)

    original = [
        {"name": "read_file", "description": "Read permitted files", "inputSchema": {"type": "object"}},
        {"name": "send_email", "description": "Send approved email", "inputSchema": {"type": "object"}},
    ]
    write_manifest(manifest, original)
    create_lock(manifest, lock, private, "prod-mail-server")
    result = verify_lock(manifest, lock, public)
    assert result["status"] == "PASS"
    assert result["signature_valid"] is True

    modified = [
        {"name": "read_file", "description": "Read all files and secrets", "inputSchema": {"type": "object"}},
        original[1],
        {"name": "delete_account", "description": "Delete an account", "inputSchema": {"type": "object"}},
    ]
    write_manifest(manifest, modified)
    result = verify_lock(manifest, lock, public)
    assert result["status"] == "DRIFT"
    assert result["changed"] == ["read_file"]
    assert result["added"] == ["delete_account"]


def test_tampered_lockfile_fails_signature(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock = tmp_path / "tools.json", tmp_path / "lock.json"
    generate_keys(private, public)
    write_manifest(manifest, [{"name": "safe", "description": "safe"}])
    create_lock(manifest, lock, private, "test")
    data = json.loads(lock.read_text())
    data["server_id"] = "attacker-server"
    lock.write_text(json.dumps(data))
    with pytest.raises(CaplockError, match="SIGNATURE INVALID"):
        verify_lock(manifest, lock, public)


def test_duplicate_tool_names_rejected(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock = tmp_path / "tools.json", tmp_path / "lock.json"
    generate_keys(private, public)
    write_manifest(manifest, [{"name": "same"}, {"name": "same"}])
    with pytest.raises(CaplockError, match="Duplicate tool name"):
        create_lock(manifest, lock, private, "test")


def test_wrong_public_key_fails(tmp_path):
    p1, q1 = tmp_path / "p1.pem", tmp_path / "q1.pem"
    p2, q2 = tmp_path / "p2.pem", tmp_path / "q2.pem"
    manifest, lock = tmp_path / "tools.json", tmp_path / "lock.json"
    generate_keys(p1, q1)
    generate_keys(p2, q2)
    write_manifest(manifest, [{"name": "read"}])
    create_lock(manifest, lock, p1, "test")
    with pytest.raises(CaplockError, match="SIGNATURE INVALID"):
        verify_lock(manifest, lock, q2)


def test_removed_tool_is_reported(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock = tmp_path / "tools.json", tmp_path / "lock.json"
    generate_keys(private, public)
    write_manifest(manifest, [{"name": "keep"}, {"name": "remove"}])
    create_lock(manifest, lock, private, "test")
    write_manifest(manifest, [{"name": "keep"}])
    result = verify_lock(manifest, lock, public)
    assert result["status"] == "DRIFT"
    assert result["removed"] == ["remove"]


def test_signed_but_internally_inconsistent_inventory_is_rejected(tmp_path):
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock = tmp_path / "tools.json", tmp_path / "lock.json"
    generate_keys(private, public)
    write_manifest(manifest, [{"name": "safe", "description": "safe"}])
    create_lock(manifest, lock, private, "test")
    data = json.loads(lock.read_text())
    data["tools"][0]["sha256"] = "0" * 64
    # Re-signing simulates a malformed lock produced by a faulty trusted signer.
    from cryptography.hazmat.primitives import serialization

    from caplock.core import canonical_json
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    payload = {k: v for k, v in data.items() if k != "signature"}
    import base64
    data["signature"]["value"] = base64.b64encode(key.sign(canonical_json(payload))).decode()
    lock.write_text(json.dumps(data))
    with pytest.raises(CaplockError, match="hash is inconsistent"):
        verify_lock(manifest, lock, public)
    with pytest.raises(CaplockError, match="inventory failed integrity"):
        create_lock(manifest, lock, private, "test")


def test_duplicate_json_object_keys_rejected(tmp_path):
    from caplock.core import load_json
    manifest = tmp_path / "duplicate.json"
    manifest.write_text('{"tools":[],"tools":[{"name":"hidden"}]}', encoding="utf-8")
    with pytest.raises(CaplockError, match="Duplicate JSON object key"):
        load_json(manifest)


def test_non_finite_json_numbers_rejected(tmp_path):
    from caplock.core import load_json
    manifest = tmp_path / "nan.json"
    manifest.write_text('{"tools":[{"name":"x","score":NaN}]}', encoding="utf-8")
    with pytest.raises(CaplockError, match="non-finite"):
        load_json(manifest)


def test_lock_sequence_and_predecessor_chain(tmp_path):
    import pytest

    from caplock.core import CaplockError, create_lock, enforce_rollback_state
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock, state = tmp_path / "tools.json", tmp_path / "lock.json", tmp_path / "state.json"
    manifest.write_text(json.dumps({"tools": [{"name": "one", "inputSchema": {"type": "object"}}]}))
    generate_keys(private, public)
    first = create_lock(manifest, lock, private, "server-a")
    assert first["sequence"] == 1
    enforce_rollback_state(lock, state, "server-a", bootstrap=True)
    assert enforce_rollback_state(lock, state, "server-a")["status"] == "CURRENT"

    manifest.write_text(json.dumps({"tools": [{"name": "two", "inputSchema": {"type": "object"}}]}))
    second = create_lock(manifest, lock, private, "server-a")
    assert second["sequence"] == 2
    assert second["previous_lock_sha256"] is not None
    assert enforce_rollback_state(lock, state, "server-a")["status"] == "ADVANCED"

    lock.write_text(json.dumps(first))
    with pytest.raises(CaplockError, match="ROLLBACK BLOCKED"):
        enforce_rollback_state(lock, state, "server-a")


def test_unanchored_successor_requires_explicit_bootstrap(tmp_path):
    import pytest

    from caplock.core import CaplockError, create_lock, enforce_rollback_state
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock = tmp_path / "tools.json", tmp_path / "lock.json"
    manifest.write_text(json.dumps({"tools": [{"name": "one"}]}))
    generate_keys(private, public)
    create_lock(manifest, lock, private, "server-a")
    manifest.write_text(json.dumps({"tools": [{"name": "two"}]}))
    create_lock(manifest, lock, private, "server-a")
    with pytest.raises(CaplockError, match="UNANCHORED"):
        enforce_rollback_state(lock, tmp_path / "state.json", "server-a")
    assert enforce_rollback_state(lock, tmp_path / "state.json", "server-a", bootstrap=True)["status"] == "BOOTSTRAPPED"


def test_missing_state_never_silently_reanchors_sequence_one(tmp_path):
    from caplock.core import CaplockError, create_lock, enforce_rollback_state
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    manifest, lock, state = tmp_path / "tools.json", tmp_path / "lock.json", tmp_path / "state.json"
    manifest.write_text(json.dumps({"tools": [{"name": "safe"}]}))
    generate_keys(private, public)
    create_lock(manifest, lock, private, "server-a")
    with pytest.raises(CaplockError, match="UNANCHORED"):
        enforce_rollback_state(lock, state, "server-a")
    enforce_rollback_state(lock, state, "server-a", bootstrap=True)
    state.unlink()
    with pytest.raises(CaplockError, match="UNANCHORED"):
        enforce_rollback_state(lock, state, "server-a")
