from __future__ import annotations

import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .core import CaplockError, enforce_rollback_state, verify_tools

MAX_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_PAGES = 1000
MAX_TOOLS = 10000


class ProxyError(Exception):
    pass


def _strict_loads(line: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in pairs:
            if key in out:
                raise ProxyError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    try:
        value = json.loads(line, object_pairs_hook=unique, parse_constant=lambda x: (_ for _ in ()).throw(ProxyError(f"invalid number: {x}")))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ProxyError(f"invalid JSON-RPC message: {exc}") from exc
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise ProxyError("expected one JSON-RPC 2.0 object per line")
    if "id" in value and (isinstance(value["id"], (dict, list, bool))):
        raise ProxyError("invalid JSON-RPC request id type")
    if "method" in value:
        if not isinstance(value["method"], str):
            raise ProxyError("JSON-RPC method must be a string")
        if "result" in value or "error" in value:
            raise ProxyError("JSON-RPC request cannot contain result or error")
        if "params" in value and not isinstance(value["params"], (dict, list)):
            raise ProxyError("JSON-RPC params must be an object or array")
    elif "id" not in value or ("result" in value) == ("error" in value):
        raise ProxyError("malformed JSON-RPC response")
    return value


def _verified_envelope(result: dict[str, Any]) -> dict[str, Any]:
    """Return only the fields CAPLOCK verifies: the tools array and the pagination cursor.

    Any other member of an upstream tools/list result (for example `instructions`
    or `_meta`) is outside the signed inventory and is never forwarded to the host.
    """
    out: dict[str, Any] = {"tools": result["tools"]}
    if result.get("nextCursor") is not None:
        out["nextCursor"] = result["nextCursor"]
    return out


def _id_key(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _encode(message: dict[str, Any]) -> bytes:
    return json.dumps(message, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


# Server-initiated requests that act on the host or the user's model/context.
# Denied by default: a compromised server could otherwise ask the host to run
# model sampling, prompt the user, or enumerate local roots outside the signed
# tool inventory. `ping` is liveness only and always relayed.
ALLOWED_SERVER_REQUESTS = frozenset({"ping"})


def _error(request_id: Any, message: str, code: int = -32091) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


@dataclass
class Discovery:
    kind: str
    downstream_id: Any
    original_request: dict[str, Any] | None
    first_result: dict[str, Any] | None = None
    selected_result: dict[str, Any] | None = None
    requested_cursor: str | None = None
    tools: list[dict[str, Any]] | None = None
    seen_cursors: set[str] | None = None
    active_internal_id: str | None = None
    cursor: str | None = None


class StdioProxy:
    """Fail-closed stdio MCP proxy. Diagnostics go to stderr; stdout is protocol-only."""

    def __init__(self, command: list[str], lock: Path, public_key: Path,
                 server_id: str, trusted_key_fingerprint: str, timeout: float = 120.0,
                 state: Path | None = None, audit: Path | None = None, bootstrap: bool = False,
                 allow_server_requests: bool = False):
        if not command:
            raise ProxyError("upstream command is required")
        self.command = command
        self.lock = lock
        self.public_key = public_key
        self.server_id = server_id
        self.trusted_key_fingerprint = trusted_key_fingerprint
        self.timeout = timeout
        import hashlib
        safe_id = hashlib.sha256(server_id.encode("utf-8")).hexdigest()[:24]
        self.state = state or (Path.home() / ".local" / "state" / "caplock" / f"{safe_id}.json")
        self.audit = audit or self.state.with_suffix(".audit.jsonl")
        self.bootstrap = bootstrap
        self.allow_server_requests = allow_server_requests
        self.child: subprocess.Popen[bytes] | None = None
        self.events: queue.Queue[tuple[str, bytes | None]] = queue.Queue(maxsize=1024)
        self.write_lock = threading.Lock()
        self.pending: dict[str, tuple[str, Any]] = {}
        # Track server-initiated requests separately. An upstream response must
        # match a request ID that CAPLOCK actually issued or forwarded.
        self.server_requests: set[str] = set()
        self.discovery: dict[str, Discovery] = {}
        self.abandoned_internal: set[str] = set()
        self.deadlines: dict[str, float] = {}
        self.used_ids: set[str] = set()
        self.counter = 0
        self.alive = True

    def _next_id(self) -> str:
        while True:
            self.counter += 1
            candidate = f"caplock-internal-{self.counter}"
            key = _id_key(candidate)
            if (key not in self.used_ids and key not in self.discovery and key not in self.pending
                    and key not in self.server_requests and key not in self.abandoned_internal):
                return candidate

    def _send_upstream(self, message: dict[str, Any]) -> None:
        assert self.child and self.child.stdin
        data = _encode(message)
        with self.write_lock:
            self.child.stdin.write(data)
            self.child.stdin.flush()

    def _send_host(self, message: dict[str, Any]) -> None:
        sys.stdout.buffer.write(_encode(message))
        sys.stdout.buffer.flush()

    def _reader(self, name: str, stream: Any) -> None:
        """Read newline-delimited protocol frames without holding buffered-I/O locks."""
        fd = stream.fileno()
        pending = bytearray()
        try:
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    if pending:
                        self.events.put((name + "_ERROR", b"unterminated protocol message at EOF"))
                    else:
                        self.events.put((name + "_EOF", None))
                    return
                pending.extend(chunk)
                if len(pending) > MAX_MESSAGE_BYTES and b"\n" not in pending:
                    self.events.put((name + "_ERROR", b"message exceeds size limit"))
                    return
                while True:
                    boundary = pending.find(b"\n")
                    if boundary < 0:
                        break
                    if boundary > MAX_MESSAGE_BYTES:
                        self.events.put((name + "_ERROR", b"message exceeds size limit"))
                        return
                    line = bytes(pending[:boundary + 1])
                    del pending[:boundary + 1]
                    self.events.put((name, line))
                if len(pending) > MAX_MESSAGE_BYTES:
                    self.events.put((name + "_ERROR", b"message exceeds size limit"))
                    return
        except Exception as exc:  # noqa: BLE001
            self.events.put((name + "_ERROR", str(exc).encode()))

    def _audit(self, event: str, **fields: Any) -> None:
        import os
        from datetime import datetime, timezone
        record = {"timestamp": datetime.now(timezone.utc).isoformat(),
                  "server_id": self.server_id, "event": event, **fields}
        self.audit.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.audit, flags, 0o600)
        os.chmod(self.audit, 0o600)
        try:
            os.write(fd, json.dumps(record, separators=(",", ":")).encode("utf-8") + b"\n")
            os.fsync(fd)
        finally:
            os.close(fd)

    def _start(self) -> None:
        self.child = subprocess.Popen(
            self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=None, bufsize=0, start_new_session=(os.name == "posix"),
        )
        assert self.child.stdout
        threading.Thread(target=self._reader, args=("up", self.child.stdout), daemon=True).start()
        threading.Thread(target=self._reader, args=("down", sys.stdin.buffer), daemon=True).start()

    def _start_discovery(self, request: dict[str, Any], kind: str) -> None:
        down_id = request.get("id")
        key = _id_key(down_id)
        if key in self.used_ids or key in self.discovery or key in self.server_requests or key in self.abandoned_internal:
            self._send_host(_error(down_id, "duplicate or reserved JSON-RPC request id"))
            return
        self.used_ids.add(key)
        params = request.get("params") if isinstance(request.get("params"), dict) else {}
        requested_cursor = params.get("cursor") if kind == "list" else None
        if requested_cursor is not None and not isinstance(requested_cursor, str):
            self._send_host(_error(down_id, "invalid pagination cursor"))
            self.used_ids.discard(key)
            return
        state = Discovery(kind=kind, downstream_id=down_id, original_request=request,
                          requested_cursor=requested_cursor, tools=[], seen_cursors=set())
        self._request_page(state, None)

    def _request_page(self, state: Discovery, cursor: str | None) -> None:
        request_id = self._next_id()
        internal_key = _id_key(request_id)
        state.active_internal_id = request_id
        self.discovery[internal_key] = state
        self.deadlines[internal_key] = time.monotonic() + self.timeout
        params: dict[str, Any] = {}
        if state.kind == "list" and state.original_request is not None:
            original_params = state.original_request.get("params")
            if isinstance(original_params, dict) and "_meta" in original_params:
                params["_meta"] = original_params["_meta"]
        if cursor is not None:
            params["cursor"] = cursor
        self._send_upstream({"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params})

    def _finish_discovery(self, request_key: str, response: dict[str, Any]) -> None:
        state = self.discovery.pop(request_key)
        self.deadlines.pop(request_key, None)
        if "error" in response:
            self._send_host(_error(state.downstream_id, "upstream tools/list failed; CAPLOCK blocked access"))
            self.used_ids.discard(_id_key(state.downstream_id))
            return
        result = response.get("result")
        if not isinstance(result, dict) or not isinstance(result.get("tools"), list):
            self._send_host(_error(state.downstream_id, "malformed upstream tools/list response; blocked"))
            self.used_ids.discard(_id_key(state.downstream_id))
            return
        page_cursor = None
        if state.first_result is None:
            state.first_result = _verified_envelope(result)
        else:
            # The requested host page is selected by the cursor used to fetch it.
            page_cursor = state.cursor
        if state.kind == "list" and page_cursor == state.requested_cursor:
            state.selected_result = _verified_envelope(result)
        page_tools = result["tools"]
        state.tools.extend(page_tools)
        if len(state.tools) > MAX_TOOLS:
            self._send_host(_error(state.downstream_id, "tool inventory exceeds CAPLOCK safety limit; blocked"))
            self.used_ids.discard(_id_key(state.downstream_id))
            return
        cursor = result.get("nextCursor")
        if cursor is not None:
            if len(state.seen_cursors or set()) >= MAX_PAGES:
                self._send_host(_error(state.downstream_id, "tool inventory exceeds pagination safety limit; blocked"))
                self.used_ids.discard(_id_key(state.downstream_id))
                return
            if not isinstance(cursor, str) or not cursor or cursor in (state.seen_cursors or set()):
                self._send_host(_error(state.downstream_id, "invalid or cyclic pagination cursor; blocked"))
                self.used_ids.discard(_id_key(state.downstream_id))
                return
            assert state.seen_cursors is not None
            state.seen_cursors.add(cursor)
            state.cursor = cursor
            self._request_page(state, cursor)
            return
        try:
            verdict = verify_tools(state.tools, self.lock, self.public_key, self.server_id,
                                   self.trusted_key_fingerprint)
        except Exception as exc:  # noqa: BLE001
            print(f"CAPLOCK BLOCK: verification failed: {exc}", file=sys.stderr)
            self._audit("verification_failed", reason=str(exc))
            self._send_host(_error(state.downstream_id, "CAPLOCK verification failed; no tools exposed or call forwarded"))
            self.used_ids.discard(_id_key(state.downstream_id))
            return
        if verdict["status"] != "PASS":
            print(f"CAPLOCK BLOCK: drift added={verdict['added']} removed={verdict['removed']} changed={verdict['changed']}", file=sys.stderr)
            self._audit("drift_blocked", added=verdict["added"], removed=verdict["removed"], changed=verdict["changed"])
            self._send_host(_error(state.downstream_id, "CAPLOCK detected unapproved tool-definition drift; access blocked"))
            self.used_ids.discard(_id_key(state.downstream_id))
            return
        try:
            rollback = enforce_rollback_state(self.lock, self.state, self.server_id, self.bootstrap,
                                              expected_lock_sha256=verdict["lock_sha256"])
            self.bootstrap = False
        except CaplockError as exc:
            print(f"CAPLOCK BLOCK: {exc}", file=sys.stderr)
            self._audit("rollback_or_trust_blocked", reason=str(exc))
            self._send_host(_error(state.downstream_id, "CAPLOCK trust-state validation failed; access blocked"))
            self.used_ids.discard(_id_key(state.downstream_id))
            return
        self._audit("inventory_verified", sequence=rollback["sequence"], inventory_sha256=verdict["current_sha256"])
        if state.kind == "list":
            # Return only the first page, preserving the upstream cursor. All pages were verified.
            if state.requested_cursor is not None and state.selected_result is None:
                self._send_host(_error(state.downstream_id, "requested pagination cursor was not present in verified inventory"))
            else:
                selected = state.selected_result if state.requested_cursor is not None else state.first_result
                self._send_host({"jsonrpc": "2.0", "id": state.downstream_id, "result": selected or {"tools": []}})
            self.used_ids.discard(_id_key(state.downstream_id))
        else:
            assert state.original_request is not None
            params = state.original_request.get("params")
            name = params.get("name") if isinstance(params, dict) else None
            approved = {tool["name"] for tool in state.tools}
            if not isinstance(name, str) or name not in approved:
                self._audit("tool_call_blocked", reason="tool not in verified inventory",
                            tool_name=name if isinstance(name, str) else None)
                self._send_host(_error(state.downstream_id, "tool is not in the verified approved inventory"))
                self.used_ids.discard(_id_key(state.downstream_id))
                return
            downstream_key = _id_key(state.downstream_id)
            self.pending[downstream_key] = ("forwarded", state.downstream_id)
            self.deadlines[downstream_key] = time.monotonic() + self.timeout
            self._audit("tool_call_forwarded", sequence=rollback["sequence"], tool_name=name)
            self._send_upstream(state.original_request)

    def _handle_host(self, message: dict[str, Any]) -> None:
        method = message.get("method")
        has_id = "id" in message
        if not has_id:
            if method is None:
                raise ProxyError("host sent a JSON-RPC response without an id")
            if method == "notifications/cancelled":
                params = message.get("params")
                cancelled_id = params.get("requestId") if isinstance(params, dict) else None
                target_key = _id_key(cancelled_id)
                cancelled_preflight = False
                for internal_key, discovery_state in list(self.discovery.items()):
                    if _id_key(discovery_state.downstream_id) == target_key:
                        self.discovery.pop(internal_key, None)
                        self.deadlines.pop(internal_key, None)
                        self.abandoned_internal.add(internal_key)
                        if len(self.abandoned_internal) > 10000:
                            raise ProxyError("too many abandoned requests; restarting proxy is required")
                        cancelled_preflight = True
                        self._send_upstream({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                             "params": {"requestId": discovery_state.active_internal_id,
                                                         "reason": "downstream request cancelled"}})
                # Once the original call has been forwarded, its ID is unchanged.
                if not cancelled_preflight:
                    self._send_upstream(message)
                return
            self._send_upstream(message)
            return
        if not isinstance(method, str):
            # Host response to an upstream-initiated request. Do not let an
            # arbitrary host response become an upstream request injection.
            response_key = _id_key(message["id"])
            if response_key not in self.server_requests:
                raise ProxyError("host response does not match an upstream-initiated request")
            self.server_requests.remove(response_key)
            self._send_upstream(message)
            return
        if method == "tools/list":
            self._start_discovery(message, "list")
            return
        if method == "tools/call":
            self._start_discovery(message, "call")
            return
        request_id = message["id"]
        key = _id_key(request_id)
        if key in self.used_ids or key in self.discovery or key in self.server_requests or key in self.abandoned_internal:
            self._send_host(_error(request_id, "duplicate or reserved JSON-RPC request id"))
            return
        self.used_ids.add(key)
        self.pending[key] = ("forwarded", request_id)
        self.deadlines[key] = time.monotonic() + self.timeout
        self._send_upstream(message)

    def _handle_upstream(self, message: dict[str, Any]) -> None:
        if "method" in message:
            # Server notification or server-initiated request. Track request
            # IDs so unsolicited responses cannot be injected into the host.
            if "id" in message:
                request_key = _id_key(message["id"])
                if request_key in self.server_requests or request_key in self.pending or request_key in self.discovery or request_key in self.used_ids:
                    raise ProxyError("upstream reused an active JSON-RPC request id")
                if not self.allow_server_requests and message["method"] not in ALLOWED_SERVER_REQUESTS:
                    self._audit("server_request_blocked", method=str(message["method"])[:200])
                    self._send_upstream(_error(message["id"], "server-initiated request blocked by CAPLOCK policy",
                                               code=-32601))
                    return
                self.server_requests.add(request_key)
            self._send_host(message)
            return
        if "id" not in message:
            raise ProxyError("upstream sent a response without an id")
        request_id = message["id"]
        internal_key = _id_key(request_id)
        if internal_key in self.abandoned_internal:
            self.abandoned_internal.discard(internal_key)
            self.used_ids.discard(internal_key)
            return
        if internal_key in self.discovery:
            self._finish_discovery(internal_key, message)
            return
        pending = self.pending.pop(internal_key, None)
        if pending:
            self.deadlines.pop(internal_key, None)
            _, downstream_id = pending
            self._send_host({**message, "id": downstream_id})
            self.used_ids.discard(_id_key(downstream_id))
            return
        raise ProxyError("upstream sent a response with an unknown or inactive JSON-RPC request id")

    def run(self) -> int:
        self._start()
        assert self.child
        try:
            while self.alive:
                try:
                    source, raw = self.events.get(timeout=0.25)
                except queue.Empty:
                    if self.child.poll() is not None:
                        print("CAPLOCK BLOCK: upstream process exited", file=sys.stderr)
                        return 1
                    if self._expire():
                        return 1
                    continue
                if self._expire():
                    return 1
                if source.endswith("_EOF"):
                    if source == "down_EOF":
                        return 0
                    print("CAPLOCK BLOCK: upstream closed protocol stream", file=sys.stderr)
                    return 1
                if source.endswith("_ERROR"):
                    print(f"CAPLOCK BLOCK: {source}: {raw!r}", file=sys.stderr)
                    return 1
                assert raw is not None
                try:
                    message = _strict_loads(raw.decode("utf-8"))
                    if source == "down":
                        self._handle_host(message)
                    else:
                        self._handle_upstream(message)
                except Exception as exc:  # noqa: BLE001
                    print(f"CAPLOCK BLOCK: protocol/verification failure: {exc}", file=sys.stderr)
                    # Never attempt to recover by forwarding an uncertain message.
                    return 1
        finally:
            self._stop()

    def _expire(self) -> bool:
        """Handle expired deadlines. Returns True if the proxy must exit.

        An unanswered inventory (tools/list) request is a verification failure and
        is fatal. An unanswered forwarded request (for example a slow tool call) is
        answered with an error, cancelled upstream and any late response is dropped;
        the session stays up.
        """
        now = time.monotonic()
        expired = [key for key, deadline in self.deadlines.items() if now > deadline]
        if not expired:
            return False
        if any(key in self.discovery for key in expired):
            print("CAPLOCK BLOCK: upstream request timed out", file=sys.stderr)
            self._audit("upstream_timeout", pending_count=len(expired))
            return True
        for key in expired:
            self.deadlines.pop(key, None)
            entry = self.pending.pop(key, None)
            if entry is None:
                continue
            _, downstream_id = entry
            self.abandoned_internal.add(key)
            if len(self.abandoned_internal) > 10000:
                raise ProxyError("too many abandoned requests; restarting proxy is required")
            self._audit("forwarded_request_timeout")
            self._send_upstream({"jsonrpc": "2.0", "method": "notifications/cancelled",
                                 "params": {"requestId": downstream_id, "reason": "CAPLOCK timeout"}})
            self._send_host(_error(downstream_id, "upstream request timed out", code=-32001))
        return False

    def _stop(self) -> None:
        self.alive = False
        if self.child and self.child.poll() is None:
            if os.name == "posix":
                try:
                    os.killpg(self.child.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            else:
                self.child.terminate()
            try:
                self.child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(self.child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    self.child.kill()
                self.child.wait(timeout=2)


def run_proxy(command: list[str], lock: Path, public_key: Path,
              server_id: str, trusted_key_fingerprint: str, timeout: float = 120.0,
              state: Path | None = None, audit: Path | None = None, bootstrap: bool = False,
              allow_server_requests: bool = False) -> int:
    return StdioProxy(command, lock, public_key, server_id, trusted_key_fingerprint,
                      timeout, state, audit, bootstrap, allow_server_requests).run()
