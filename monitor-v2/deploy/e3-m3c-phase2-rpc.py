#!/usr/bin/env python3
"""Narrow Phase 2 adapter around the reviewed E3RpcClient.

The adapter deliberately implements no transport, retry, transaction, or
reconciliation logic.  It validates one of the six frozen operations, reads a
non-secret JSON payload from stdin, and performs exactly one reviewed RPC.
"""

from __future__ import annotations

import json
import os
import re
import sys


OPS = {
    "management.status": frozenset(),
    "client.list": frozenset(),
    "management.activate": frozenset({"actor"}),
    "management.deactivate": frozenset({"actor"}),
    "client.add": frozenset({"name", "idempotency_key"}),
    "client.delete": frozenset({"name", "idempotency_key"}),
}
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$")
KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{16,128}$")
FP_RE = re.compile(r"^[0-9a-f]{16}$")


def reject(message: str) -> int:
    print(json.dumps({"ok": False, "adapter_error": message}, separators=(",", ":")))
    return 64


def main() -> int:
    if len(sys.argv) != 4:
        return reject("usage")
    op, app_root, payload_raw = sys.argv[1:]
    if op not in OPS:
        return reject("operation_not_allowed")
    if not os.path.isabs(app_root):
        return reject("app_root_not_absolute")
    try:
        payload = json.loads(payload_raw)
    except ValueError:
        return reject("payload_not_json")
    if not isinstance(payload, dict) or frozenset(payload) != OPS[op]:
        return reject("payload_shape")

    actor = payload.pop("actor", None)
    if actor is not None:
        if not isinstance(actor, dict) or frozenset(actor) != {"session_fp"}:
            return reject("actor_shape")
        if not isinstance(actor["session_fp"], str) or not FP_RE.fullmatch(actor["session_fp"]):
            return reject("actor_fingerprint")
    if op in ("client.add", "client.delete"):
        if not isinstance(payload["name"], str) or not NAME_RE.fullmatch(payload["name"]):
            return reject("client_name")
        key = payload["idempotency_key"]
        if not isinstance(key, str) or not KEY_RE.fullmatch(key):
            return reject("idempotency_key")

    sys.path.insert(0, app_root)
    try:
        from web.e3rpc import E3RpcClient, RpcTransportError

        result = E3RpcClient().call(op, payload=payload or None, actor=actor)
    except RpcTransportError as exc:
        print(json.dumps({
            "ok": False,
            "transport_error": {"stage": exc.stage, "uncertain": exc.uncertain},
        }, separators=(",", ":")))
        return 70
    except Exception:
        print(json.dumps({"ok": False, "adapter_error": "rpc_adapter_failure"}, separators=(",", ":")))
        return 70
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
