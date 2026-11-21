"""Local workspace paths and the non-secret server configuration store.

Threat model notes:

* ``servers.json`` contains NO password, token, UUID or YAML. A file that
  contains a ``password``-like key is rejected outright (fail closed), so a
  hand-edited or older file can never make the app treat a secret as ordinary
  configuration.
* The file lives below the private workspace root; writes are atomic
  (same-directory temp file + ``os.replace``) and the private ACL is re-applied
  and re-verified by :mod:`ha_ui.core.private_fs`.
* Hosts/usernames are validated to a strict character set because they are
  handed to Paramiko (never to a shell). They are not shell-interpolated.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

from . import errors
from .errors import HaUiError
from .models import SERVER_IDS, ServerConfig
from . import hostkey

SCHEMA = "ha-ui/servers/1"
CONFIG_FILENAME = "servers.json"

_ALIAS_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,40}$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_FORBIDDEN_KEYS = frozenset({
    "password", "passwd", "secret", "token", "private_key", "uuid",
    "yaml", "content", "ssh_password",
})
_ALLOWED_SERVER_KEYS = frozenset({
    "alias", "host", "port", "username", "host_key_fingerprint",
})


def default_workspace_root() -> Path:
    """Private workspace below LOCALAPPDATA (overridable for tests/builds)."""
    override = os.environ.get("HA_UI_HOME")
    if override:
        return Path(override)
    local = os.environ.get("LOCALAPPDATA")
    if local:
        return Path(local) / "HASingbox"
    # Non-Windows developer fallback; never used by the packaged EXE.
    return Path.home() / ".has_ui"


def validate_host(value: str) -> str:
    value = (value or "").strip()
    if not value or len(value) > 253:
        raise HaUiError(errors.E_CONFIG, detail="host")
    if any(ch.isspace() for ch in value):
        raise HaUiError(errors.E_CONFIG, detail="host")
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    if not _HOSTNAME_RE.fullmatch(value):
        raise HaUiError(errors.E_CONFIG, detail="host")
    return value


def validate_username(value: str) -> str:
    value = (value or "").strip()
    if not _USERNAME_RE.fullmatch(value):
        raise HaUiError(errors.E_CONFIG, detail="username")
    return value


def validate_alias(value: str) -> str:
    value = (value or "").strip()
    if not _ALIAS_RE.fullmatch(value):
        raise HaUiError(errors.E_CONFIG, detail="alias")
    return value


def validate_port(value: Any) -> int:
    if isinstance(value, bool):
        raise HaUiError(errors.E_CONFIG, detail="port")
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise HaUiError(errors.E_CONFIG, detail="port") from None
    if not 1 <= port <= 65535:
        raise HaUiError(errors.E_CONFIG, detail="port")
    return port


def validate_server(server: ServerConfig) -> ServerConfig:
    if server.server_id not in SERVER_IDS:
        raise HaUiError(errors.E_CONFIG, detail="server-id")
    alias = validate_alias(server.alias) if server.alias else ""
    host = validate_host(server.host) if server.host else ""
    username = validate_username(server.username) if server.username else "root"
    port = validate_port(server.port)
    fingerprint = server.host_key_fingerprint
    if fingerprint is not None:
        fingerprint = hostkey.validate_fingerprint(fingerprint)
    return ServerConfig(server_id=server.server_id, alias=alias, host=host,
                        port=port, username=username,
                        host_key_fingerprint=fingerprint)


def default_servers() -> dict[str, ServerConfig]:
    return {
        "A": ServerConfig(server_id="A", alias="VPS A", host="", port=22,
                          username="root"),
        "B": ServerConfig(server_id="B", alias="VPS B", host="", port=22,
                          username="root"),
    }


class ServerConfigStore:
    """Load/save the two non-secret VPS identities."""

    def __init__(self, workspace: Path, config_path: Path | None = None) -> None:
        self.workspace = Path(workspace)
        self.path = Path(config_path) if config_path else (
            self.workspace / CONFIG_FILENAME)

    # ------------------------------------------------------------------ load --
    def load(self) -> dict[str, ServerConfig]:
        if not self.path.exists():
            return default_servers()
        try:
            raw = self.path.read_text(encoding="utf-8")
        except OSError:
            raise HaUiError(errors.E_STORE_IO, detail="servers-read") from None
        return self.parse(raw)

    @staticmethod
    def parse(raw: str) -> dict[str, ServerConfig]:
        try:
            doc = json.loads(raw)
        except ValueError:
            raise HaUiError(errors.E_CONFIG_SCHEMA, detail="json") from None
        if not isinstance(doc, dict) or set(doc) != {"schema", "servers"}:
            raise HaUiError(errors.E_CONFIG_SCHEMA, detail="root")
        if doc.get("schema") != SCHEMA:
            raise HaUiError(errors.E_CONFIG_SCHEMA, detail="schema")
        servers = doc.get("servers")
        if not isinstance(servers, dict) or set(servers) != set(SERVER_IDS):
            raise HaUiError(errors.E_CONFIG_SCHEMA, detail="servers")
        out: dict[str, ServerConfig] = {}
        for server_id in SERVER_IDS:
            record = servers.get(server_id)
            if not isinstance(record, dict):
                raise HaUiError(errors.E_CONFIG_SCHEMA, detail=server_id)
            folded = {str(key).casefold() for key in record}
            if folded & _FORBIDDEN_KEYS:
                # Never treat a secret-bearing legacy file as configuration.
                raise HaUiError(errors.E_CONFIG_SCHEMA, detail="secret-key")
            unknown = set(record) - _ALLOWED_SERVER_KEYS
            if unknown:
                raise HaUiError(errors.E_CONFIG_SCHEMA,
                                detail="unknown-key")
            server = ServerConfig(
                server_id=server_id,
                alias=record.get("alias", ""),
                host=record.get("host", ""),
                port=record.get("port", 22),
                username=record.get("username", "root"),
                host_key_fingerprint=record.get("host_key_fingerprint"),
            )
            out[server_id] = validate_server(server)
        return out

    # ------------------------------------------------------------------ save --
    def save(self, servers: dict[str, ServerConfig]) -> None:
        if set(servers) != set(SERVER_IDS):
            raise HaUiError(errors.E_CONFIG, detail="servers")
        payload: dict[str, Any] = {"schema": SCHEMA, "servers": {}}
        for server_id in SERVER_IDS:
            server = validate_server(servers[server_id])
            if server.server_id != server_id:
                raise HaUiError(errors.E_CONFIG, detail="server-id")
            payload["servers"][server_id] = {
                "alias": server.alias,
                "host": server.host,
                "port": server.port,
                "username": server.username,
                "host_key_fingerprint": server.host_key_fingerprint,
            }
        # Imported lazily: private_fs imports ha_tools for real ACL checks, and
        # config loading must stay usable for diagnostics even if tools break.
        from . import private_fs
        private_fs.ensure_private_dir(self.workspace, workspace=self.workspace)
        data = (json.dumps(payload, ensure_ascii=False, indent=2,
                           sort_keys=True) + "\n").encode("utf-8")
        private_fs.secure_write_replace(self.path, data,
                                        workspace=self.workspace)
        private_fs.verify_private_file(self.path)


def load_servers(workspace: Path | None = None) -> dict[str, ServerConfig]:
    root = Path(workspace) if workspace else default_workspace_root()
    return ServerConfigStore(root).load()
