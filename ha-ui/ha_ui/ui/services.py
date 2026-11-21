"""UI-facing service layer over the reviewed security core.

:class:`ServerActions` is the single dependency-injection seam for the UI: it
wraps the non-secret config store, the Windows Credential Manager store, the
host-key probe and the pinned SSH client. Production builds use the real
implementations; tests pass an :class:`~ha_ui.core.secrets_store.InMemoryCredentialStore`
and fake probe/connect callables, so no test ever touches the real vault or the
network.

The read-only preflight command is built here from constant text only. No
operator-supplied value is ever interpolated into it (host/username/port are
handed to Paramiko as data, never to a shell). The same command must stay in
sync with the future client-management slice.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from ..core import config_store, errors, secrets_store, ssh_client
from ..core.errors import HaUiError
from ..core.models import HostKeyInfo, RemoteFacts, ServerConfig
from ..core.secrets_store import CredentialStore

# Read-only facts collected by the test-connection button (and later by the
# client slice before it touches anything). Constant text: never interpolate.
PREFLIGHT_COMMAND = (
    "id -u; uname -s; "
    "test -f /root/sbox/sbconfig_server.json && echo config=present || echo config=missing; "
    "command -v miaomiao >/dev/null 2>&1 && echo manager=present || echo manager=missing"
)

ConnectFn = Callable[..., object]
ProbeFn = Callable[[str, int], HostKeyInfo]


def parse_preflight_output(stdout: str) -> RemoteFacts:
    """Turn the fixed preflight stdout into non-secret :class:`RemoteFacts`.

    The remote shell output is treated as untrusted text: only the fixed marker
    tokens are interpreted, the system name is only a short display label, and
    a response without both markers is ``E_SSH_PROTOCOL`` rather than a guessed
    success.
    """
    text = (stdout or "").replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.strip() for line in text.split("\n")]
    non_empty = [line for line in lines if line]
    if not non_empty:
        raise HaUiError(errors.E_SSH_PROTOCOL, detail="output")

    numeric = [line for line in non_empty if line.isdigit()]
    root = "0" in numeric
    platform = ""
    config_present: bool | None = None
    manager_present: bool | None = None
    for line in non_empty:
        if line == "config=present":
            config_present = True
        elif line == "config=missing":
            config_present = False
        elif line == "manager=present":
            manager_present = True
        elif line == "manager=missing":
            manager_present = False
        elif platform == "" and not line.isdigit():
            platform = line[:128]
    if config_present is None or manager_present is None:
        raise HaUiError(errors.E_SSH_PROTOCOL, detail="output")
    return RemoteFacts(root=root, os_release=platform,
                       config_present=config_present,
                       miaomiao_present=manager_present)


class ServerActions:
    """Testable wrapper around the security core's config/vault/SSH APIs."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        config_store_override: config_store.ServerConfigStore | None = None,
        credential_store: CredentialStore | None = None,
        probe_fn: ProbeFn | None = None,
        connect_fn: ConnectFn | None = None,
    ) -> None:
        self.workspace = Path(workspace)
        self.config_store = (config_store_override
                             if config_store_override is not None
                             else config_store.ServerConfigStore(self.workspace))
        self._credentials = (credential_store
                             if credential_store is not None
                             else secrets_store.default_credential_store())
        self._probe = probe_fn if probe_fn is not None else ssh_client.probe_host_key
        self._connect = connect_fn if connect_fn is not None else ssh_client.connect

    # --------------------------------------------------------------- config ---
    def load_servers(self) -> dict[str, ServerConfig]:
        return self.config_store.load()

    def save_server(self, server: ServerConfig) -> None:
        """Persist one validated, non-secret server identity (never a password)."""
        servers = self.config_store.load()
        servers[server.server_id] = config_store.validate_server(server)
        self.config_store.save(servers)

    # ----------------------------------------------------------- credentials ---
    def credential_available(self) -> bool:
        try:
            return bool(self._credentials.available())
        except Exception:  # noqa: BLE001 - a broken backend is simply unavailable
            return False

    def credential_backend_name(self) -> str:
        try:
            return str(self._credentials.backend_name())
        except Exception:  # noqa: BLE001
            return "unavailable"

    def save_password(self, server_id: str, password: str) -> None:
        self._credentials.save(server_id, password)

    def load_password(self, server_id: str) -> str | None:
        return self._credentials.load(server_id)

    def delete_password(self, server_id: str) -> bool:
        return bool(self._credentials.delete(server_id))

    # ------------------------------------------------------------------ ssh ---
    def probe_host_key(self, host: str, port: int) -> HostKeyInfo:
        """Read the server key without authenticating (worker thread only)."""
        clean_host = config_store.validate_host(host)
        clean_port = config_store.validate_port(port)
        return self._probe(clean_host, clean_port)

    def open_session(self, server: ServerConfig, password: str):
        """Open one pinned session for a client/generation operation.

        Worker thread only; the caller owns the returned session and must close
        it (``SessionGenerationService`` closes it in ``finally``). The same
        pre-connect gates as :meth:`test_connection` apply, so a missing host,
        unconfirmed fingerprint or missing password can never reach the network.
        """
        if not server.host:
            raise HaUiError(errors.E_CONFIG, detail="host")
        if not server.host_key_fingerprint:
            raise HaUiError(errors.E_HOSTKEY_MISSING, detail="confirm-first")
        if not isinstance(password, str) or not password:
            raise HaUiError(errors.E_CREDENTIAL_MISSING, detail="password")
        return self._connect(server, password,
                             expected_fingerprint=server.host_key_fingerprint)

    def test_connection(self, server: ServerConfig,
                        password: str) -> RemoteFacts:
        """Read-only preflight: pinned connect + one fixed exec command.

        Refuses before any network use unless a confirmed host-key fingerprint is
        stored and a password is available. The returned facts are metadata only;
        no remote text beyond the fixed markers is retained.
        """
        if not server.host:
            raise HaUiError(errors.E_CONFIG, detail="host")
        if not server.host_key_fingerprint:
            raise HaUiError(errors.E_HOSTKEY_MISSING, detail="confirm-first")
        if not isinstance(password, str) or not password:
            raise HaUiError(errors.E_CREDENTIAL_MISSING, detail="password")

        session = None
        try:
            session = self._connect(
                server, password,
                expected_fingerprint=server.host_key_fingerprint)
            exit_code, stdout, _stderr = session.exec(PREFLIGHT_COMMAND)
        finally:
            if session is not None:
                try:
                    session.close()
                except Exception:  # noqa: BLE001 - closing must not mask errors
                    pass
        if int(exit_code) != 0:
            raise HaUiError(errors.E_REMOTE_PREFLIGHT, detail="exit")
        return parse_preflight_output(stdout)
