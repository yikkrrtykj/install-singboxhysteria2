"""Paramiko-based SSH transport with pinned host keys and strict IO caps.

Design:

* the only authentication method in the MVP is an SSH password supplied by the
  operator (optionally from the Windows Credential Manager); no agent, no
  ``~/.ssh`` key discovery, no keyboard-interactive fallback;
* the server's host key is verified against the fingerprint the operator
  explicitly confirmed. An unknown or changed key stops the connection *before*
  authentication, so a password is never offered to an unverified host;
* commands are built by trusted internal code with a strict allowlist and never
  interpolate an operator-supplied string; output is capped and decoded as
  UTF-8 (replacement on invalid bytes);
* downloads use SFTP and re-verify regular-file/root-owner/0600 attributes and
  the opened file's own attributes before returning bytes.
"""

from __future__ import annotations

import select
import socket
import stat
import time

import paramiko

from . import errors, hostkey
from .errors import HaUiError
from .models import HostKeyInfo, ServerConfig

DEFAULT_TIMEOUT = 20.0
MAX_COMMAND_OUTPUT = 1024 * 1024
MAX_DOWNLOAD = 512 * 1024


def _map_transport_error(exc: BaseException) -> HaUiError:
    if isinstance(exc, HaUiError):
        return exc
    if isinstance(exc, paramiko.AuthenticationException):
        return HaUiError(errors.E_SSH_AUTH)
    if isinstance(exc, (paramiko.BadHostKeyException,)):
        return HaUiError(errors.E_HOSTKEY_MISMATCH, detail="host-key")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return HaUiError(errors.E_SSH_TIMEOUT)
    if isinstance(exc, paramiko.SSHException):
        return HaUiError(errors.E_SSH_PROTOCOL)
    if isinstance(exc, OSError):
        return HaUiError(errors.E_SSH_CONNECT)
    return HaUiError(errors.E_SSH_PROTOCOL)


class _PinnedHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Accept exactly the operator-confirmed SHA-256 fingerprint, or nothing."""

    def __init__(self, expected_fingerprint: str | None) -> None:
        self._expected = expected_fingerprint

    def missing_host_key(self, client, hostname, key) -> None:  # noqa: ANN001
        del client, hostname
        actual = hostkey.fingerprint_from_key(key)
        if not self._expected:
            raise HaUiError(errors.E_HOSTKEY_MISSING, detail="confirm-first")
        if not hostkey.fingerprint_matches(self._expected, actual):
            raise HaUiError(errors.E_HOSTKEY_MISMATCH, detail="fingerprint")


def probe_host_key(host: str, port: int,
                   timeout: float = DEFAULT_TIMEOUT) -> HostKeyInfo:
    """Read the server host key without authenticating or sending a password."""
    sock = None
    transport = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        return HostKeyInfo(algorithm=key.get_name(),
                           fingerprint=hostkey.fingerprint_from_key(key))
    except HaUiError:
        raise
    except Exception as exc:
        raise _map_transport_error(exc) from None
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass
        elif sock is not None:
            try:
                sock.close()
            except OSError:
                pass


class ParamikoSession:
    """One authenticated SSH connection. Not thread-safe; use inside a worker."""

    def __init__(self, client: paramiko.SSHClient,
                 server: ServerConfig) -> None:
        self._client = client
        self.server = server
        self._closed = False

    # ---------------------------------------------------------------- connect --
    @classmethod
    def connect(cls, server: ServerConfig, password: str, *,
                expected_fingerprint: str | None = None,
                timeout: float = DEFAULT_TIMEOUT) -> "ParamikoSession":
        if not server.host:
            raise HaUiError(errors.E_CONFIG, detail="host")
        if not password:
            raise HaUiError(errors.E_CREDENTIAL_MISSING, detail="password")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(
            _PinnedHostKeyPolicy(expected_fingerprint))
        try:
            client.connect(
                hostname=server.host,
                port=server.port,
                username=server.username,
                password=password,
                timeout=timeout,
                banner_timeout=timeout,
                auth_timeout=timeout,
                channel_timeout=timeout,
                look_for_keys=False,
                allow_agent=False,
            )
        except HaUiError:
            client.close()
            raise
        except Exception as exc:
            client.close()
            raise _map_transport_error(exc) from None
        session = cls(client, server)
        # Defense in depth: re-read the negotiated key and verify it again.
        try:
            actual = hostkey.fingerprint_from_key(
                client.get_transport().get_remote_server_key())
            if not expected_fingerprint:
                raise HaUiError(errors.E_HOSTKEY_MISSING, detail="confirm-first")
            if not hostkey.fingerprint_matches(expected_fingerprint, actual):
                raise HaUiError(errors.E_HOSTKEY_MISMATCH, detail="fingerprint")
        except HaUiError:
            session.close()
            raise
        except Exception:
            session.close()
            raise HaUiError(errors.E_SSH_PROTOCOL) from None
        return session

    # ---------------------------------------------------------------- helpers --
    @property
    def closed(self) -> bool:
        return self._closed

    def _require_open(self) -> None:
        if self._closed:
            raise HaUiError(errors.E_SSH_CLOSED)

    # ------------------------------------------------------------------- exec --
    def exec(self, command: str, *, stdin_data: bytes | None = None,
             timeout: float = 60.0,
             max_output: int = MAX_COMMAND_OUTPUT) -> tuple[int, str, str]:
        """Run one trusted, pre-built command; return (rc, stdout, stderr)."""
        self._require_open()
        if not isinstance(command, str) or not command or "\x00" in command:
            raise HaUiError(errors.E_USAGE, detail="command")
        try:
            stdin, stdout, stderr = self._client.exec_command(
                command, timeout=timeout, get_pty=False)
        except HaUiError:
            raise
        except Exception as exc:
            raise _map_transport_error(exc) from None
        channel = stdout.channel
        try:
            if stdin_data:
                stdin.write(stdin_data)
                stdin.flush()
            try:
                stdin.channel.shutdown_write()
            except Exception:
                pass
            out = bytearray()
            err = bytearray()
            deadline = time.monotonic() + timeout
            while True:
                progressed = False
                while channel.recv_ready():
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    out.extend(chunk)
                    progressed = True
                    if len(out) > max_output:
                        raise HaUiError(errors.E_SSH_PROTOCOL,
                                        detail="output-limit")
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    if not chunk:
                        break
                    err.extend(chunk)
                    progressed = True
                    if len(err) > max_output:
                        raise HaUiError(errors.E_SSH_PROTOCOL,
                                        detail="output-limit")
                if (channel.exit_status_ready() and not channel.recv_ready()
                        and not channel.recv_stderr_ready()):
                    break
                if time.monotonic() > deadline:
                    raise HaUiError(errors.E_SSH_TIMEOUT, detail="command")
                if not progressed:
                    try:
                        select.select([channel], [], [], 0.2)
                    except (OSError, ValueError):
                        time.sleep(0.05)
            rc = channel.recv_exit_status()
        except HaUiError:
            try:
                channel.close()
            except Exception:
                pass
            raise
        except Exception as exc:
            raise _map_transport_error(exc) from None
        return (int(rc),
                bytes(out).decode("utf-8", "replace"),
                bytes(err).decode("utf-8", "replace"))

    # ------------------------------------------------------------------- sftp --
    def download_file(self, remote_path: str,
                      *, max_bytes: int = MAX_DOWNLOAD) -> bytes:
        """Read a root-owned 0600 regular file, with attribute re-checks."""
        self._require_open()
        if not isinstance(remote_path, str) or not remote_path.startswith("/"):
            raise HaUiError(errors.E_USAGE, detail="remote-path")
        if "\x00" in remote_path:
            raise HaUiError(errors.E_USAGE, detail="remote-path")
        try:
            sftp = self._client.open_sftp()
        except Exception as exc:
            raise _map_transport_error(exc) from None
        try:
            try:
                before = sftp.lstat(remote_path)
            except IOError:
                raise HaUiError(errors.E_REMOTE_FILE, detail="missing") from None
            self._check_private_remote_file(before, max_bytes)
            try:
                handle = sftp.open(remote_path, "rb")
            except IOError:
                raise HaUiError(errors.E_REMOTE_FILE, detail="open") from None
            with handle:
                try:
                    opened = handle.stat()
                except IOError:
                    raise HaUiError(errors.E_REMOTE_FILE, detail="stat") from None
                self._check_private_remote_file(opened, max_bytes)
                if (int(before.st_size or -1) != int(opened.st_size or -2)
                        or int(before.st_mtime or -1) != int(opened.st_mtime or -2)):
                    raise HaUiError(errors.E_REMOTE_FILE, detail="changed")
                data = handle.read(max_bytes + 1)
                try:
                    after = handle.stat()
                except IOError:
                    after = None
                if after is not None and int(after.st_size or -1) != len(data):
                    raise HaUiError(errors.E_REMOTE_FILE, detail="changed")
            if len(data) > max_bytes:
                raise HaUiError(errors.E_REMOTE_FILE, detail="too-large")
            return data
        finally:
            try:
                sftp.close()
            except Exception:
                pass

    @staticmethod
    def _check_private_remote_file(attrs, max_bytes: int) -> None:  # noqa: ANN001
        mode = int(getattr(attrs, "st_mode", 0) or 0)
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise HaUiError(errors.E_REMOTE_FILE, detail="not-regular")
        if int(getattr(attrs, "st_uid", -1)) != 0:
            raise HaUiError(errors.E_REMOTE_FILE, detail="owner")
        if mode & 0o077:
            raise HaUiError(errors.E_REMOTE_FILE, detail="mode")
        size = int(getattr(attrs, "st_size", -1))
        if size < 0 or size > max_bytes:
            raise HaUiError(errors.E_REMOTE_FILE, detail="size")

    # ------------------------------------------------------------------ close --
    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._client.close()
        except Exception:
            pass

    def __enter__(self) -> "ParamikoSession":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        self.close()


def connect(server: ServerConfig, password: str, *,
            expected_fingerprint: str | None = None,
            timeout: float = DEFAULT_TIMEOUT) -> ParamikoSession:
    return ParamikoSession.connect(server, password,
                                   expected_fingerprint=expected_fingerprint,
                                   timeout=timeout)
