"""Windows Credential Manager storage for SSH passwords.

Contract (issue #110):

* a password is stored ONLY when the operator explicitly chooses "保存密码";
* before claiming success the backend must be the real Windows Credential
  Manager and the write must be read back and compared;
* if the vault is unavailable or the write fails, the app reports a failure and
  never writes the password anywhere else (no plaintext file, no env var, no
  command line);
* delete removes the vault entry; "不保存" simply keeps the password in memory
  for the current operation only.

The protocol exists so every test (and the UI in a non-Windows dev environment)
can use :class:`InMemoryCredentialStore` without touching a real vault.
"""

from __future__ import annotations

import os
from typing import Protocol

from .. import CREDENTIAL_SERVICE, SERVER_IDS
from . import errors
from .errors import HaUiError

MAX_PASSWORD_LENGTH = 1024


class CredentialStore(Protocol):
    def available(self) -> bool: ...
    def backend_name(self) -> str: ...
    def save(self, server_id: str, password: str) -> None: ...
    def load(self, server_id: str) -> str | None: ...
    def delete(self, server_id: str) -> bool: ...


def _account(server_id: str) -> str:
    if server_id not in SERVER_IDS:
        raise HaUiError(errors.E_CONFIG, detail="server-id")
    return "server-%s" % server_id


def _validate_password(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise HaUiError(errors.E_CONFIG, detail="password-empty")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise HaUiError(errors.E_CONFIG, detail="password-length")
    if "\x00" in password:
        raise HaUiError(errors.E_CONFIG, detail="password-nul")
    return password


def _windows_backend():
    """The real Windows vault backend, or None on any other environment."""
    if os.name != "nt":
        return None
    try:
        import keyring
        from keyring.backends import Windows
    except Exception:
        return None
    try:
        backend = keyring.get_keyring()
    except Exception:
        return None
    if isinstance(backend, Windows.WinVaultKeyring):
        return backend
    return None


class KeyringCredentialStore:
    """Thin wrapper around the real Windows Credential Manager (keyring)."""

    def __init__(self) -> None:
        self._backend = _windows_backend()

    def available(self) -> bool:
        return self._backend is not None

    def backend_name(self) -> str:
        if self._backend is None:
            return "unavailable"
        return "%s.%s" % (type(self._backend).__module__,
                          type(self._backend).__name__)

    def _require(self) -> None:
        if self._backend is None:
            raise HaUiError(errors.E_CREDENTIAL_UNAVAILABLE, detail="backend")

    def save(self, server_id: str, password: str) -> None:
        self._require()
        _validate_password(password)
        account = _account(server_id)
        try:
            self._backend.set_password(CREDENTIAL_SERVICE, account, password)
        except Exception:
            # Keyring errors may echo service/account only; still never render
            # the exception text in the UI or a log file.
            raise HaUiError(errors.E_CREDENTIAL_STORE, detail="write") from None
        # Read-back proof: never report "saved" without it.
        try:
            readback = self._backend.get_password(CREDENTIAL_SERVICE, account)
        except Exception:
            raise HaUiError(errors.E_CREDENTIAL_STORE, detail="readback") from None
        if readback != password:
            raise HaUiError(errors.E_CREDENTIAL_STORE, detail="readback-mismatch")

    def load(self, server_id: str) -> str | None:
        self._require()
        try:
            return self._backend.get_password(CREDENTIAL_SERVICE,
                                              _account(server_id))
        except Exception:
            raise HaUiError(errors.E_CREDENTIAL_STORE, detail="read") from None

    def delete(self, server_id: str) -> bool:
        self._require()
        account = _account(server_id)
        try:
            self._backend.delete_password(CREDENTIAL_SERVICE, account)
            return True
        except Exception:
            # keyring raises PasswordDeleteError when absent; treat only the
            # absent case as a no-op success and anything else as a failure.
            try:
                from keyring.errors import PasswordDeleteError
            except Exception:
                PasswordDeleteError = ()  # type: ignore[assignment]
            if PasswordDeleteError and isinstance(
                    __import__("sys").exc_info()[1], PasswordDeleteError):
                return False
            raise HaUiError(errors.E_CREDENTIAL_STORE, detail="delete") from None


class InMemoryCredentialStore:
    """Deterministic store for tests and non-Windows development runs."""

    def __init__(self, available: bool = True) -> None:
        self._available = available
        self._data: dict[str, str] = {}
        self.fail_on_save = False

    def available(self) -> bool:
        return self._available

    def backend_name(self) -> str:
        return "in-memory" if self._available else "unavailable"

    def save(self, server_id: str, password: str) -> None:
        if not self._available:
            raise HaUiError(errors.E_CREDENTIAL_UNAVAILABLE, detail="backend")
        _validate_password(password)
        if self.fail_on_save:
            raise HaUiError(errors.E_CREDENTIAL_STORE, detail="write")
        self._data[_account(server_id)] = password

    def load(self, server_id: str) -> str | None:
        if not self._available:
            raise HaUiError(errors.E_CREDENTIAL_UNAVAILABLE, detail="backend")
        return self._data.get(_account(server_id))

    def delete(self, server_id: str) -> bool:
        if not self._available:
            raise HaUiError(errors.E_CREDENTIAL_UNAVAILABLE, detail="backend")
        account = _account(server_id)
        return self._data.pop(account, None) is not None


def default_credential_store() -> CredentialStore:
    return KeyringCredentialStore()
