"""Tests for :mod:`ha_ui.core.secrets_store` (requirement B + error hygiene).

The real Windows Credential Manager is never touched:

* :class:`InMemoryCredentialStore` is exercised directly;
* :class:`KeyringCredentialStore` gets a fake backend injected into its
  ``_backend`` instance attribute (the same contract ``keyring`` exposes), so
  read-back proof, failure mapping and deletion can be tested deterministically;
* the "vault unavailable" path is simulated by monkeypatching
  ``_windows_backend`` to return ``None``.
"""

from __future__ import annotations

import os

import pytest
from keyring.errors import PasswordDeleteError

from ha_ui import CREDENTIAL_SERVICE
from ha_ui.core import errors, secrets_store
from ha_ui.core.errors import HaUiError

VALID_PASSWORD = "correct horse battery staple"
PASSWORD_SENTINEL = "P@ssw0rd-sentinel-Z9!never-render-me"


def _assert_error(exc_info: "pytest.ExceptionInfo[HaUiError]", code: str,
                  detail: str | None = None) -> None:
    err = exc_info.value
    assert isinstance(err, HaUiError), "expected HaUiError, got %r" % (err,)
    assert err.code == code, (
        "expected error code %r, got %r (detail=%r)" % (code, err.code, err.detail))
    if detail is not None:
        assert err.detail == detail, (
            "expected detail %r, got %r" % (detail, err.detail))


class FakeKeyringBackend:
    """Contract-compatible stand-in for the real Windows vault backend."""

    def __init__(self) -> None:
        self.data: dict[tuple[str, str], str] = {}
        self.calls: list[tuple[str, str, str]] = []
        self.mismatch = False
        self.fail_set: BaseException | None = None
        self.fail_get: BaseException | None = None
        self.fail_delete: BaseException | None = None

    def set_password(self, service: str, account: str, password: str) -> None:
        self.calls.append(("set", service, account))
        if self.fail_set is not None:
            raise self.fail_set
        self.data[(service, account)] = password

    def get_password(self, service: str, account: str) -> str | None:
        self.calls.append(("get", service, account))
        if self.fail_get is not None:
            raise self.fail_get
        stored = self.data.get((service, account))
        if stored is not None and self.mismatch:
            return "tampered-" + stored
        return stored

    def delete_password(self, service: str, account: str) -> None:
        self.calls.append(("delete", service, account))
        if self.fail_delete is not None:
            raise self.fail_delete
        if (service, account) not in self.data:
            raise PasswordDeleteError("no such credential")
        del self.data[(service, account)]


@pytest.fixture()
def keyring_store() -> tuple[secrets_store.KeyringCredentialStore,
                             FakeKeyringBackend]:
    """A KeyringCredentialStore whose vault backend is a fake (no real writes)."""
    store = secrets_store.KeyringCredentialStore()
    backend = FakeKeyringBackend()
    # Deliberate injection: this is the documented seam used by the app/tests.
    store._backend = backend
    return store, backend


# --------------------------------------------------------------------------- #
# InMemoryCredentialStore
# --------------------------------------------------------------------------- #
def test_inmemory_available_and_backend_name() -> None:
    assert secrets_store.InMemoryCredentialStore().available() is True
    assert secrets_store.InMemoryCredentialStore().backend_name() == "in-memory"
    unavailable = secrets_store.InMemoryCredentialStore(available=False)
    assert unavailable.available() is False
    assert unavailable.backend_name() == "unavailable"


def test_inmemory_save_load_delete_roundtrip() -> None:
    store = secrets_store.InMemoryCredentialStore()
    assert store.load("A") is None, "fresh store must not report a credential"
    store.save("A", VALID_PASSWORD)
    store.save("B", "another-secret")
    assert store.load("A") == VALID_PASSWORD
    assert store.load("B") == "another-secret"
    assert store.delete("A") is True
    assert store.load("A") is None
    assert store.delete("A") is False, "deleting an absent credential returns False"
    assert store.load("B") == "another-secret", "delete must not touch other roles"


def test_inmemory_unavailable_reports_credential_unavailable() -> None:
    store = secrets_store.InMemoryCredentialStore(available=False)
    for operation in (
            lambda: store.save("A", VALID_PASSWORD),
            lambda: store.load("A"),
            lambda: store.delete("A"),
    ):
        with pytest.raises(HaUiError) as excinfo:
            operation()
        _assert_error(excinfo, errors.E_CREDENTIAL_UNAVAILABLE, "backend")


def test_inmemory_fail_on_save_maps_to_credential_store_error() -> None:
    store = secrets_store.InMemoryCredentialStore()
    store.fail_on_save = True
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", VALID_PASSWORD)
    _assert_error(excinfo, errors.E_CREDENTIAL_STORE, "write")
    assert store.load("A") is None, "a failed save must not claim a stored value"


@pytest.mark.parametrize("server_id", ["C", "AB", "", "a", "server-A"])
def test_inmemory_rejects_unknown_server_id(server_id: str) -> None:
    store = secrets_store.InMemoryCredentialStore()
    with pytest.raises(HaUiError) as excinfo:
        store.save(server_id, VALID_PASSWORD)
    _assert_error(excinfo, errors.E_CONFIG, "server-id")

    with pytest.raises(HaUiError) as excinfo:
        store.load(server_id)
    _assert_error(excinfo, errors.E_CONFIG, "server-id")

    with pytest.raises(HaUiError) as excinfo:
        store.delete(server_id)
    _assert_error(excinfo, errors.E_CONFIG, "server-id")


# --------------------------------------------------------------------------- #
# Password validation (shared by both stores)
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("password", ["", None, 123, b"bytes"])
def test_save_rejects_empty_or_non_string_password(password) -> None:
    store = secrets_store.InMemoryCredentialStore()
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", password)
    _assert_error(excinfo, errors.E_CONFIG, "password-empty")
    assert store.load("A") is None


def test_save_rejects_oversized_password() -> None:
    store = secrets_store.InMemoryCredentialStore()
    too_long = "x" * (secrets_store.MAX_PASSWORD_LENGTH + 1)
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", too_long)
    _assert_error(excinfo, errors.E_CONFIG, "password-length")

    maximum = "y" * secrets_store.MAX_PASSWORD_LENGTH
    store.save("A", maximum)
    assert store.load("A") == maximum


def test_save_rejects_nul_password() -> None:
    store = secrets_store.InMemoryCredentialStore()
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", "abc\x00def")
    _assert_error(excinfo, errors.E_CONFIG, "password-nul")
    assert "\x00" not in str(excinfo.value)


def test_save_accepts_unicode_password() -> None:
    store = secrets_store.InMemoryCredentialStore()
    password = "pässwörd-密码-🔑"
    store.save("B", password)
    assert store.load("B") == password


# --------------------------------------------------------------------------- #
# KeyringCredentialStore: platform / availability reporting
# --------------------------------------------------------------------------- #
@pytest.mark.skipif(os.name == "nt",
                    reason="real Windows vault host; unavailable path is "
                           "simulated with monkeypatch below")
def test_keyring_reports_unavailable_on_non_windows() -> None:
    store = secrets_store.KeyringCredentialStore()
    assert store.available() is False
    assert store._backend is None
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", VALID_PASSWORD)
    _assert_error(excinfo, errors.E_CREDENTIAL_UNAVAILABLE, "backend")


def test_keyring_reports_unavailable_when_backend_is_absent(monkeypatch) -> None:
    monkeypatch.setattr(secrets_store, "_windows_backend", lambda: None)
    store = secrets_store.KeyringCredentialStore()
    assert store._backend is None
    assert store.available() is False
    assert store.backend_name() == "unavailable"
    for operation in (
            lambda: store.save("A", VALID_PASSWORD),
            lambda: store.load("A"),
            lambda: store.delete("A"),
    ):
        with pytest.raises(HaUiError) as excinfo:
            operation()
        _assert_error(excinfo, errors.E_CREDENTIAL_UNAVAILABLE, "backend")


def test_default_credential_store_is_keyring_backed() -> None:
    store = secrets_store.default_credential_store()
    assert isinstance(store, secrets_store.KeyringCredentialStore)
    assert isinstance(store.available(), bool)


# --------------------------------------------------------------------------- #
# KeyringCredentialStore: read-back proof and failure mapping
# --------------------------------------------------------------------------- #
def test_keyring_save_then_readback_and_load(keyring_store) -> None:
    store, backend = keyring_store
    assert store.available() is True
    assert store._backend is backend
    assert store.backend_name().endswith("FakeKeyringBackend")

    store.save("A", VALID_PASSWORD)
    assert backend.data == {(CREDENTIAL_SERVICE, "server-A"): VALID_PASSWORD}
    assert store.load("A") == VALID_PASSWORD
    assert store.load("B") is None
    assert [call[0] for call in backend.calls].count("set") == 1
    assert [call[0] for call in backend.calls].count("get") >= 1, (
        "save() must read the value back before reporting success")


def test_keyring_save_rejects_readback_mismatch(keyring_store) -> None:
    store, backend = keyring_store
    backend.mismatch = True
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", VALID_PASSWORD)
    _assert_error(excinfo, errors.E_CREDENTIAL_STORE, "readback-mismatch")


def test_keyring_save_maps_write_exception(keyring_store) -> None:
    store, backend = keyring_store
    backend.fail_set = RuntimeError("vault exploded")
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", VALID_PASSWORD)
    _assert_error(excinfo, errors.E_CREDENTIAL_STORE, "write")
    assert backend.data == {}


def test_keyring_save_maps_readback_exception(keyring_store) -> None:
    store, backend = keyring_store
    backend.fail_get = RuntimeError("vault read exploded")
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", VALID_PASSWORD)
    _assert_error(excinfo, errors.E_CREDENTIAL_STORE, "readback")


def test_keyring_save_validates_before_touching_backend(keyring_store) -> None:
    store, backend = keyring_store
    invalid_inputs = [("A", ""), ("A", "x" * 1025), ("A", "a\x00b"),
                      ("C", VALID_PASSWORD)]
    for server_id, password in invalid_inputs:
        with pytest.raises(HaUiError):
            store.save(server_id, password)
    assert backend.calls == [], (
        "an invalid password/role must be rejected before any vault call")


def test_keyring_load_maps_failure_and_missing(keyring_store) -> None:
    store, backend = keyring_store
    assert store.load("A") is None
    backend.fail_get = RuntimeError("vault exploded")
    with pytest.raises(HaUiError) as excinfo:
        store.load("A")
    _assert_error(excinfo, errors.E_CREDENTIAL_STORE, "read")


def test_keyring_delete_success(keyring_store) -> None:
    store, backend = keyring_store
    store.save("B", VALID_PASSWORD)
    assert store.delete("B") is True
    assert store.load("B") is None


def test_keyring_delete_absent_returns_false(keyring_store) -> None:
    store, _backend = keyring_store
    assert store.delete("A") is False, (
        "keyring raises PasswordDeleteError for an absent credential; this is "
        "a no-op success, not a failure")


def test_keyring_delete_maps_other_failure(keyring_store) -> None:
    store, backend = keyring_store
    backend.fail_delete = RuntimeError("vault delete exploded")
    with pytest.raises(HaUiError) as excinfo:
        store.delete("A")
    _assert_error(excinfo, errors.E_CREDENTIAL_STORE, "delete")


# --------------------------------------------------------------------------- #
# Requirement F extension: fixed error text never echoes credential material
# --------------------------------------------------------------------------- #
def test_credential_errors_never_echo_password_material(keyring_store) -> None:
    store, backend = keyring_store
    secret_exception = RuntimeError("failed while storing " + PASSWORD_SENTINEL)
    backend.fail_set = secret_exception
    with pytest.raises(HaUiError) as excinfo:
        store.save("A", PASSWORD_SENTINEL)
    rendered = str(excinfo.value) + repr(excinfo.value)
    assert PASSWORD_SENTINEL not in rendered, (
        "HaUiError text must never include password material or raw backend "
        "exception text")
    assert excinfo.value.code == errors.E_CREDENTIAL_STORE
