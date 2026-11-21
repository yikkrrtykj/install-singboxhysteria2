"""Tests for :mod:`ha_ui.core.hostkey` and :mod:`ha_ui.core.ssh_client`
(requirement D).

No network access and no SSH server are needed:

* fingerprints are derived from generated Paramiko keys;
* the pinned-host-key policy and :func:`ensure_trusted` are exercised directly;
* :func:`probe_host_key` is pointed at a loopback port that was just bound and
  closed, so it fails without any external network;
* download/session validation is tested through the pure helpers and through
  calls that are rejected before any socket is opened.
"""

from __future__ import annotations

import base64
import hashlib
import socket
import stat
from types import SimpleNamespace

import paramiko
import pytest

from ha_ui.core import errors, hostkey, ssh_client
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import ServerConfig


def _assert_error(exc_info: "pytest.ExceptionInfo[HaUiError]", code: str,
                  detail: str | None = None) -> None:
    err = exc_info.value
    assert isinstance(err, HaUiError), "expected HaUiError, got %r" % (err,)
    assert err.code == code, (
        "expected error code %r, got %r (detail=%r)" % (code, err.code, err.detail))
    if detail is not None:
        assert err.detail == detail, (
            "expected detail %r, got %r" % (detail, err.detail))


def _generate_key():
    """Ed25519Key.generate() if the installed Paramiko has it, else RSA 1024."""
    generator = getattr(paramiko.Ed25519Key, "generate", None)
    if generator is not None:
        return generator()
    return paramiko.RSAKey.generate(1024)


@pytest.fixture(scope="module")
def generated_key():
    return _generate_key()


@pytest.fixture(scope="module")
def other_key():
    return _generate_key()


# --------------------------------------------------------------------------- #
# Fingerprints
# --------------------------------------------------------------------------- #
def test_fingerprint_format_from_generated_key(generated_key) -> None:
    raw = generated_key.asbytes()
    fingerprint = hostkey.fingerprint_from_key(generated_key)
    assert fingerprint.startswith("SHA256:"), (
        "OpenSSH fingerprints use the SHA256: prefix, got %r" % fingerprint)
    assert hostkey.FINGERPRINT_RE.fullmatch(fingerprint), (
        "fingerprint does not match the strict OpenSSH format: %r" % fingerprint)
    assert len(fingerprint) == len("SHA256:") + 43
    assert hostkey.validate_fingerprint(fingerprint) == fingerprint

    # Independent computation from the SSH wire-format public key bytes.
    expected = "SHA256:" + base64.b64encode(
        hashlib.sha256(raw).digest()).decode("ascii").rstrip("=")
    assert fingerprint == expected
    assert fingerprint == hostkey.fingerprint_from_key_bytes(raw)


def test_fingerprint_is_deterministic_and_key_specific(generated_key,
                                                       other_key) -> None:
    first = hostkey.fingerprint_from_key(generated_key)
    second = hostkey.fingerprint_from_key(generated_key)
    assert first == second
    assert first != hostkey.fingerprint_from_key(other_key), (
        "two distinct keys must not share a fingerprint")


@pytest.mark.parametrize("raw", [b"", b"", b"ssh-rsa AAAA"])
def test_fingerprint_from_key_bytes_is_a_sha256_digest(raw: bytes) -> None:
    fingerprint = hostkey.fingerprint_from_key_bytes(raw)
    assert hostkey.FINGERPRINT_RE.fullmatch(fingerprint)


class _ExplodingKey:
    def asbytes(self):
        raise RuntimeError("key export exploded")


class _EmptyKey:
    def asbytes(self):
        return b""


class _TextKey:
    def asbytes(self):
        return "not-bytes"


@pytest.mark.parametrize("bad_key", [_ExplodingKey(), _EmptyKey(), _TextKey()])
def test_fingerprint_from_key_rejects_unusable_keys(bad_key) -> None:
    with pytest.raises(HaUiError) as excinfo:
        hostkey.fingerprint_from_key(bad_key)
    _assert_error(excinfo, errors.E_HOSTKEY_FORMAT, "key")


@pytest.mark.parametrize("value", [
    "", "SHA256:", "SHA256:abc", "SHA256:" + "A" * 42, "SHA256:" + "A" * 44,
    "SHA256:" + "A" * 43 + "=", "sha256:" + "A" * 43, "MD5:aa:bb", " ",
    "SHA256:" + "A" * 42 + "!", None, 42, b"SHA256:" + b"A" * 43,
])
def test_validate_fingerprint_rejects_garbage(value) -> None:
    with pytest.raises(HaUiError) as excinfo:
        hostkey.validate_fingerprint(value)
    _assert_error(excinfo, errors.E_HOSTKEY_FORMAT, "format")


def test_validate_fingerprint_accepts_valid_values() -> None:
    valid = "SHA256:" + "AbC012+/" * 5 + "AbC"
    assert len(valid) == 7 + 43
    assert hostkey.validate_fingerprint(valid) == valid
    assert hostkey.validate_fingerprint("SHA256:" + "A" * 43).startswith("SHA256:")


def test_fingerprint_matches_true_and_false(generated_key, other_key) -> None:
    fingerprint = hostkey.fingerprint_from_key(generated_key)
    other = hostkey.fingerprint_from_key(other_key)
    joined = "SHA256:" + fingerprint[len("SHA256:"):]
    assert hostkey.fingerprint_matches(fingerprint, joined) is True
    assert hostkey.fingerprint_matches(fingerprint, other) is False


@pytest.mark.parametrize("expected,actual", [
    ("bogus", "SHA256:" + "A" * 43),
    ("SHA256:" + "A" * 43, "bogus"),
    (None, "SHA256:" + "A" * 43),
])
def test_fingerprint_matches_validates_both_inputs(expected, actual) -> None:
    with pytest.raises(HaUiError) as excinfo:
        hostkey.fingerprint_matches(expected, actual)
    _assert_error(excinfo, errors.E_HOSTKEY_FORMAT)


# --------------------------------------------------------------------------- #
# Trust gate and pinned-host-key policy
# --------------------------------------------------------------------------- #
def test_ensure_trusted_requires_a_confirmed_fingerprint(generated_key) -> None:
    actual = hostkey.fingerprint_from_key(generated_key)
    with pytest.raises(HaUiError) as excinfo:
        hostkey.ensure_trusted(None, actual)
    _assert_error(excinfo, errors.E_HOSTKEY_MISSING, "confirm-first")
    with pytest.raises(HaUiError) as excinfo:
        hostkey.ensure_trusted("", actual)
    _assert_error(excinfo, errors.E_HOSTKEY_MISSING, "confirm-first")


def test_ensure_trusted_accepts_match_and_refuses_mismatch(generated_key,
                                                           other_key) -> None:
    expected = hostkey.fingerprint_from_key(generated_key)
    assert hostkey.ensure_trusted(expected, expected) is None
    with pytest.raises(HaUiError) as excinfo:
        hostkey.ensure_trusted(expected,
                               hostkey.fingerprint_from_key(other_key))
    _assert_error(excinfo, errors.E_HOSTKEY_MISMATCH, "fingerprint")
    assert expected not in str(excinfo.value), (
        "the fixed mismatch error must not log either fingerprint")


def test_pinned_policy_accepts_matching_fingerprint(generated_key) -> None:
    fingerprint = hostkey.fingerprint_from_key(generated_key)
    policy = ssh_client._PinnedHostKeyPolicy(fingerprint)
    assert policy.missing_host_key(None, "203.0.113.10",
                                   generated_key) is None


def test_pinned_policy_raises_missing_without_expected(generated_key) -> None:
    policy = ssh_client._PinnedHostKeyPolicy(None)
    with pytest.raises(HaUiError) as excinfo:
        policy.missing_host_key(None, "203.0.113.10", generated_key)
    _assert_error(excinfo, errors.E_HOSTKEY_MISSING, "confirm-first")


def test_pinned_policy_raises_mismatch_for_other_key(generated_key,
                                                     other_key) -> None:
    expected = hostkey.fingerprint_from_key(generated_key)
    policy = ssh_client._PinnedHostKeyPolicy(expected)
    with pytest.raises(HaUiError) as excinfo:
        policy.missing_host_key(None, "203.0.113.10", other_key)
    _assert_error(excinfo, errors.E_HOSTKEY_MISMATCH, "fingerprint")
    assert expected not in str(excinfo.value)


def test_pinned_policy_fails_closed_on_malformed_expected(generated_key) -> None:
    policy = ssh_client._PinnedHostKeyPolicy("not-a-fingerprint")
    with pytest.raises(HaUiError) as excinfo:
        policy.missing_host_key(None, "203.0.113.10", generated_key)
    _assert_error(excinfo, errors.E_HOSTKEY_FORMAT)


# --------------------------------------------------------------------------- #
# Error mapping
# --------------------------------------------------------------------------- #
def test_transport_error_mapping() -> None:
    pairs = [
        (paramiko.AuthenticationException("bad password"),
         errors.E_SSH_AUTH),
        (socket.timeout("timed out"), errors.E_SSH_TIMEOUT),
        (TimeoutError("timed out"), errors.E_SSH_TIMEOUT),
        (ConnectionRefusedError(10061, "refused"), errors.E_SSH_CONNECT),
        (paramiko.SSHException("protocol"), errors.E_SSH_PROTOCOL),
        (RuntimeError("unexpected"), errors.E_SSH_PROTOCOL),
    ]
    for exception, expected_code in pairs:
        mapped = ssh_client._map_transport_error(exception)
        assert isinstance(mapped, HaUiError)
        assert mapped.code == expected_code, (
            "%r should map to %s, got %s"
            % (type(exception).__name__, expected_code, mapped.code))


def test_transport_error_mapping_for_bad_host_key(generated_key,
                                                  other_key) -> None:
    exception = paramiko.BadHostKeyException("host", generated_key, other_key)
    mapped = ssh_client._map_transport_error(exception)
    assert mapped.code == errors.E_HOSTKEY_MISMATCH
    assert mapped.detail == "host-key"


def test_transport_error_mapping_passes_ha_ui_error_through() -> None:
    original = HaUiError(errors.E_SSH_CLOSED)
    assert ssh_client._map_transport_error(original) is original


# --------------------------------------------------------------------------- #
# probe_host_key without any external network
# --------------------------------------------------------------------------- #
def test_probe_host_key_fails_on_closed_loopback_port() -> None:
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    finally:
        probe.close()
    assert port > 0

    with pytest.raises(HaUiError) as excinfo:
        ssh_client.probe_host_key("127.0.0.1", port, timeout=0.75)
    err = excinfo.value
    assert err.code in (errors.E_SSH_CONNECT, errors.E_SSH_TIMEOUT), (
        "closed port must map to E_SSH_CONNECT or E_SSH_TIMEOUT, got %r"
        % err.code)
    safe_text = str(err).casefold()
    for leak in ("password", "sentinel", "secret"):
        assert leak not in safe_text


# --------------------------------------------------------------------------- #
# Session helpers: validation happens before any socket is opened
# --------------------------------------------------------------------------- #
def _dummy_session() -> ssh_client.ParamikoSession:
    server = ServerConfig(server_id="A", host="203.0.113.10", port=22)
    # The client object is never touched by the calls under test.
    return ssh_client.ParamikoSession(object(), server)


def test_connect_rejects_missing_host_without_network() -> None:
    with pytest.raises(HaUiError) as excinfo:
        ssh_client.ParamikoSession.connect(ServerConfig(server_id="A"),
                                           "password")
    _assert_error(excinfo, errors.E_CONFIG, "host")


def test_connect_rejects_missing_password_without_network() -> None:
    server = ServerConfig(server_id="A", host="203.0.113.10")
    with pytest.raises(HaUiError) as excinfo:
        ssh_client.ParamikoSession.connect(server, "")
    _assert_error(excinfo, errors.E_CREDENTIAL_MISSING, "password")


@pytest.mark.parametrize("command", ["", "ls\x00; rm -rf /", None, 42])
def test_exec_rejects_invalid_commands(command) -> None:
    session = _dummy_session()
    with pytest.raises(HaUiError) as excinfo:
        session.exec(command)
    _assert_error(excinfo, errors.E_USAGE, "command")


@pytest.mark.parametrize("remote_path", ["relative/file", "", "~/.ssh/id_rsa",
                                         "/tmp/x\x00y", None])
def test_download_file_rejects_invalid_remote_path(remote_path) -> None:
    session = _dummy_session()
    with pytest.raises(HaUiError) as excinfo:
        session.download_file(remote_path)
    _assert_error(excinfo, errors.E_USAGE, "remote-path")


def test_session_close_is_idempotent_and_blocks_operations() -> None:
    session = _dummy_session()
    assert session.closed is False
    session.close()
    assert session.closed is True
    session.close()  # must not raise
    with pytest.raises(HaUiError) as excinfo:
        session.exec("ls")
    _assert_error(excinfo, errors.E_SSH_CLOSED)


# --------------------------------------------------------------------------- #
# download_file attribute re-validation (static helper)
# --------------------------------------------------------------------------- #
def _attrs(mode, uid=0, size=10):
    return SimpleNamespace(st_mode=mode, st_uid=uid, st_size=size)


@pytest.mark.parametrize("attrs", [
    _attrs(stat.S_IFREG | 0o600, uid=0, size=0),
    _attrs(stat.S_IFREG | 0o400, uid=0, size=100),
    _attrs(stat.S_IFREG | 0o600, uid=0, size=100),
])
def test_download_attr_accepts_private_regular_root_files(attrs) -> None:
    ssh_client.ParamikoSession._check_private_remote_file(attrs, 100)


@pytest.mark.parametrize("attrs,expected_detail", [
    (_attrs(stat.S_IFLNK | 0o777), "not-regular"),
    (_attrs(stat.S_IFDIR | 0o700), "not-regular"),
    (_attrs(stat.S_IFIFO | 0o600), "not-regular"),
    (_attrs(stat.S_IFREG | 0o600, uid=1000), "owner"),
    (_attrs(stat.S_IFREG | 0o644), "mode"),
    (_attrs(stat.S_IFREG | 0o640), "mode"),
    (_attrs(stat.S_IFREG | 0o604), "mode"),
    (_attrs(stat.S_IFREG | 0o666), "mode"),
    (_attrs(stat.S_IFREG | 0o600, size=101), "size"),
    (_attrs(stat.S_IFREG | 0o600, size=-1), "size"),
    (SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_size=10), "owner"),
    (SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0), "size"),
])
def test_download_attr_rejects_unsafe_files(attrs, expected_detail: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        ssh_client.ParamikoSession._check_private_remote_file(attrs, 100)
    _assert_error(excinfo, errors.E_REMOTE_FILE, expected_detail)


def test_download_attr_size_boundary_is_inclusive() -> None:
    max_bytes = ssh_client.MAX_DOWNLOAD
    ok = _attrs(stat.S_IFREG | 0o600, size=max_bytes)
    ssh_client.ParamikoSession._check_private_remote_file(ok, max_bytes)
    too_large = _attrs(stat.S_IFREG | 0o600, size=max_bytes + 1)
    with pytest.raises(HaUiError) as excinfo:
        ssh_client.ParamikoSession._check_private_remote_file(too_large,
                                                              max_bytes)
    _assert_error(excinfo, errors.E_REMOTE_FILE, "size")
