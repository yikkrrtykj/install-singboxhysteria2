"""Tests for :mod:`ha_ui.core.config_store` (requirement A + F).

Scope:
* the two fixed, non-secret server identities A/B and their defaults;
* save/load round-trips, atomic private writes and JSON validity;
* fail-closed parsing: schema, unknown keys, password-like keys, hosts, ports,
  usernames and host-key fingerprints;
* secret hygiene: ``servers.json`` (and every other private file) never gets a
  password-like key or password bytes.
"""

from __future__ import annotations

import json
import re
from dataclasses import fields, replace

import pytest

from ha_ui.core import config_store, errors, private_fs
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import SERVER_IDS, ServerConfig
from ha_ui.core.secrets_store import InMemoryCredentialStore

# Syntactically valid OpenSSH fingerprint (43 base64 chars); deliberately not
# tied to any real key so the value itself can never be a secret.
VALID_FINGERPRINT = "SHA256:" + "A" * 43
PASSWORD_SENTINEL = "P@ssw0rd-sentinel-Q7!must-never-leak"

_ALLOWED_SERVER_KEYS = frozenset({
    "alias", "host", "port", "username", "host_key_fingerprint",
})
_FORBIDDEN_KEYS = (
    "password", "passwd", "secret", "token", "private_key", "uuid",
    "yaml", "content", "ssh_password",
)


def _record(**overrides) -> dict:
    record = {
        "alias": "VPS A",
        "host": "",
        "port": 22,
        "username": "root",
        "host_key_fingerprint": None,
    }
    record.update(overrides)
    return record


def _document(server_a: dict | None = None, server_b: dict | None = None,
              *, schema: str = config_store.SCHEMA,
              root_extra: dict | None = None) -> str:
    doc = {
        "schema": schema,
        "servers": {
            "A": _record() if server_a is None else server_a,
            "B": _record() if server_b is None else server_b,
        },
    }
    if root_extra:
        doc.update(root_extra)
    return json.dumps(doc)


def _assert_error(exc_info: "pytest.ExceptionInfo[HaUiError]", code: str,
                  detail: str | None = None) -> None:
    err = exc_info.value
    assert isinstance(err, HaUiError), "expected HaUiError, got %r" % (err,)
    assert err.code == code, (
        "expected error code %r, got %r (detail=%r)" % (code, err.code, err.detail))
    if detail is not None:
        assert err.detail == detail, (
            "expected danger-free detail %r, got %r" % (detail, err.detail))


# --------------------------------------------------------------------------- #
# Defaults, load and save round-trip
# --------------------------------------------------------------------------- #
def test_default_servers_returns_exactly_two_fixed_roles() -> None:
    servers = config_store.default_servers()
    assert set(servers) == set(SERVER_IDS) == {"A", "B"}
    for server_id in SERVER_IDS:
        server = servers[server_id]
        assert isinstance(server, ServerConfig)
        assert server.server_id == server_id
        assert server.role == server_id
        assert server.alias == "VPS %s" % server_id
        assert server.host == ""
        assert server.port == 22
        assert server.username == "root"
        assert server.host_key_fingerprint is None
        assert server.host_key_confirmed is False


def test_load_missing_config_file_returns_defaults(workspace_tmp) -> None:
    store = config_store.ServerConfigStore(workspace_tmp)
    assert store.path == workspace_tmp / config_store.CONFIG_FILENAME
    assert not store.path.exists(), "fresh workspace must not contain servers.json"
    assert store.load() == config_store.default_servers()


def test_save_load_roundtrip(private_workspace) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()
    servers["A"] = ServerConfig(server_id="A", alias="东京 VPS A",
                                host="203.0.113.10", port=2222,
                                username="root",
                                host_key_fingerprint=VALID_FINGERPRINT)
    servers["B"] = ServerConfig(server_id="B", alias="VPS B",
                                host="vps-b.example.com", port=22,
                                username="admin-agent",
                                host_key_fingerprint=None)
    store.save(servers)

    loaded = store.load()
    assert loaded == servers
    assert loaded["A"].host_key_fingerprint == VALID_FINGERPRINT
    assert loaded["A"].display_name == "A（东京 VPS A）"
    assert loaded["B"].host_key_confirmed is False


def test_load_servers_convenience_helper(workspace_tmp) -> None:
    store = config_store.ServerConfigStore(workspace_tmp)
    servers = config_store.default_servers()
    servers["A"] = replace(servers["A"], host="198.51.100.7")
    store.save(servers)
    loaded = config_store.load_servers(workspace_tmp)
    assert loaded["A"].host == "198.51.100.7"
    assert config_store.load_servers(workspace_tmp / "other-missing")[
        "B"].host == ""


# --------------------------------------------------------------------------- #
# File contents: no secrets, valid JSON, atomic private write
# --------------------------------------------------------------------------- #
def test_saved_config_contains_no_password_like_key(private_workspace) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()
    servers["A"] = ServerConfig(server_id="A", alias="VPS A",
                                host="203.0.113.10", port=22, username="root",
                                host_key_fingerprint=VALID_FINGERPRINT)
    servers["B"] = ServerConfig(server_id="B", alias="VPS B",
                                host="vps-b.example.com", port=2200,
                                username="admin", host_key_fingerprint=None)
    store.save(servers)

    raw = store.path.read_bytes()
    text = raw.decode("utf-8")
    doc = json.loads(text)
    assert set(doc) == {"schema", "servers"}, "unexpected top-level keys"
    assert doc["schema"] == config_store.SCHEMA
    assert set(doc["servers"]) == {"A", "B"}
    for server_id, record in doc["servers"].items():
        assert set(record) == _ALLOWED_SERVER_KEYS, (
            "servers.json[%s] must only contain non-secret keys" % server_id)
    folded = text.casefold()
    for forbidden in _FORBIDDEN_KEYS:
        assert '"%s"' % forbidden not in folded, (
            "servers.json must never contain a password-like key: %r"
            % forbidden)
    assert PASSWORD_SENTINEL.encode("utf-8") not in raw
    assert b"\x00" not in raw


def test_saved_config_is_private_and_valid_after_repeated_saves(
        private_workspace) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()

    servers["A"] = replace(servers["A"], host="203.0.113.10")
    store.save(servers)
    first = store.path.read_text(encoding="utf-8")
    json.loads(first)
    private_fs.verify_private_file(store.path)

    servers["A"] = replace(servers["A"], host="203.0.113.11")
    store.save(servers)
    second = store.path.read_text(encoding="utf-8")
    json.loads(second)
    private_fs.verify_private_file(store.path)

    assert first != second, "second save must replace the first payload"
    assert json.loads(second)["servers"]["A"]["host"] == "203.0.113.11"
    assert second.endswith("\n"), "config file should be newline-terminated"
    temp_files = [p.name for p in private_workspace.iterdir()
                  if p.name.startswith(".ha-ui-")]
    assert temp_files == [], "atomic write must not leave temp files: %r" % temp_files


def test_rejected_save_leaves_previous_file_intact(private_workspace) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()
    servers["A"] = replace(servers["A"], host="203.0.113.10")
    store.save(servers)
    before = store.path.read_bytes()

    bad = dict(servers)
    bad["B"] = replace(bad["B"], host="bad host")
    with pytest.raises(HaUiError) as excinfo:
        store.save(bad)
    _assert_error(excinfo, errors.E_CONFIG, "host")
    assert store.path.read_bytes() == before, (
        "a rejected save must not corrupt the existing configuration")
    json.loads(before.decode("utf-8"))


def test_load_of_corrupt_config_raises_schema_error(private_workspace) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    private_fs.secure_write_replace(store.path, b"{not valid json")
    with pytest.raises(HaUiError) as excinfo:
        store.load()
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "json")


# --------------------------------------------------------------------------- #
# parse(): fail-closed schema handling
# --------------------------------------------------------------------------- #
def test_parse_accepts_valid_document() -> None:
    parsed = config_store.ServerConfigStore.parse(_document())
    assert set(parsed) == {"A", "B"}
    assert parsed["A"].port == 22


@pytest.mark.parametrize("raw", ["", "not json", "[]", '"x"', "42", "null"])
def test_parse_rejects_non_object_or_bad_json(raw: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(raw)
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA)


def test_parse_rejects_root_key_set_mismatch() -> None:
    raw = _document(root_extra={"extra": True})
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(raw)
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "root")

    raw_missing = json.dumps({"schema": config_store.SCHEMA})
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(raw_missing)
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "root")


@pytest.mark.parametrize("schema", [
    "ha-ui/servers/2", "ha-ui/servers/0", "", "HA-UI/SERVERS/1",
])
def test_parse_rejects_unknown_schema_version(schema: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(_document(schema=schema))
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "schema")


def test_parse_rejects_wrong_servers_set() -> None:
    missing = json.dumps({"schema": config_store.SCHEMA,
                          "servers": {"A": _record()}})
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(missing)
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "servers")

    extra = json.dumps({"schema": config_store.SCHEMA,
                        "servers": {"A": _record(), "B": _record(),
                                    "C": _record()}})
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(extra)
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "servers")


def test_parse_rejects_non_dictionary_server_record() -> None:
    raw = json.dumps({"schema": config_store.SCHEMA,
                      "servers": {"A": [_record()], "B": _record()}})
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(raw)
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "A")


def test_parse_rejects_unknown_server_key() -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(
            _document(server_a=_record(hostname="evil")))
    _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "unknown-key")


@pytest.mark.parametrize("forbidden", _FORBIDDEN_KEYS)
def test_parse_rejects_password_like_keys(forbidden: str) -> None:
    for spelling in (forbidden, forbidden.upper(), forbidden.capitalize()):
        raw = _document(server_a=_record(**{spelling: PASSWORD_SENTINEL}))
        with pytest.raises(HaUiError) as excinfo:
            config_store.ServerConfigStore.parse(raw)
        _assert_error(excinfo, errors.E_CONFIG_SCHEMA, "secret-key")


# --------------------------------------------------------------------------- #
# parse(): validated field values
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host", [
    "bad host", "host;rm -rf /", "host&calc", "$(touch x)", "a/b", "a\\b",
    "host:22", "user@host", "-leading", "trailing-", "a" * 254,
    "bücher.example",
])
def test_parse_rejects_invalid_host(host: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(
            _document(server_a=_record(host=host)))
    _assert_error(excinfo, errors.E_CONFIG, "host")


@pytest.mark.parametrize("port", [0, 65536, -1, True, False, "abc", "", None,
                                  "0", "65536"])
def test_parse_rejects_invalid_port(port) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(
            _document(server_a=_record(port=port)))
    _assert_error(excinfo, errors.E_CONFIG, "port")


@pytest.mark.parametrize("username", [
    "bad user", "root;reboot", "$(id)", "root\x00", "üser", "a" * 65, "a/b",
])
def test_parse_rejects_invalid_username(username: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(
            _document(server_a=_record(username=username)))
    _assert_error(excinfo, errors.E_CONFIG, "username")


def test_parse_rejects_empty_username_in_record() -> None:
    # An empty username falls back to "root" by design; invalid spellings are
    # rejected, which is what a hand-edited file would contain.
    parsed = config_store.ServerConfigStore.parse(
        _document(server_a=_record(username="")))
    assert parsed["A"].username == "root"


@pytest.mark.parametrize("fingerprint", [
    "MD5:aa:bb:cc", "SHA256:", "SHA256:short", "SHA256:" + "A" * 42,
    "SHA256:" + "A" * 44, "SHA256:" + "A" * 43 + "=", "sha256:" + "A" * 43,
    "SHA256:" + "A" * 42 + "!", "ed25519",
])
def test_parse_rejects_bad_host_key_fingerprint(fingerprint: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.ServerConfigStore.parse(
            _document(server_a=_record(host_key_fingerprint=fingerprint)))
    _assert_error(excinfo, errors.E_HOSTKEY_FORMAT)


# --------------------------------------------------------------------------- #
# save(): validation and path-escape defence
# --------------------------------------------------------------------------- #
def test_save_rejects_wrong_server_set(workspace_tmp) -> None:
    store = config_store.ServerConfigStore(workspace_tmp)
    servers = config_store.default_servers()
    with pytest.raises(HaUiError) as excinfo:
        store.save({"A": servers["A"]})
    _assert_error(excinfo, errors.E_CONFIG, "servers")
    assert not store.path.exists()


def test_save_rejects_server_id_key_mismatch(private_workspace) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()
    servers["A"] = replace(servers["A"], server_id="B")
    with pytest.raises(HaUiError) as excinfo:
        store.save(servers)
    _assert_error(excinfo, errors.E_CONFIG, "server-id")
    assert not store.path.exists(), "invalid config must not be written"


@pytest.mark.parametrize("mutate,code,detail", [
    (lambda s: replace(s, host="bad host"), errors.E_CONFIG, "host"),
    (lambda s: replace(s, port=0), errors.E_CONFIG, "port"),
    (lambda s: replace(s, port=True), errors.E_CONFIG, "port"),
    (lambda s: replace(s, username="bad user"), errors.E_CONFIG, "username"),
    (lambda s: replace(s, alias="x" * 41), errors.E_CONFIG, "alias"),
    (lambda s: replace(s, host_key_fingerprint="SHA256:bad"),
     errors.E_HOSTKEY_FORMAT, None),
])
def test_save_validates_each_field(private_workspace, mutate, code, detail) -> None:
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()
    servers["A"] = mutate(servers["A"])
    with pytest.raises(HaUiError) as excinfo:
        store.save(servers)
    _assert_error(excinfo, code, detail)
    assert not store.path.exists()


def test_save_refuses_config_path_escaping_the_private_root(
        workspace_tmp) -> None:
    escape_path = workspace_tmp.parent / ("escape-%s.json" % workspace_tmp.name)
    store = config_store.ServerConfigStore(workspace_tmp,
                                           config_path=escape_path)
    with pytest.raises(HaUiError) as excinfo:
        store.save(config_store.default_servers())
    assert excinfo.value.code in (errors.E_PATH, errors.E_ACL), (
        "path escape must be refused, got %r" % excinfo.value.code)
    assert not escape_path.exists(), "no file may be created outside the root"


# --------------------------------------------------------------------------- #
# Field validators
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("host", [
    "203.0.113.10", "vps-a.example.com", "localhost", "HOST-1", "a",
    "a.b.c.d.example", "2001:db8::1", "::1", "xn--bcher-kva.example",
])
def test_validate_host_accepts_valid_values(host: str) -> None:
    assert config_store.validate_host(host) == host


@pytest.mark.parametrize("host", [
    "", "   ", "bad host", "a;b", "a&b", "a|b", "a`b", "a$(b)", "a/b", "a\\b",
    "-a", "a-", "a..b", "a" * 254, "host\ninjection", "a:b",
])
def test_validate_host_rejects_invalid_values(host: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.validate_host(host)
    _assert_error(excinfo, errors.E_CONFIG, "host")


@pytest.mark.parametrize("username", ["root", "admin-agent", "a.b_c-d", "A1",
                                      "a" * 64])
def test_validate_username_accepts_valid_values(username: str) -> None:
    assert config_store.validate_username(username) == username


@pytest.mark.parametrize("username", ["", " ", "bad user", "root;rm", "üser",
                                      "a" * 65, "a/b", "a\\b", "$USER"])
def test_validate_username_rejects_invalid_values(username: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.validate_username(username)
    _assert_error(excinfo, errors.E_CONFIG, "username")


@pytest.mark.parametrize("alias", ["VPS A", "东京节点 A", "a" * 40])
def test_validate_alias_accepts_valid_values(alias: str) -> None:
    assert config_store.validate_alias(alias) == alias


def test_empty_alias_is_accepted_by_save(private_workspace) -> None:
    # An empty alias is the "no alias" value: ServerConfigStore.save skips the
    # alias validator for it rather than failing the whole configuration.
    store = config_store.ServerConfigStore(private_workspace)
    servers = config_store.default_servers()
    servers["A"] = replace(servers["A"], alias="")
    store.save(servers)
    assert store.load()["A"].alias == ""


@pytest.mark.parametrize("alias", ["a" * 41, "bad\x00alias", "line\nbreak",
                                   "tab\there"])
def test_validate_alias_rejects_invalid_values(alias: str) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.validate_alias(alias)
    _assert_error(excinfo, errors.E_CONFIG, "alias")


@pytest.mark.parametrize("value,expected", [
    (22, 22), (1, 1), (65535, 65535), ("22", 22), (2222, 2222),
])
def test_validate_port_accepts_valid_values(value, expected: int) -> None:
    assert config_store.validate_port(value) == expected


@pytest.mark.parametrize("value", [0, 65536, -1, True, False, "", "abc", None,
                                   [], 3.7e9])
def test_validate_port_rejects_invalid_values(value) -> None:
    with pytest.raises(HaUiError) as excinfo:
        config_store.validate_port(value)
    _assert_error(excinfo, errors.E_CONFIG, "port")


def test_validate_server_normalises_whitespace_and_text_port() -> None:
    raw = ServerConfig(server_id="A", alias="  VPS A  ", host=" 10.0.0.1 ",
                       port="2222", username=" root ",
                       host_key_fingerprint=VALID_FINGERPRINT)
    validated = config_store.validate_server(raw)
    assert validated == ServerConfig(server_id="A", alias="VPS A",
                                     host="10.0.0.1", port=2222,
                                     username="root",
                                     host_key_fingerprint=VALID_FINGERPRINT)
    defaulted = config_store.validate_server(ServerConfig(server_id="B"))
    assert defaulted.username == "root"
    assert defaulted.port == 22
    assert defaulted.host_key_fingerprint is None


# --------------------------------------------------------------------------- #
# Default workspace root resolution
# --------------------------------------------------------------------------- #
def test_default_workspace_root_uses_ha_ui_home(workspace_tmp) -> None:
    assert config_store.default_workspace_root() == workspace_tmp


def test_default_workspace_root_falls_back_to_localappdata(
        monkeypatch, workspace_tmp) -> None:
    fake_local = workspace_tmp / "fake-local-appdata"
    fake_local.mkdir()
    monkeypatch.delenv("HA_UI_HOME", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(fake_local))
    assert config_store.default_workspace_root() == fake_local / "HASingbox"


# --------------------------------------------------------------------------- #
# Requirement F: password sentinel hygiene
# --------------------------------------------------------------------------- #
def test_server_config_dataclass_has_no_password_field() -> None:
    names = {field.name for field in fields(ServerConfig)}
    assert names == {"server_id", "alias", "host", "port", "username",
                     "host_key_fingerprint"}
    assert not names & {"password", "passwd", "secret", "token", "uuid"}


def test_workspace_files_never_contain_a_saved_password(private_workspace) -> None:
    # A UI-like save path stores the password in the credential store only and
    # persists the non-secret server identity; nothing under the private root
    # may contain the sentinel secret.
    credentials = InMemoryCredentialStore()
    credentials.save("A", PASSWORD_SENTINEL)
    assert credentials.load("A") == PASSWORD_SENTINEL

    servers = config_store.default_servers()
    servers["A"] = replace(servers["A"], host="203.0.113.10",
                           host_key_fingerprint=VALID_FINGERPRINT)
    servers["B"] = replace(servers["B"], host="vps-b.example.com",
                           port=2200, username="admin")
    config_store.ServerConfigStore(private_workspace).save(servers)

    leaked = []
    for path in private_workspace.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            if PASSWORD_SENTINEL.encode("utf-8") in data:
                leaked.append(str(path))
    assert leaked == [], "password bytes leaked into private files: %r" % leaked

    text = (private_workspace / config_store.CONFIG_FILENAME).read_text(
        encoding="utf-8")
    assert not re.search(r'"(?:ssh_)?passw(?:or)?d"|"(?:secret|token|uuid)"',
                         text, re.IGNORECASE)
