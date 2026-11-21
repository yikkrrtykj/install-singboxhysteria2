"""Hermetic tests for the read-only remote provider (``ha_ui.core.remote``).

Every test drives the *real* :class:`RemoteProvider` against a scripted
:class:`~tests.fakes.FakeSession`; no SSH, no network, no real VPS.  The fakes
return the exact command-shaped metadata the provider parses, so these tests
pin the refusal mapping, the derived-export freshness gate, the certificate pin
parsing and the explicit CLI-consent behaviour of the remote read path.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from ha_ui.core import errors, remote
from ha_ui.core.errors import HaUiError
from ha_ui.core.chain import validate_client_records
from ha_ui.core.models import CertPin
from tests import fakes
from tests.fakes import (
    ClientSpec,
    DerivedState,
    FakeSession,
    PinsReply,
    VpsFacts,
)

NOW = datetime(2026, 11, 21, 12, 0, 0, tzinfo=timezone.utc)


def make_provider(role: str = "A", **session_kwargs):
    session = FakeSession(role, **session_kwargs)
    return remote.RemoteProvider(role, session), session


# --------------------------------------------------------------------------- #
# Preflight: happy path and every fixed refusal mapping.
# --------------------------------------------------------------------------- #
def test_preflight_happy_path_reports_install_facts():
    provider, _ = make_provider()
    facts = provider.preflight()
    assert isinstance(facts, remote.RemotePreflight)
    assert facts.okay is True
    assert facts.root is True
    assert facts.os_name == "Linux"
    assert facts.config_present is True
    assert facts.state_present is True
    assert facts.manager_present is True
    assert facts.jq_present is True
    assert facts.openssl_present is True
    assert facts.api_secret_present is True
    assert facts.management_active is False
    assert facts.config_mtime == fakes.DEFAULT_CONFIG_MTIME


def test_preflight_nonzero_command_exit_maps_to_remote_command():
    provider, _ = make_provider(facts=VpsFacts(preflight_rc=2))
    with pytest.raises(HaUiError) as excinfo:
        provider.preflight()
    assert excinfo.value.code == errors.E_REMOTE_COMMAND
    assert excinfo.value.detail == "preflight"


@pytest.mark.parametrize("fact_overrides, code, detail", [
    pytest.param({"root": False}, errors.E_REMOTE_NOT_ROOT, None,
                 id="non-root"),
    pytest.param({"os_name": "Darwin"}, errors.E_REMOTE_PLATFORM, None,
                 id="non-linux"),
    pytest.param({"config_present": False}, errors.E_REMOTE_PREFLIGHT,
                 "install", id="missing-config"),
    pytest.param({"state_present": False}, errors.E_REMOTE_PREFLIGHT,
                 "install", id="missing-state"),
    pytest.param({"manager_present": False}, errors.E_REMOTE_PREFLIGHT,
                 "miaomiao", id="missing-manager"),
    pytest.param({"jq_present": False}, errors.E_REMOTE_PREFLIGHT, "jq",
                 id="missing-jq"),
    pytest.param({"openssl_present": False}, errors.E_REMOTE_PREFLIGHT,
                 "openssl", id="missing-openssl"),
    pytest.param({"management_active": True}, errors.E_REMOTE_PREFLIGHT,
                 "management-active", id="management-active"),
    pytest.param({"api_present": False}, errors.E_REMOTE_PREFLIGHT,
                 "api-migration", id="api-secret-missing"),
])
def test_preflight_refusals(fact_overrides, code, detail):
    provider, _ = make_provider(facts=VpsFacts(**fact_overrides))
    with pytest.raises(HaUiError) as excinfo:
        provider.preflight()
    assert excinfo.value.code == code
    assert excinfo.value.detail == detail


# --------------------------------------------------------------------------- #
# Client list: derived-export freshness/ownership gate and protocol problems.
# --------------------------------------------------------------------------- #
def test_list_marks_only_fresh_private_root_owned_derived_exports_present():
    clients = [
        ClientSpec("fresh", derived=DerivedState()),
        ClientSpec("stale", derived=DerivedState(fresh=False)),
        ClientSpec("mode644", derived=DerivedState(mode=0o644)),
        ClientSpec("uid1000", derived=DerivedState(uid=1000)),
        ClientSpec("empty", derived=DerivedState(size=0)),
        ClientSpec("oversize", derived=DerivedState(
            size=remote.MAX_EXPORT_BYTES + 1)),
        ClientSpec("missing", derived=None),
    ]
    provider, _ = make_provider(clients=clients)
    records = provider.list_clients()
    assert set(records) == {spec.name for spec in clients}
    assert records["fresh"].derived_export_present is True
    for name in ("stale", "mode644", "uid1000", "empty", "oversize",
                 "missing"):
        assert records[name].derived_export_present is False, name
    # Protocol completeness is independent of the derived-file freshness gate.
    assert all(record.complete for record in records.values())


def test_list_name_set_mismatch_reports_problems_and_incomplete_records():
    clients = [
        ClientSpec("alpha", hy2_cred=None),        # Reality only
        ClientSpec("beta", reality_cred=None),     # HY2 only
    ]
    provider, _ = make_provider(clients=clients)
    records = provider.list_clients()
    assert set(records) == {"alpha", "beta"}
    for name in ("alpha", "beta"):
        record = records[name]
        assert "name-set-mismatch" in record.problems
        assert record.complete is False
        assert record.exportable is False
    assert "missing-hy2" in records["alpha"].problems
    assert "missing-reality" in records["beta"].problems
    assert validate_client_records(records) == []


def test_list_empty_credentials_report_problems_and_incomplete_records():
    clients = [ClientSpec("blank", reality_cred=False, hy2_cred=False)]
    provider, _ = make_provider(clients=clients)
    record = provider.list_clients()["blank"]
    assert record.reality_ok is False
    assert record.hy2_ok is False
    assert record.complete is False
    assert "no-reality-credential" in record.problems
    assert "no-hy2-credential" in record.problems


def test_list_casefold_duplicate_protocol_entries_report_a_problem():
    """Two entries collapsing under casefold are one identity on Windows."""
    clients = [
        ClientSpec("Dup", hy2_cred=None),
        ClientSpec("dup", reality_cred=None),
        ClientSpec("Dup", reality_cred=None, hy2_cred=True),
        ClientSpec("dup", reality_cred=True, hy2_cred=None),
    ]
    provider, _ = make_provider(clients=clients)
    records = provider.list_clients()
    for name in records:
        assert "duplicate-name" in records[name].problems, name
        assert records[name].exportable is False
    assert validate_client_records(records) == []


def test_list_same_spelling_duplicate_protocol_entries_report_a_problem():
    clients = [ClientSpec("dup"), ClientSpec("dup")]
    provider, _ = make_provider(clients=clients)
    records = provider.list_clients()
    assert "duplicate-name" in records["dup"].problems
    assert records["dup"].exportable is False
    assert validate_client_records(records) == []


def test_list_unnamed_protocol_entries_report_a_problem():
    clients = [
        ClientSpec("ok"),
        ClientSpec(None, reality_cred=True, hy2_cred=False),
    ]
    provider, _ = make_provider(clients=clients)
    records = provider.list_clients()
    assert "unnamed-reality" in records["ok"].problems
    assert records["ok"].exportable is False
    assert validate_client_records(records) == []


def test_list_ambiguous_inbound_count_reports_a_problem():
    provider, _ = make_provider(
        clients=[ClientSpec("ok")],
        facts=VpsFacts(reality_inbounds=2))
    records = provider.list_clients()
    assert "reality-inbound-count" in records["ok"].problems
    assert records["ok"].exportable is False
    assert validate_client_records(records) == []


# --------------------------------------------------------------------------- #
# HY2 certificate pins: parse and fixed failures.
# --------------------------------------------------------------------------- #
def test_read_pins_parses_and_normalises_the_remote_certificate():
    session = FakeSession("A", pins=PinsReply(
        fingerprint=fakes.PIN_A.upper(),
        not_before="2026-05-01T00:00:00Z",
        not_after="2027-05-01T00:00:00Z"))
    pins = remote.RemoteProvider("A", session).read_pins()
    assert set(pins) == {"A"}
    pin = pins["A"]
    assert pin.fingerprint_sha256 == fakes.PIN_A
    assert pin.not_before == fakes.NOT_BEFORE
    assert pin.not_after == fakes.NOT_AFTER
    assert pin.source == "ssh-openssl-hy2-in-2026-05-01"


@pytest.mark.parametrize("reply, code, detail", [
    pytest.param(PinsReply(rc=1, stderr="REFUSE: not-pem\n"),
                 errors.E_REMOTE_PIN, "REFUSE", id="refused-cert"),
    pytest.param(PinsReply(raw_stdout=(
        "fingerprint=not-hex not_before=2026-05-01T00:00:00Z "
        "not_after=2027-05-01T00:00:00Z\n")),
        errors.E_REMOTE_PIN, "output", id="malformed-hex"),
    pytest.param(PinsReply(raw_stdout=(
        "fingerprint=%s not_before=2026-13-01T00:00:00Z "
        "not_after=2027-05-01T00:00:00Z\n" % fakes.PIN_A)),
        errors.E_REMOTE_PIN, "date", id="malformed-date"),
    pytest.param(PinsReply(raw_stdout=(
        "fingerprint=%s not_before=2027-05-01T00:00:00Z "
        "not_after=2026-05-01T00:00:00Z\n" % fakes.PIN_A)),
        errors.E_PIN_FORMAT, "window", id="inverted-window"),
])
def test_read_pins_malformed_outputs(reply, code, detail):
    session = FakeSession("A", pins=reply)
    with pytest.raises(HaUiError) as excinfo:
        remote.RemoteProvider("A", session).read_pins()
    assert excinfo.value.code == code
    assert excinfo.value.detail == detail


def _pair(*, a=fakes.PIN_A, b=fakes.PIN_B,
          not_before: datetime = fakes.NOT_BEFORE,
          not_after: datetime = fakes.NOT_AFTER,
          b_not_before: datetime | None = None,
          b_not_after: datetime | None = None) -> dict[str, CertPin]:
    return {
        "A": CertPin(a, not_before, not_after, "test"),
        "B": CertPin(b, b_not_before or not_before,
                     b_not_after or not_after, "test"),
    }


def test_validate_pins_pair_happy_path():
    assert remote.validate_pins_pair(_pair(), now=NOW) is None


def test_validate_pins_pair_accepts_lower_case_hex_only():
    with pytest.raises(HaUiError) as excinfo:
        remote.validate_pins_pair(_pair(b="ZZ" * 32), now=NOW)
    assert excinfo.value.code == errors.E_PIN_FORMAT
    assert excinfo.value.detail == "B"


@pytest.mark.parametrize("pins, code, detail", [
    pytest.param(_pair(b=fakes.PIN_A), errors.E_PIN_REUSED, "pin",
                 id="same-fingerprint"),
    pytest.param(_pair(b_not_before=NOW - timedelta(days=30),
                       b_not_after=NOW - timedelta(days=1)),
                 errors.E_PIN_EXPIRED, "B", id="expired"),
    pytest.param(_pair(b_not_before=NOW - timedelta(days=30),
                       b_not_after=NOW + timedelta(hours=1)),
                 errors.E_PIN_EXPIRED, "B", id="less-than-24h"),
    pytest.param(_pair(b_not_before=NOW + timedelta(hours=1)),
                 errors.E_PIN_FORMAT, "B", id="future-not-before"),
    pytest.param(_pair(b_not_before=NOW + timedelta(days=30),
                       b_not_after=NOW + timedelta(days=10)),
                 errors.E_PIN_FORMAT, "B", id="inverted-window"),
    pytest.param({"A": CertPin(fakes.PIN_A, fakes.NOT_BEFORE,
                               fakes.NOT_AFTER, "test")},
                 errors.E_REMOTE_PIN, "servers", id="missing-server"),
])
def test_validate_pins_pair_refusals(pins, code, detail):
    with pytest.raises(HaUiError) as excinfo:
        remote.validate_pins_pair(pins, now=NOW)
    assert excinfo.value.code == code
    assert excinfo.value.detail == detail


def test_validate_pins_pair_rejects_missing_validity_floor():
    """The app-level floor must reject a certificate that expires tomorrow."""
    pins = _pair(b_not_before=NOW - timedelta(days=30),
                 b_not_after=NOW + timedelta(hours=12))
    with pytest.raises(HaUiError) as excinfo:
        remote.validate_pins_pair(pins, now=NOW)
    assert excinfo.value.code == errors.E_PIN_EXPIRED
    assert remote.MIN_PIN_VALIDITY_HOURS == 24


def test_pin_warning_flags_a_near_expiry_window():
    near = _pair(b_not_after=NOW + timedelta(days=10))
    assert remote.pin_warning(near, now=NOW) is not None
    far = _pair()
    assert remote.pin_warning(far, now=NOW) is None


# --------------------------------------------------------------------------- #
# generate_exports: freshness, explicit CLI consent, download hash check.
# --------------------------------------------------------------------------- #
def test_fresh_derived_exports_never_run_the_menu():
    session = FakeSession("A", clients=[ClientSpec(
        "fresh", derived=DerivedState())], exports={"fresh": b"canonical-A"})
    provider = remote.RemoteProvider("A", session)
    assert provider.generate_exports(["fresh"], allow_cli=False) == {
        "fresh": b"canonical-A"}
    assert session.menu_invoked is False
    assert not any("HAUI_MENU_END" in command
                   for command in session.commands)
    assert session.downloads == [
        "/root/sbox/clients/fresh/mihomo.yaml"]


def test_stale_derived_exports_require_explicit_cli_consent():
    clients = [ClientSpec("stale", derived=DerivedState(fresh=False))]
    provider, session = make_provider(clients=clients,
                                      exports={"stale": b"canonical-A"})
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["stale"], allow_cli=False)
    assert excinfo.value.code == errors.E_REMOTE_EXPORT
    assert excinfo.value.detail == "cli-consent"
    assert session.menu_invoked is False
    assert session.downloads == []


def test_stale_derived_exports_with_consent_run_menu_then_download():
    clients = [ClientSpec("stale", derived=DerivedState(fresh=False))]
    provider, session = make_provider(clients=clients,
                                      exports={"stale": b"canonical-A"})
    data = provider.generate_exports(["stale"], allow_cli=True)
    assert data == {"stale": b"canonical-A"}
    assert session.menu_invoked is True
    assert any("HAUI_MENU_END" in command for command in session.commands)
    assert session.downloads == ["/root/sbox/clients/stale/mihomo.yaml"]


def test_menu_output_without_the_end_marker_is_refused():
    clients = [ClientSpec("stale", derived=DerivedState(fresh=False))]
    provider, _ = make_provider(clients=clients,
                                exports={"stale": b"canonical-A"},
                                menu_end_marker=False)
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["stale"], allow_cli=True)
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "no-end"


def test_menu_that_does_not_refresh_the_derived_file_is_refused():
    clients = [ClientSpec("stale", derived=DerivedState(fresh=False))]
    provider, _ = make_provider(clients=clients,
                                exports={"stale": b"canonical-A"},
                                menu_side_effect=False)
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["stale"], allow_cli=True)
    assert excinfo.value.code == errors.E_REMOTE_MENU
    assert excinfo.value.detail == "not-regenerated"


def test_download_sha256_mismatch_is_refused():
    clients = [ClientSpec("fresh", derived=DerivedState())]
    provider, session = make_provider(
        clients=clients, exports={"fresh": b"canonical-A"},
        hash_overrides={"fresh": "0" * 64})
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["fresh"], allow_cli=True)
    assert excinfo.value.code == errors.E_REMOTE_HASH
    assert excinfo.value.detail == "mismatch"
    # The bytes were downloaded and then refused; they were never handed on.
    assert session.downloads == ["/root/sbox/clients/fresh/mihomo.yaml"]


def test_missing_remote_derived_file_fails_before_download():
    clients = [ClientSpec("fresh", derived=DerivedState())]
    provider, session = make_provider(
        clients=clients, exports={"fresh": b"canonical-A"},
        missing_exports=("fresh",))
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports(["fresh"], allow_cli=True)
    assert excinfo.value.code == errors.E_REMOTE_HASH
    assert excinfo.value.detail == "sha256sum"
    assert session.downloads == []


def test_generate_exports_rejects_empty_or_unsafe_client_names():
    provider, _ = make_provider()
    with pytest.raises(HaUiError) as excinfo:
        provider.generate_exports([], allow_cli=True)
    assert excinfo.value.code == errors.E_USAGE
    assert excinfo.value.detail == "clients"
    for bad_name in ("../evil", "bad name", "a/b", ""):
        with pytest.raises(HaUiError) as excinfo:
            provider.read_exports([bad_name])
        assert excinfo.value.code == errors.E_USAGE
        assert excinfo.value.detail == "client-name"


def test_unknown_remote_command_fails_closed():
    """Drift guard: an unrecognised command never returns a scripted answer."""
    session = FakeSession("A")
    with pytest.raises(AssertionError):
        session.exec("rm -rf /root/sbox")
    with pytest.raises(AssertionError):
        session.download_file("/etc/passwd")
