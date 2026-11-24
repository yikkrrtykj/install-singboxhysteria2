"""P2 contract: ``ClientRecord.complete`` is protocol-only, ``exportable`` is
the gate for creation success and generation readiness.

The distinction matters because ``_build_records`` attaches *global* structural
anomalies (duplicate name, name-set mismatch, unnamed entries, inbound-count
drift) to every record. A client can therefore hold both credentials and still
be unusable; reporting it as "created" or "ready to generate" would be wrong.
"""

from __future__ import annotations

import pytest

from ha_ui.core import errors
from ha_ui.core.errors import HaUiError
from ha_ui.core.models import ClientRecord
from ha_ui.core.service import GenerationService
from tests import fakes


def record(*, reality: bool = True, hy2: bool = True,
           problems: tuple[str, ...] = ()) -> ClientRecord:
    return ClientRecord(name="alpha", reality_ok=reality, hy2_ok=hy2,
                        derived_export_present=False, problems=problems)


@pytest.mark.parametrize("reality,hy2,problems,complete,exportable", [
    (True, True, (), True, True),
    (True, False, (), False, False),
    (False, True, (), False, False),
    (False, False, (), False, False),
    (True, True, ("duplicate-name",), True, False),
    (True, True, ("name-set-mismatch",), True, False),
    (True, True, ("unnamed-reality", "duplicate-name"), True, False),
    (False, False, ("hy2-inbound-count",), False, False),
])
def test_complete_is_protocol_only_while_exportable_adds_structure(
        reality, hy2, problems, complete, exportable):
    current = record(reality=reality, hy2=hy2, problems=problems)
    assert current.complete is complete
    assert current.exportable is exportable
    # exportable can never be true when complete is false.
    assert not (current.exportable and not current.complete)


def test_derived_presence_does_not_change_semantics():
    base = fakes.client_record("alpha")
    assert base.exportable is True
    assert base.complete is True


def ready_providers():
    return {
        "A": fakes.FakeProvider(role="A"),
        "B": fakes.FakeProvider(role="B", pin=fakes.cert_pin(fakes.PIN_B)),
    }


def make_service(workspace, providers):
    factory = fakes.FakeProviderFactory(providers)
    return GenerationService(workspace, provider_factory=factory,
                             pipeline=fakes.PipelineSpy())


def test_service_refuses_to_repair_from_a_structurally_broken_existing_client(
        workspace_tmp):
    # Present on one side only, both protocols present, but a duplicate name
    # invalidates the inventory: it is NOT a valid repair base.
    providers = ready_providers()
    providers["A"].records["event-vmix01"] = fakes.client_record(
        "event-vmix01", problems=("duplicate-name",))
    service = make_service(workspace_tmp, providers)
    with pytest.raises(HaUiError) as excinfo:
        service.create_client(sessions={"A": object(), "B": object()},
                              name="event-vmix01", confirmed=True)
    assert excinfo.value.code == errors.E_CLIENT_INCOMPLETE
    assert excinfo.value.detail == "A"
    assert providers["B"].create_requests == []


def test_service_still_allows_repair_of_a_structurally_sound_existing_client(
        workspace_tmp):
    providers = ready_providers()
    providers["A"].records["event-vmix01"] = fakes.client_record("event-vmix01")
    service = make_service(workspace_tmp, providers)
    result = service.create_client(sessions={"A": object(), "B": object()},
                                   name="event-vmix01", confirmed=True,
                                   allow_partial_repair=True)
    assert result.side("A").status == "existing"
    assert result.side("B").status == "created"
    assert result.ok is True
    assert providers["A"].create_requests == []
