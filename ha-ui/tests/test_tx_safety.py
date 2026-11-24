"""Fourth-review regression contracts for the managed transaction (P0/P1).

These are the fast, hermetic halves of the review items; the real shell /
process-level halves run in ``ha-ui/ci/linux/tx_lab.py`` on Linux CI.
"""

from __future__ import annotations

import pytest

from ha_ui.core import errors, remote
from ha_ui.core.errors import HaUiError
from ha_ui.core.service import _pending_role_state
from tests import fakes

BASE = dict(absent=False, phases=("check", "backup", "replace"),
            notes=(), rc=1, finished=2, running=False, counts={})


def status(**kwargs) -> remote.TxStatus:
    values = dict(BASE)
    values.update(kwargs)
    return remote.TxStatus(tx_id="alpha-" + "a" * 32, **values)


# --------------------------------------------------------------------------- #
# P0-2: terminal is not "safe to release"
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("kwargs,outcome,safe", [
    (dict(rc=0, counts={"COMMIT": 1, "SUCCESS": 1}), "created", True),
    (dict(phases=("check", "replace", "rollback"),
          counts={"ROLLED_BACK": 1}), "rolled-back", True),
    (dict(phases=("check",), counts={"LOCK": 1}), "refused", True),
    (dict(phases=("check", "replace", "rollback"),
          counts={"ROLLBACK_FAILED": 1}), "rollback-manual", False),
    (dict(phases=("check", "replace", "rollback"),
          counts={"ROLLBACK_UNCONFIRMED": 1}), "rollback-manual", False),
    (dict(phases=("check", "replace", "rollback_manual"),
          counts={"ROLLED_BACK": 1}), "rollback-manual",
     False),
    (dict(rc=0, running=True, counts={"COMMIT": 1, "SUCCESS": 1}),
     "worker-alive", False),
    (dict(rc=0, damaged=True, counts={"COMMIT": 1, "SUCCESS": 1}),
     "damaged", False),
    (dict(rc=None, finished=2), "damaged", False),
    (dict(rc=0, counts={}), "unknown", False),
    (dict(rc=1, counts={"SUCCESS": 1}), "unknown", False),
    # A refusal sentence plus a rollback intent is contradictory evidence:
    # it stays unknown (blocked), never a clean release.
    (dict(rc=1, phases=("check",), counts={"LOCK": 1, "ROLLBACK_INTENT": 1}),
     "unknown", False),
])
def test_release_requires_a_proven_outcome(kwargs, outcome, safe):
    current = status(**kwargs)
    assert current.outcome == outcome
    assert current.release_safe is safe


# --------------------------------------------------------------------------- #
# P0-1: the read-only query must glob real directories, not quote the star
# --------------------------------------------------------------------------- #
def test_pending_command_leaves_the_glob_unquoted():
    command = remote._pending_tx_command("event-vmix01")
    assert '"/root/sbox/.ha-ui-tx"' in command or (
        "/root/sbox/.ha-ui-tx" in command)
    assert '"$root"/"$name"-*' in command
    # The previous defect: the whole path (including '*') was single-quoted.
    assert "'/root/sbox/.ha-ui-tx/event-vmix01-*'" not in command
    assert remote.TX_ROOT in command


def test_pending_overview_reports_every_record_and_the_claim():
    block = (
        "HAUI_TX_RECORDS_BEGIN\n"
        "HAUI_TX_RECORD_BEGIN\n"
        "HAUI_TX_ID=alpha-1\nHAUI_TX_RUNNING=0\n"
        "HAUI_TX_PHASES_BEGIN\ncheck\nreplace\nHAUI_TX_PHASES_END\n"
        "HAUI_TX_RESULT_BEGIN\nrc=0\nfinished=2\nHAUI_TX_RESULT_END\n"
        "HAUI_TX_COMMIT=1\nHAUI_TX_SUCCESS=1\n"
        "HAUI_TX_RECORD_END\n"
        "HAUI_TX_RECORD_BEGIN\n"
        "HAUI_TX_ID=alpha-2\nHAUI_TX_RUNNING=1\n"
        "HAUI_TX_PHASES_BEGIN\ncheck\nHAUI_TX_PHASES_END\n"
        "HAUI_TX_RESULT_BEGIN\nHAUI_TX_RESULT_END\n"
        "HAUI_TX_RECORD_END\n"
        "HAUI_TX_RECORDS_END\nHAUI_TX_RECORD_COUNT=2\n"
        "HAUI_TX_CLAIM=1\nHAUI_TX_CLAIM_TXID=alpha-3\n")
    overview = remote._parse_tx_overview(block)
    assert len(overview.records) == 2
    assert [record.outcome for record in overview.records] == [
        "created", "running"]
    assert overview.claim == "alpha-3"
    assert overview.unfinished is True  # claim without a matching record


def test_claim_without_record_is_blocked_not_absent():
    overview = remote.TxOverview(records=(), claim="alpha-x")
    assert _pending_role_state(overview, None) == "blocked"


def test_claim_with_record_is_not_treated_as_unfinished():
    record = status(rc=0, counts={"COMMIT": 1, "SUCCESS": 1})
    overview = remote.TxOverview(records=(record,), claim=record.tx_id)
    assert overview.unfinished is False


# --------------------------------------------------------------------------- #
# P0-2 (service): live state must agree with the terminal outcome
# --------------------------------------------------------------------------- #
def test_created_terminal_requires_an_exportable_live_record():
    record = status(rc=0, counts={"COMMIT": 1, "SUCCESS": 1})
    overview = remote.TxOverview(records=(record,), claim=None)
    assert _pending_role_state(overview, None) == "blocked"
    assert _pending_role_state(
        overview, fakes.client_record("alpha")) == "terminal-safe"
    assert _pending_role_state(
        overview, fakes.client_record("alpha", hy2=False)) == "blocked"


def test_rolled_back_terminal_requires_the_name_to_be_absent():
    record = status(phases=("check", "replace", "rollback"),
                    counts={"ROLLED_BACK": 1})
    overview = remote.TxOverview(records=(record,), claim=None)
    assert _pending_role_state(overview, None) == "terminal-safe"
    assert _pending_role_state(
        overview, fakes.client_record("alpha")) == "blocked"


def test_rollback_manual_never_releases():
    record = status(phases=("check", "replace", "rollback"),
                    counts={"ROLLBACK_FAILED": 1})
    overview = remote.TxOverview(records=(record,), claim=None)
    assert _pending_role_state(overview, None) == "blocked"


# --------------------------------------------------------------------------- #
# P0-3 / P1: worker and hook text contracts
# --------------------------------------------------------------------------- #
def test_worker_never_kills_the_menu():
    worker = remote._tx_worker_script(precommit=1)
    assert "kill -TERM" not in worker
    assert "precommit-stall" in worker
    assert "publish-failed" in worker
    assert "mv --" in worker


def test_journal_hook_checks_every_sync():
    text = remote._tx_env_text("alpha-" + "a" * 32)
    assert "if ! sync -f " in text
    assert "sync || return 1" in text
    assert "|| exit 1" in text  # load-time sentinel


# --------------------------------------------------------------------------- #
# P0-4: durable per-name guard text (behavioural proof runs in the Linux lab)
# --------------------------------------------------------------------------- #
def test_guard_blocks_unfinished_records_and_claims_atomically():
    guard = remote._tx_guard_script("alpha", "alpha-" + "a" * 32)
    assert "tx-in-flight" in guard
    assert 'mkdir -- "$claim"' in guard
    assert '! -f "$old/result"' in guard
    assert "find" in guard and "-mtime +1" in guard


def test_damaged_receipt_is_uncertain_in_the_create_path():
    provider = remote.RemoteProvider("A", fakes.FakeSession("A"))
    before = provider.snapshot()
    damaged = status(rc=0, damaged=True, counts={"COMMIT": 1, "SUCCESS": 1})
    with pytest.raises(HaUiError) as excinfo:
        provider._judge_tx(damaged, "alpha", before)
    assert excinfo.value.code == errors.E_CREATE_UNCERTAIN
    assert excinfo.value.detail == "tx-damaged"
