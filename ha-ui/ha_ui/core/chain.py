"""Local generation pipeline: HA-02 -> HA-03 -> HA-04 -> friendly export.

The pipeline only orchestrates the reviewed tools. Every delivery/check gate
stays inside those tools; this module adds:

* one unique, private run directory per attempt (a failure can never overwrite
  a previous successful delivery);
* staging of the downloaded canonical exports and the private pins file with
  real ACL verification;
* early, per-client validation using the batch/merge tool's own canonical
  parser and A/B credential-independence checks (HA-02 re-checks them);
* an explicit ``--check`` after HA-03 generation and after HA-04 generation;
* friendly A-first/B-first publication, SHA-256 verification and a non-secret
  run receipt;
* cancellation between stages and cleanup of a failed run directory so partial
  credential copies never linger (previous runs are untouched).
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Mapping

from . import errors, ha_tools, private_fs
from .errors import HaUiError
from .models import (
    CertPin,
    ClientRecord,
    DeliveredFile,
    GenerationResult,
    ProbePolicy,
    SelectedClient,
    StageOutcome,
)

CANCEL_CHECK = "cancel"
MAX_STAGED_EXPORT = 512 * 1024
CONFIG_VERSION_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
RUN_ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
FRIENDLY_FILE_RE = re.compile(
    r"\A([A-Za-z0-9][A-Za-z0-9._-]{0,31})-(A-first|B-first)\.yaml\Z")


@dataclass(frozen=True)
class RunPaths:
    run_id: str
    root: Path
    exports: Path
    ha02: Path
    ha03: Path
    ha04: Path
    download: Path
    inventory: Path
    pins: Path

    def export_path(self, vps: str, name: str) -> Path:
        return self.exports / vps / (name + "-mihomo.yaml")


def new_run_id(now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
    return "run-%s-%s" % (current.strftime("%Y%m%d-%H%M%S"),
                          secrets.token_hex(3))


def new_config_version(now: datetime | None = None) -> str:
    current = now or datetime.now(timezone.utc)
    version = "ha-ui-%s-r1" % current.strftime("%Y%m%d-%H%M%S")
    if not CONFIG_VERSION_RE.fullmatch(version):  # pragma: no cover - fixed shape
        raise HaUiError(errors.E_USAGE, detail="config-version")
    return version


def create_run_paths(workspace: Path, run_id: str,
                     policy: ProbePolicy) -> RunPaths:
    if not RUN_ID_RE.fullmatch(run_id or ""):
        raise HaUiError(errors.E_PATH, detail="run-id")
    root = private_fs.run_dir(workspace, run_id)
    exports = private_fs.ensure_private_dir(root / "exports", workspace)
    for vps in ("A", "B"):
        private_fs.ensure_private_dir(exports / vps, workspace)
    ha02 = private_fs.ensure_private_dir(root / "ha02", workspace)
    ha03 = private_fs.ensure_private_dir(root / "ha03", workspace)
    ha04 = private_fs.ensure_private_dir(
        root / ("ha04-i%d-t%d" % (policy.interval, policy.timeout)),
        workspace)
    download = private_fs.ensure_private_dir(root / "download", workspace)
    return RunPaths(run_id=run_id, root=root, exports=exports, ha02=ha02,
                    ha03=ha03, ha04=ha04, download=download,
                    inventory=root / "inventory.csv",
                    pins=root / "pins.json")


class _ParseFailure(Exception):
    pass


def _fail() -> _ParseFailure:
    return _ParseFailure()


def validate_client_records(
        records: Mapping[str, ClientRecord]) -> list[ClientRecord]:
    """Keep only complete, consistent clients and report the rest as broken."""
    return [record for record in records.values() if record.complete
            and not record.problems]


def validate_selection(
        selected: list[SelectedClient],
        records_a: Mapping[str, ClientRecord],
        records_b: Mapping[str, ClientRecord]) -> None:
    if not selected:
        raise HaUiError(errors.E_USAGE, detail="clients")
    folded: set[str] = set()
    for item in selected:
        if item.group not in ("A-first", "B-first"):
            raise HaUiError(errors.E_USAGE, detail="group")
        if item.name.casefold() in folded:
            raise HaUiError(errors.E_CONFIG, detail="duplicate-client")
        folded.add(item.name.casefold())
        for role, records in (("A", records_a), ("B", records_b)):
            record = records.get(item.name)
            if record is None:
                raise HaUiError(errors.E_CLIENT_MISSING, detail=role)
            if not record.complete or record.problems:
                raise HaUiError(errors.E_CLIENT_INCOMPLETE, detail=role)


def _write_inventory(paths: RunPaths, selected: list[SelectedClient]) -> None:
    rows = ["terminal,group"]
    for item in selected:
        rows.append("%s,%s" % (item.name, item.group))
    payload = ("\n".join(rows) + "\n").encode("utf-8")
    private_fs.secure_write_new(paths.inventory, payload)
    private_fs.verify_private_file(paths.inventory)


def _stage_exports(paths: RunPaths,
                   exports: Mapping[str, Mapping[str, bytes]],
                   selected: list[SelectedClient]) -> None:
    for item in selected:
        for vps in ("A", "B"):
            try:
                data = exports[vps][item.name]
            except KeyError:
                raise HaUiError(errors.E_CLIENT_MISSING, detail=vps) from None
            if not isinstance(data, bytes) or not data:
                raise HaUiError(errors.E_CLIENT_INCOMPLETE, detail=vps)
            if len(data) > MAX_STAGED_EXPORT or b"\x00" in data or b"\r" in data:
                raise HaUiError(errors.E_REMOTE_FILE, detail=vps)
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                raise HaUiError(errors.E_REMOTE_FILE, detail=vps) from None
            private_fs.secure_write_new(
                paths.export_path(vps, item.name), data)


def _validate_staged_exports(paths: RunPaths,
                             selected: list[SelectedClient]) -> None:
    merge = ha_tools.merge_tool()
    profiles: dict[str, dict[str, object]] = {"A": {}, "B": {}}
    for item in selected:
        for vps in ("A", "B"):
            path = paths.export_path(vps, item.name)
            try:
                profile = merge.parse_export(str(path), _fail)
                merge.check_provenance(str(path), item.name, _fail)
            except _ParseFailure:
                raise HaUiError(errors.E_CLIENT_INCOMPLETE,
                                detail=vps) from None
            profiles[vps][item.name] = profile
        try:
            merge.check_sources(profiles["A"][item.name],
                                profiles["B"][item.name])
        except merge.MergeError:
            raise HaUiError(errors.E_CLIENT_INCOMPLETE,
                            detail="source-collision") from None
        try:
            merge.check_credentials(profiles["A"][item.name],
                                    profiles["B"][item.name])
        except merge.MergeError:
            raise HaUiError(errors.E_CREDENTIAL_REUSE,
                            detail=item.name) from None


def _write_pins(paths: RunPaths, pins: Mapping[str, CertPin]) -> None:
    if set(pins) != {"A", "B"}:
        raise HaUiError(errors.E_PIN_FORMAT, detail="servers")
    document = {
        "schema": "mihomo-competition-ha-pins/2",
        "vps": {
            role: {
                "fingerprint_sha256": pins[role].fingerprint_sha256.lower(),
                "not_before": pins[role].not_before.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "not_after": pins[role].not_after.strftime(
                    "%Y-%m-%dT%H:%M:%SZ"),
                "source": pins[role].source,
            }
            for role in ("A", "B")
        },
    }
    payload = (json.dumps(document, ensure_ascii=False, indent=2,
                          sort_keys=True) + "\n").encode("utf-8")
    private_fs.secure_write_new(paths.pins, payload)
    # The reviewed pins parser performs the real schema/ACL/duplicate-key gate.
    try:
        ha_tools.profile_tool().parse_pins(str(paths.pins), 0, None)
    except Exception:
        raise HaUiError(errors.E_PIN_FORMAT, detail="pins") from None


def _stage_outcome(stage: str, ok: bool, code: str = "",
                   summary: str = "") -> StageOutcome:
    return StageOutcome(stage=stage, ok=ok, code=code, summary=summary)


def _run_stage(name: str, argv: list[str], stage: str, *,
               check: bool = False) -> tuple[StageOutcome, object]:
    result = ha_tools.run_tool(name, argv)
    if result.exit_code != 0:
        code = ha_tools.first_failure_code(result)
        raise HaUiError(errors.E_CHAIN_CHECK if check else errors.E_CHAIN_STAGE,
                        detail="%s:%s" % (stage, code))
    return _stage_outcome(stage, True, summary="ok"), result


def _append_stage(result: GenerationResult, name: str, argv: list[str],
                  stage: str, *, check: bool = False):
    outcome, tool = _run_stage(name, argv, stage, check=check)
    result.stages.append(outcome)
    return tool


def _verify_friendly_output(paths: RunPaths, item: SelectedClient,
                            stdout: str) -> DeliveredFile:
    expected = "%s-%s.yaml" % (item.name, item.group)
    filename = ""
    digest = ""
    for line in stdout.replace("\r", "").splitlines():
        if line.startswith("file: "):
            filename = line[len("file: "):].strip()
        elif line.startswith("sha256: "):
            digest = line[len("sha256: "):].strip()
    if filename != expected:
        raise HaUiError(errors.E_FRIENDLY_EXPORT, detail="filename")
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise HaUiError(errors.E_FRIENDLY_EXPORT, detail="digest")
    path = paths.download / expected
    if not path.is_file():
        raise HaUiError(errors.E_FRIENDLY_EXPORT, detail="missing")
    private_fs.verify_private_file(path)
    actual = private_fs.file_sha256(path)
    if actual != digest:
        raise HaUiError(errors.E_FRIENDLY_EXPORT, detail="sha256")
    if path.stat().st_size > MAX_STAGED_EXPORT:
        raise HaUiError(errors.E_FRIENDLY_EXPORT, detail="size")
    return DeliveredFile(client=item.name, group=item.group,
                         filename=expected, path=str(path), sha256=actual)


def _write_receipt(paths: RunPaths, result: GenerationResult,
                   config_version: str, policy: ProbePolicy,
                   selected: list[SelectedClient]) -> None:
    document = {
        "schema": "ha-ui/run/1",
        "run_id": result.run_id,
        "config_version": config_version,
        "policy": {"interval": policy.interval, "timeout": policy.timeout},
        "clients": [
            {"name": item.name, "group": item.group,
             "file": entry.filename, "sha256": entry.sha256}
            for item, entry in zip(selected, result.files)
        ],
        "stages": [
            {"stage": stage.stage, "ok": stage.ok, "code": stage.code}
            for stage in result.stages
        ],
        "tools": ha_tools.toolset_fingerprint(),
        "started_at": result.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "finished_at": (result.finished_at or datetime.now(timezone.utc))
        .strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload = (json.dumps(document, ensure_ascii=False, indent=2,
                          sort_keys=True) + "\n").encode("utf-8")
    private_fs.secure_write_new(paths.root / "run.json", payload)


class GenerationPipeline:
    """One immutable attempt: new private run directory, all-or-nothing outputs."""

    def __init__(self, workspace: Path) -> None:
        self.workspace = Path(workspace)

    def generate(self, *,
                 run_id: str,
                 config_version: str,
                 policy: ProbePolicy,
                 selected: list[SelectedClient],
                 exports: Mapping[str, Mapping[str, bytes]],
                 pins: Mapping[str, CertPin],
                 progress: Callable[[str], None] | None = None,
                 cancel: Callable[[], bool] | None = None,
                 cleanup_failed: bool = True) -> GenerationResult:
        report = progress or (lambda _stage: None)
        cancelled = cancel or (lambda: False)
        if not CONFIG_VERSION_RE.fullmatch(config_version or ""):
            raise HaUiError(errors.E_USAGE, detail="config-version")
        paths = create_run_paths(self.workspace, run_id, policy)
        result = GenerationResult(run_id=run_id)
        try:
            if cancelled():
                raise HaUiError(errors.E_CANCELLED)
            report("stage:validate")
            _write_inventory(paths, selected)
            _stage_exports(paths, exports, selected)
            _validate_staged_exports(paths, selected)
            _write_pins(paths, pins)

            report("stage:ha02")
            _append_stage(result, "batch",
                          ["--inventory", str(paths.inventory),
                           "--exports", str(paths.exports),
                           "--output-dir", str(paths.ha02),
                           "--config-version", config_version],
                          "ha02-generate")
            if cancelled():
                raise HaUiError(errors.E_CANCELLED)

            report("stage:ha03")
            ha03_version = config_version + "-c"
            _append_stage(result, "profile",
                          ["--delivery", str(paths.ha02),
                           "--pins", str(paths.pins),
                           "--output-dir", str(paths.ha03),
                           "--config-version", ha03_version,
                           "--min-validity-days", "1"],
                          "ha03-generate")
            _append_stage(result, "profile",
                          ["--delivery", str(paths.ha03),
                           "--source-delivery", str(paths.ha02),
                           "--pins", str(paths.pins),
                           "--check"],
                          "ha03-check", check=True)
            if cancelled():
                raise HaUiError(errors.E_CANCELLED)

            report("stage:ha04")
            ha04_version = config_version + "-h4"
            _append_stage(result, "fastprobe",
                          ["--delivery", str(paths.ha03),
                           "--ha02-delivery", str(paths.ha02),
                           "--pins", str(paths.pins),
                           "--output-dir", str(paths.ha04),
                           "--config-version", ha04_version,
                           "--interval", str(policy.interval),
                           "--timeout", str(policy.timeout)],
                          "ha04-generate")
            _append_stage(result, "fastprobe",
                          ["--check",
                           "--delivery", str(paths.ha04),
                           "--source-delivery", str(paths.ha03),
                           "--ha02-delivery", str(paths.ha02),
                           "--pins", str(paths.pins)],
                          "ha04-check", check=True)
            if cancelled():
                raise HaUiError(errors.E_CANCELLED)

            report("stage:friendly")
            for item in selected:
                if cancelled():
                    raise HaUiError(errors.E_CANCELLED)
                tool = _append_stage(
                    result, "friendly",
                    ["--ha04", str(paths.ha04),
                     "--ha03", str(paths.ha03),
                     "--ha02", str(paths.ha02),
                     "--pins", str(paths.pins),
                     "--terminal", item.name,
                     "--group", item.group,
                     "--output-dir", str(paths.download)],
                    "friendly-%s" % item.name)
                result.files.append(
                    _verify_friendly_output(paths, item, tool.stdout))
            if len(result.files) != len(selected):
                raise HaUiError(errors.E_FRIENDLY_EXPORT, detail="count")
            result.finished_at = datetime.now(timezone.utc)
            _write_receipt(paths, result, config_version, policy, selected)
            return result
        except HaUiError as error:
            result.failed_stage = _stage_outcome(
                "failed", False, code=error.code, summary=error.detail or "")
            if cleanup_failed:
                try:
                    private_fs.delete_tree_under(self.workspace, paths.root)
                except HaUiError:
                    pass
            raise
        except Exception:
            result.failed_stage = _stage_outcome("failed", False,
                                                 code=errors.E_INTERNAL)
            if cleanup_failed:
                try:
                    private_fs.delete_tree_under(self.workspace, paths.root)
                except HaUiError:
                    pass
            raise HaUiError(errors.E_INTERNAL) from None


def discard_failed_run(workspace: Path, run_id: str) -> None:
    """Remove a failed attempt's staging directory (never a successful one)."""
    if not RUN_ID_RE.fullmatch(run_id or ""):
        raise HaUiError(errors.E_PATH, detail="run-id")
    target = Path(workspace) / "runs" / run_id
    private_fs.delete_tree_under(workspace, target)
