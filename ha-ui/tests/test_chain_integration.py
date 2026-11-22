"""End-to-end hermetic test of the real local HA chain on synthetic exports.

This is the issue-#110 integration gate: the reviewed HA-02 -> HA-03 -> HA-04
-> friendly-export modules are executed unchanged by ``GenerationPipeline`` on
Windows against two synthetic canonical A/B exports.  No VPS, no network, no
real credentials: the delivery is built from the same canonical template the
``.scratch/chain_smoke.py`` reference used, and the receipt/artifacts are
checked byte-for-byte.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from ha_ui.core import ha_tools
from ha_ui.core.chain import GenerationPipeline
from ha_ui.core.models import ProbePolicy
from tests import fakes

CONFIG_VERSION = "itest-20261121-r1"
RUN_ID = "itest-run-1"
RUN_ID_2 = "itest-run-2"
CONFIG_VERSION_2 = "itest-20261121-r2"
POLICY = ProbePolicy(5, 2000)
HA04_DIR = "ha04-i%d-t%d" % (POLICY.interval, POLICY.timeout)
SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
EXPECTED_STAGES = [
    "ha02-generate",
    "ha03-generate",
    "ha03-check",
    "ha04-generate",
    "ha04-check",
]


@pytest.fixture(scope="module")
def chain():
    with fakes.workspace_environment("chain") as workspace:
        batch = fakes.synthetic_batch()
        result = GenerationPipeline(workspace).generate(
            run_id=RUN_ID,
            config_version=CONFIG_VERSION,
            policy=POLICY,
            selected=batch.selected,
            exports=batch.exports,
            pins=batch.run_pins(),
        )
        run = fakes.ChainRun(
            workspace=workspace,
            batch=batch,
            result=result,
            run_id=RUN_ID,
            artifacts=fakes.snapshot_files(workspace / "runs" / RUN_ID),
        )
        yield run


@pytest.fixture(scope="module")
def second_run(chain):
    before = fakes.snapshot_files(chain.run_root)
    result = GenerationPipeline(chain.workspace).generate(
        run_id=RUN_ID_2,
        config_version=CONFIG_VERSION_2,
        policy=POLICY,
        selected=chain.batch.selected,
        exports=chain.batch.exports,
        pins=chain.batch.run_pins(),
    )
    return result, before


# --------------------------------------------------------------------------- #
# Delivered files.
# --------------------------------------------------------------------------- #
def test_pipeline_publishes_the_expected_delivery_files(chain):
    assert chain.result.ok is True
    assert len(chain.result.files) == 2
    assert [entry.filename for entry in chain.result.files] == (
        chain.batch.expected_filenames())
    # Both groups are represented (mixed A-first / B-first batch).
    assert [entry.group for entry in chain.result.files] == [
        item.group for item in chain.batch.selected]
    assert {entry.group for entry in chain.result.files} == {
        "A-first", "B-first"}

    download = chain.run_root / "download"
    for entry in chain.result.files:
        path = Path(entry.path)
        assert path == download / entry.filename
        assert path.is_file()
        assert path.stat().st_size > 0
        assert SHA256_RE.match(entry.sha256)
        assert entry.sha256 == fakes.file_sha256(path)
    # Nothing else was published to the delivery directory.
    assert sorted(path.name for path in download.iterdir()) == sorted(
        chain.batch.expected_filenames())


# --------------------------------------------------------------------------- #
# The run receipt must stay metadata-only.
# --------------------------------------------------------------------------- #
def test_run_receipt_is_metadata_only_and_secret_free(chain):
    receipt_path = chain.run_root / "run.json"
    assert receipt_path.is_file()
    raw = receipt_path.read_bytes()
    document = json.loads(raw.decode("utf-8"))

    assert document["schema"] == "ha-ui/run/1"
    assert document["run_id"] == RUN_ID
    assert document["config_version"] == CONFIG_VERSION
    assert document["policy"] == {"interval": POLICY.interval,
                                  "timeout": POLICY.timeout}
    assert [(entry["name"], entry["group"], entry["file"])
            for entry in document["clients"]] == [
                (item.name, item.group, "%s-%s.yaml" % (item.name,
                                                        item.group))
                for item in chain.batch.selected]
    assert [entry["sha256"] for entry in document["clients"]] == [
        entry.sha256 for entry in chain.result.files]
    assert [entry["stage"] for entry in document["stages"]] == (
        EXPECTED_STAGES + ["friendly-%s" % item.name
                           for item in chain.batch.selected])
    assert all(entry["ok"] is True for entry in document["stages"])
    assert set(document["tools"]) == {
        "batch", "merge", "profile", "fastprobe", "friendly"}
    assert all(SHA256_RE.match(digest)
               for digest in document["tools"].values())

    # No UUID, password or VPS address sentinel may appear in the receipt.
    for sentinel in chain.batch.sentinels:
        assert sentinel.encode("utf-8") not in raw, sentinel
    for address in (fakes.SERVER_A, fakes.SERVER_B):
        assert address.encode("utf-8") not in raw, address


# --------------------------------------------------------------------------- #
# Intermediate reviewed-tool artifacts and their manifests.
# --------------------------------------------------------------------------- #
def test_intermediate_manifests_exist_and_parse_via_reviewed_tools(chain):
    run = chain.run_root
    delivery_manifest = run / "ha02" / (
        "ha-delivery-%s.json" % CONFIG_VERSION)
    competition_manifest = run / "ha03" / (
        "ha-competition-%s-c.json" % CONFIG_VERSION)
    variant_dir = run / HA04_DIR
    variant_manifest = variant_dir / (
        "ha4-fastprobe-%s-h4-i5-t2000.json" % CONFIG_VERSION)
    for path in (delivery_manifest, competition_manifest,
                 variant_manifest):
        assert path.is_file(), path

    delivery = json.loads(delivery_manifest.read_text(encoding="utf-8"))
    assert delivery["schema"] == "mihomo-competition-ha-batch/1"
    assert delivery["terminal_count"] == 2
    assert [entry["name"] for entry in delivery["terminals"]] == [
        item.name for item in chain.batch.selected]

    competition = json.loads(
        competition_manifest.read_text(encoding="utf-8"))
    assert competition["schema"] == "mihomo-competition-ha-profile/2"
    assert competition["pins"]["A"]["fingerprint_sha256"] == fakes.PIN_A
    assert competition["pins"]["B"]["fingerprint_sha256"] == fakes.PIN_B

    variant = json.loads(variant_manifest.read_text(encoding="utf-8"))
    assert variant["schema"] == "mihomo-competition-ha4-fastprobe/1"
    assert variant["policy"]["interval"] == POLICY.interval
    assert variant["policy"]["timeout"] == POLICY.timeout
    assert variant["terminal_count"] == 2

    # Parse the HA-04 delivery with the reviewed fast-probe module itself.
    fastprobe = ha_tools.fastprobe_tool()
    doc, manifest_name, entries, names = fastprobe.load_variant_delivery(
        str(variant_dir))
    assert manifest_name == variant_manifest.name
    assert doc["schema"] == "mihomo-competition-ha4-fastprobe/1"
    assert [entry["name"] for entry in entries] == [
        item.name for item in chain.batch.selected]
    assert {entry["output"] for entry in entries} == {
        "%s-ha4f.yaml" % item.name for item in chain.batch.selected}
    assert fastprobe.validate_manifest_entries(
        entries, ha_tools.merge_tool()) == entries
    assert "-ha4f.yaml" in " ".join(names)


# --------------------------------------------------------------------------- #
# The delivered profile is the 4-node dual-VPS merge, not a raw export.
# --------------------------------------------------------------------------- #
def test_delivered_profile_is_the_four_node_dual_vps_merge(chain):
    expected_nodes = ["Reality", "Hysteria2", "Backup-Reality",
                      "Backup-Hysteria2"]
    for entry, item in zip(chain.result.files, chain.batch.selected):
        delivered = Path(entry.path).read_bytes()
        # It cannot be either raw single-VPS export.
        assert delivered != chain.batch.exports["A"][item.name]
        assert delivered != chain.batch.exports["B"][item.name]
        text = delivered.decode("utf-8")
        proxy_region = text.split("proxies:", 1)[1].split(
            "proxy-groups:", 1)[0]
        node_names = [
            line[len("  - name: "):]
            for line in proxy_region.splitlines()
            if line.startswith("  - name: ")
        ]
        assert node_names == expected_nodes
        # Primary VPS is the group's VPS, backup is the other one, in order.
        primary, backup = ((fakes.SERVER_A, fakes.SERVER_B)
                           if item.group == "A-first"
                           else (fakes.SERVER_B, fakes.SERVER_A))
        assert text.index(primary) < text.index(backup)
        # The delivered bytes are exactly the trusted HA-04 variant file.
        variant = chain.run_root / HA04_DIR / ("%s-ha4f.yaml" % item.name)
        assert delivered == variant.read_bytes()


# --------------------------------------------------------------------------- #
# HA-04 pins both HY2 certificates instead of skipping verification.
# --------------------------------------------------------------------------- #
def test_ha04_variants_pin_both_hy2_certificates(chain):
    for item in chain.batch.selected:
        path = chain.run_root / HA04_DIR / ("%s-ha4f.yaml" % item.name)
        text = path.read_text(encoding="utf-8")
        assert text.count("type: hysteria2") == 2
        # Both HY2 nodes are certificate-pinned; the renderer's
        # skip-cert-verify: true must have been replaced.
        assert text.count("skip-cert-verify: false") == 2
        assert "skip-cert-verify: true" not in text
        fingerprints = [
            line.strip()[len("fingerprint: "):]
            for line in text.splitlines()
            if line.strip().startswith("fingerprint: ")
        ]
        expected = ([fakes.PIN_A, fakes.PIN_B] if item.group == "A-first"
                    else [fakes.PIN_B, fakes.PIN_A])
        assert fingerprints == expected


# --------------------------------------------------------------------------- #
# No-clobber: a second run must not disturb the first successful delivery.
# --------------------------------------------------------------------------- #
def test_second_run_is_isolated_and_leaves_the_first_untouched(chain,
                                                               second_run):
    result, before = second_run
    assert result.ok is True
    assert result.run_id == RUN_ID_2
    assert [entry.filename for entry in result.files] == (
        chain.batch.expected_filenames())
    second_root = chain.workspace / "runs" / RUN_ID_2
    assert second_root.is_dir()
    assert (second_root / "run.json").is_file()

    # The second attempt wrote to its own run directory only.
    assert Path(result.files[0].path).parent == second_root / "download"
    assert Path(chain.result.files[0].path).parent == (
        chain.run_root / "download")

    # Every first-run artifact (deliveries, manifests, pins, receipt) is
    # byte-identical and still present.
    assert before
    for path, digest in before.items():
        assert path.is_file(), "previous artifact disappeared: %s" % path
        assert fakes.file_sha256(path) == digest, (
            "previous artifact was modified: %s" % path)
    for entry in chain.result.files:
        assert fakes.file_sha256(entry.path) == entry.sha256


# The GUI's default must pass through the real reviewed HA chain, not only
# update its dropdown label. Explicit legacy i5/t2000 runs above are preserved.
def test_default_probe_policy_produces_verified_i5_t5000_yaml():
    policy = ProbePolicy()
    assert policy == ProbePolicy(5, 5000)
    with fakes.workspace_environment("default-probe-policy") as workspace:
        batch = fakes.synthetic_batch()
        result = GenerationPipeline(workspace).generate(
            run_id="default-probe-i5-t5000",
            config_version="itest-default-i5-t5000",
            policy=policy,
            selected=batch.selected,
            exports=batch.exports,
            pins=batch.run_pins(),
        )
        assert result.ok is True
        assert all(stage.ok for stage in result.stages)
        assert [stage.stage for stage in result.stages] == (
            EXPECTED_STAGES + ["friendly-%s" % item.name
                               for item in batch.selected])
        root = workspace / "runs" / result.run_id
        receipt = json.loads((root / "run.json").read_text(encoding="utf-8"))
        assert receipt["policy"] == {"interval": 5, "timeout": 5000}
        variant_dir = root / "ha04-i5-t5000"
        assert variant_dir.is_dir()
        manifests = list(variant_dir.glob("ha4-fastprobe-*-i5-t5000.json"))
        assert len(manifests) == 1
        manifest = json.loads(manifests[0].read_text(encoding="utf-8"))
        assert manifest["policy"] == {"interval": 5, "timeout": 5000}
        for entry in result.files:
            yaml = Path(entry.path).read_text(encoding="utf-8")
            assert "    interval: 5\n    timeout: 5000\n" in yaml
            assert yaml.count("skip-cert-verify: false") == 2
            assert "skip-cert-verify: true" not in yaml
