"""Behavioural gates for the re-frozen three-table contract.

All acceptance fixtures use the actual atomic store primitive or ingest
plane; no independently locked check/write harness substitutes for it.
Linux filesystem authority and real nginx validation have separate gates.
"""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
from unittest.mock import patch

import server_groups as h
from web import remote_store as rs
from web.remote_ingest import IngestRateLimiter, TokenBucket


def send(plane, sample):
    raw = h.pl.encode_sample(sample)
    now = int(plane.clock())
    headers = {h.HEADER_PROBE_ID: sample["probe_id"], h.HEADER_RUN: sample["run"],
               h.HEADER_SEQ: str(sample["seq"]), h.HEADER_SENT_EPOCH: str(now),
               h.HEADER_SIGNATURE: h.pl.sign(h.KEY, sample["probe_id"], now,
                                           sample["run"], sample["seq"], raw)}
    return plane.handle(raw, headers)


def accept(store, seq=1, run=h.RUN, probe=h.PROBE, epoch=None, now=None):
    epoch = h.NOW + seq if epoch is None else epoch
    raw = h.pl.encode_sample(h._sample(seq, probe, run, epoch))
    return store.accept(probe, run, seq, epoch, raw, store.clock() if now is None else now)


def refused(call, error):
    try:
        call()
    except error:
        return True
    return False


def group_store():
    out = {}
    root = h.temp_dir()
    store = rs.RemoteStore(root, clock=lambda: h.NOW).open()
    try:
        tables = {row[0] for row in store._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        out["exact_three_table_v1"] = tables == rs.EXPECTED_TABLES and store._conn.execute(
            "PRAGMA user_version").fetchone()[0] == 1
        out["path_is_physically_independent"] = store.db_path == os.path.join(
            root, "remote-probes", "remote-probes.sqlite3") and os.path.isfile(store.db_path)
        out["delete_full_foreign_keys_busy_timeout"] = (
            store._conn.execute("PRAGMA journal_mode").fetchone()[0] == "delete"
            and store._conn.execute("PRAGMA synchronous").fetchone()[0] == 2
            and store._conn.execute("PRAGMA foreign_keys").fetchone()[0] == 1
            and store._conn.execute("PRAGMA busy_timeout").fetchone()[0] == 5000)
        raw = h.pl.encode_sample(h._sample(1))
        first = accept(store)
        duplicate = accept(store)
        changed = dict(h._sample(1), dns=h._slot(9))
        conflict = store.accept(h.PROBE, h.RUN, 1, h.NOW+1, h.pl.encode_sample(changed))
        out["retained_duplicate_and_equivocation"] = (first, duplicate, conflict) == (
            "accepted", "duplicate", "equivocation") and store.status()["sample_count"] == 1
        receipt = store._conn.execute("SELECT body_hash,accepted_epoch FROM remote_probe_receipts").fetchone()
        out["receipt_is_original_32_byte_digest"] = receipt == (hashlib.sha256(raw).digest(), h.NOW)
        out["independent_exact_byte_charges"] = (
            store.status()["sample_bytes"] == len(raw)+256
            and store.status()["receipt_bytes"] == 256 and store.status()["run_bytes"] == 1024)
        store.close()
        store = rs.RemoteStore(root, clock=lambda: h.NOW).open()
        out["restart_preserves_receipt_authority"] = accept(store) == "duplicate"
        store.close()
        # Every malformed shape must be rejected without adoption or mutation.
        for case in ("draft_two_tables", "empty_v1", "newer", "foreign", "missing_constraint",
                     "orphan_receipt", "hash_mismatch", "missing_highwater_receipt"):
            case_root = os.path.join(root, case)
            fixture = rs.RemoteStore(case_root, clock=lambda: h.NOW).open()
            accept(fixture)
            fixture.close()
            conn = sqlite3.connect(fixture.db_path)
            if case == "draft_two_tables":
                for table in rs.EXPECTED_TABLES:
                    conn.execute("DROP TABLE "+table)
                conn.execute("CREATE TABLE remote_probe_samples (probe_id TEXT NOT NULL,run TEXT NOT NULL,"
                    "seq INTEGER NOT NULL,sample_epoch REAL NOT NULL,received_epoch REAL NOT NULL,"
                    "body_hash TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(probe_id,run,seq))")
                conn.execute("CREATE INDEX remote_probe_samples_age ON remote_probe_samples(probe_id,sample_epoch)")
                conn.execute("CREATE TABLE remote_probe_runs (probe_id TEXT NOT NULL,run TEXT NOT NULL,"
                    "max_seq INTEGER NOT NULL,max_sample_epoch REAL NOT NULL,created_epoch REAL NOT NULL,"
                    "last_activity_epoch REAL NOT NULL,PRIMARY KEY(probe_id,run))")
                conn.execute("INSERT INTO remote_probe_runs VALUES(?,?,?,?,?,?)",(h.PROBE,h.RUN,1,h.NOW+1,h.NOW,h.NOW))
                conn.execute("INSERT INTO remote_probe_samples VALUES(?,?,?,?,?,?,?)",
                    (h.PROBE,h.RUN,1,h.NOW+1,h.NOW,hashlib.sha256(raw).hexdigest(),raw))
            elif case == "empty_v1":
                for table in rs.EXPECTED_TABLES:
                    conn.execute("DROP TABLE " + table)
            elif case == "newer":
                conn.execute("PRAGMA user_version=2")
            elif case == "foreign":
                conn.execute("CREATE TABLE extra(x)")
            elif case == "missing_constraint":
                conn.execute("ALTER TABLE remote_probe_receipts RENAME TO old_receipts")
                conn.execute("CREATE TABLE remote_probe_receipts AS SELECT * FROM old_receipts")
                conn.execute("DROP TABLE old_receipts")
            elif case == "orphan_receipt":
                conn.execute("DELETE FROM remote_probe_runs")
            elif case == "hash_mismatch":
                conn.execute("UPDATE remote_probe_receipts SET body_hash=?", (b'z'*32,))
            else:
                conn.execute("UPDATE remote_probe_runs SET max_seq=2")
            conn.commit()
            conn.close()
            before = open(fixture.db_path, "rb").read()
            out[case+"_fails_closed_without_mutation"] = refused(
                lambda: rs.RemoteStore(case_root, clock=lambda: h.NOW).open(), rs.RemoteStoreError
            ) and open(fixture.db_path, "rb").read() == before
    finally:
        store.close()
        h.clean(root)
    return out


def group_retention():
    out = {}
    root = h.temp_dir()
    clock = [h.NOW]
    plane, cfg, kd = h.make_plane(root, clock=lambda: clock[0])
    store = plane.store
    try:
        out["frozen_three_independent_budgets"] = (
            rs.SOFT_BUDGET_BYTES == 16*1024*1024 and rs.HARD_BUDGET_BYTES == 24*1024*1024
            and rs.RECEIPT_BUDGET_BYTES == 256*1024*1024 and rs.RUN_BUDGET_BYTES == 4*1024*1024
            and rs.DB_BUDGET_BYTES == 320*1024*1024 and rs.WORKING_BUDGET_BYTES == 1024*1024*1024)
        near = h._sample(1, epoch=h.NOW-7*86400-1)
        result = send(plane, near)
        out["ingest_immediately_ages_near_horizon_evidence"] = (
            result[1] == {"v": 1, "result": "accepted"} and store.status()["sample_count"] == 0
            and store.status()["receipt_count"] == 1)
        out["aged_evidence_receipt_duplicate"] = send(plane, near)[1] == {"v": 1, "result": "duplicate"}
        changed = dict(near, dns=h._slot(19))
        out["aged_evidence_receipt_equivocation"] = send(plane, changed)[1] == {"error": "equivocation"}
        fresh = h._sample(3)
        send(plane, fresh)
        out["seq_gap_not_duplicate_with_evidence"] = send(plane, h._sample(2))[1] == {
            "error": "sequence_not_increasing"}
        clock[0] += 8*86400
        before = store._conn.execute("SELECT COUNT(*) FROM remote_probe_samples").fetchone()[0]
        read = plane.read_samples(clock[0]-7*86400, clock[0])
        out["idle_read_triggers_age_retention"] = before == 1 and read == [] and store.status()["sample_count"] == 0
        out["replay_older_than_new_sample_window_is_duplicate"] = send(plane, fresh)[1] == {
            "v": 1, "result": "duplicate"}
        out["old_receipt_changed_hash_is_equivocation"] = send(plane, dict(fresh, dns=h._slot(10)))[1] == {
            "error": "equivocation"}
        # Original never-accepted seq 2 is a sequence error even when its
        # original timestamp is now outside the new-sample age window.
        out["seq_gap_not_duplicate_after_deletion"] = send(plane, h._sample(2))[1] == {
            "error": "sequence_not_increasing"}
        out["receipts_are_not_read_evidence"] = store.status()["receipt_count"] == 2 and read == []
        # Startup enforcement: old evidence is still on disk before opening.
        clock[0] = h.NOW
        fresh4 = h._sample(4, epoch=h.NOW+4)
        send(plane, fresh4)
        store.close()
        clock[0] = h.NOW+8*86400
        store = rs.RemoteStore(os.path.join(root, "state"), clock=lambda: clock[0]).open()
        plane.store = store
        out["startup_retention_keeps_receipts"] = store.status()["sample_count"] == 0 and store.status()["receipt_count"] == 3
        # Drive scaled logical sample pressure through authenticated ingest.
        store.hard_budget, store.soft_budget, store.prune_batch = 3500, 1800, 1
        for seq in range(5, 15):
            send(plane, h._sample(seq, epoch=clock[0]-60+seq))
        rows = plane.read_samples(clock[0]-100, clock[0]+100)
        status = store.status()
        survivor_seq = [row["sample"]["seq"] for row in rows]
        out["production_ingest_budget_prunes_oldest_only"] = (
            status["budget_pruned"] and status["sample_bytes"] <= store.hard_budget
            and survivor_seq == list(range(min(survivor_seq),15)) and min(survivor_seq)>5)
        out["sample_budget_preserves_all_receipts_and_run"] = status["receipt_count"] == 13 and status["run_count"] == 1
        pruned_sample = h._sample(5, epoch=clock[0]-55)
        out["budget_deleted_sample_duplicate"] = send(plane, pruned_sample)[1] == {"v": 1, "result": "duplicate"}
        out["budget_deleted_sample_equivocation"] = send(plane, dict(pruned_sample,dns=h._slot(11)))[1] == {"error": "equivocation"}
        out["retained_since_and_closed_status"] = (
            set(status) == set(rs.STATUS_KEYS) and status["retained_since_epoch"] == rows[0]["sample"]["sample_epoch"]
            and status["sample_count"] == len(rows) and status["budget_pruned_total"] > 0)
        out["budget_shortening_is_remote_degradation"] = plane.status()["subcode"] == "remote_budget_pruned"
        # Reopening resets explanatory flags, never the durable horizon.
        oldest = status["retained_since_epoch"]
        store.close()
        store = rs.RemoteStore(os.path.join(root,"state"),clock=lambda:clock[0]).open()
        plane.store = store
        out["restart_keeps_durable_retained_since"] = store.status()["retained_since_epoch"] == oldest
        # Status alone must age out evidence, without direct retention calls.
        clock[0] += 8*86400
        out["idle_status_triggers_retention_and_silence"] = (
            plane.status()["subcode"] == "probe_not_reporting" and store.status()["sample_count"] == 0)
    finally:
        plane.close()
        h.clean(root)
        h.clean(os.path.dirname(cfg))
    return out


def group_continuity():
    out = {}
    root = h.temp_dir()
    clock = [h.NOW]
    store = rs.RemoteStore(root, clock=lambda:clock[0]).open()
    try:
        accept(store)
        original = store.receipt_hash(h.PROBE,h.RUN,1)
        clock[0] += 29*86400
        accept(store, now=clock[0])
        refreshed = store.run_state(h.PROBE,h.RUN)["last_activity_epoch"]
        clock[0] += 2*86400
        out["receipt_not_expired_by_own_acceptance_time"] = store.receipt_hash(h.PROBE,h.RUN,1) == original
        clock[0] = refreshed+rs.RUN_LIFETIME_SECONDS
        out["run_alive_at_exact_expiry_boundary"] = store.run_state(h.PROBE,h.RUN) is not None
        clock[0] += 1
        out["run_receipts_expire_together_after_boundary"] = (
            store.status()["run_count"] == 0 and store.status()["receipt_count"] == 0)
        clock[0] = h.NOW
        accept(store)
        clock[0] += 10
        accept(store)
        clock[0] -= 20
        accept(store)
        out["activity_never_regresses_on_clock_rollback"] = store.run_state(h.PROBE,h.RUN)["last_activity_epoch"] == h.NOW+10
        clock[0] = h.NOW+15
        altered = h.pl.encode_sample(dict(h._sample(1),dns=h._slot(17)))
        store.accept(h.PROBE,h.RUN,1,h.NOW+1,altered)
        accept(store,seq=2,epoch=h.NOW)
        out["equivocation_and_invalid_progression_do_not_refresh"] = store.run_state(h.PROBE,h.RUN)["last_activity_epoch"] == h.NOW+10
        store.max_receipts_per_probe = 1
        out["capacity_retry_is_closed"] = refused(lambda: accept(store,seq=2),rs.ReceiptCapacityError)
        out["valid_capacity_retry_refreshes_existing_run"] = store.run_state(h.PROBE,h.RUN)["last_activity_epoch"] == h.NOW+15
        store.close()
        store = rs.RemoteStore(root,clock=lambda:clock[0]).open()
        out["activity_and_receipt_are_durable"] = store.receipt_hash(h.PROBE,h.RUN,1) == original and store.run_state(h.PROBE,h.RUN)["last_activity_epoch"] == h.NOW+15
    finally:
        store.close()
        h.clean(root)
    return out


def group_capacity():
    out = {}
    root = h.temp_dir()
    clock = [h.NOW]
    plane,cfg,kd = h.make_plane(root,clock=lambda:clock[0])
    store = plane.store
    try:
        send(plane,h._sample(1))
        for name, attr, value, code in (
                ("per_probe_runs","max_runs_per_probe",1,"remote_run_capacity"),
                ("global_runs","max_runs_global",1,"remote_run_capacity"),
                ("run_bytes","run_budget",1024,"remote_run_capacity"),
                ("per_probe_receipts","max_receipts_per_probe",1,"remote_receipt_capacity"),
                ("global_receipts","max_receipts_global",1,"remote_receipt_capacity"),
                ("receipt_bytes","receipt_budget",256,"remote_receipt_capacity"),
                ("db_bytes","db_budget",1,"remote_storage_capacity"),
                ("working_bytes","working_budget",1,"remote_storage_capacity")):
            previous = getattr(store,attr)
            setattr(store,attr,value)
            before = tuple(store._conn.execute("SELECT COUNT(*) FROM "+table).fetchone()[0]
                           for table in (rs.TABLE_RUNS,rs.TABLE_RECEIPTS,rs.TABLE_SAMPLES))
            newrun = "f"*32 if code == "remote_run_capacity" else h.RUN
            result = send(plane,h._sample(2,run=newrun))
            after = tuple(store._conn.execute("SELECT COUNT(*) FROM "+table).fetchone()[0]
                          for table in (rs.TABLE_RUNS,rs.TABLE_RECEIPTS,rs.TABLE_SAMPLES))
            out[name+"_rejects_without_partial_admission"] = result[0] == 503 and result[1] == {"error":code} and before == after
            out[name+"_retains_duplicate_verdict"] = send(plane,h._sample(1))[1] == {"v":1,"result":"duplicate"}
            out[name+"_retains_equivocation_verdict"] = send(plane,dict(h._sample(1),dns=h._slot(15)))[1] == {"error":"equivocation"}
            out[name+"_visible_remote_only"] = plane.status()["probes"][h.PROBE]["status"] == "degraded"
            setattr(store,attr,previous)
            out[name+"_automatically_recovers"] = plane.status()["suspended_probes"] == []
        # Retired registry mapping still consumes live continuity capacity.
        plane.registry.entries.clear()
        store.max_receipts_global = 1
        out["retired_mapping_continuity_still_counts"] = (
            store.status()["receipt_count"] == 1 and store.status()["capacity_code"] == "remote_receipt_capacity"
            and plane.read_samples(h.NOW,h.NOW+10)[0]["mapping_retired"])
        clock[0] = h.NOW+rs.RUN_LIFETIME_SECONDS+1
        out["capacity_recovers_only_after_legal_expiry"] = store.status()["capacity_code"] is None and store.status()["receipt_count"] == 0
        # Actual page allocation ceiling, not merely a mocked capacity code.
        store.db_budget = 64*1024
        store.max_receipts_global = rs.MAX_RECEIPTS_GLOBAL
        store._set_page_ceiling()
        accepted = 0
        failure = False
        for seq in range(1,100):
            try:
                verdict = accept(store,seq=seq,epoch=clock[0]+seq)
                accepted += verdict == "accepted"
            except rs.StorageCapacityError:
                failure = True
                break
        out["sqlite_actual_page_growth_rolls_back_at_ceiling"] = (
            failure and store.status()["receipt_count"] == accepted
            and store.status()["sample_count"] == accepted
            and os.path.getsize(store.db_path) <= store.db_budget
            and (store.run_state(h.PROBE,h.RUN) is None or store.run_state(h.PROBE,h.RUN)["max_seq"] == accepted))
        out["frozen_run_and_receipt_count_limits"] = (
            rs.MAX_RUNS_PER_PROBE == 64 and rs.MAX_RUNS_GLOBAL == 4096
            and rs.MAX_RECEIPTS_PER_PROBE == 131072 and rs.MAX_RECEIPTS_GLOBAL == 1048576)
        # Populate legitimate receipt/run authority at the REAL run limits
        # in one fixture transaction, instead of 4096 expensive fsyncs.
        full = rs.RemoteStore(os.path.join(root,"full-runs"),clock=lambda:h.NOW).open()
        try:
            with full._transaction():
                for i in range(rs.MAX_RUNS_GLOBAL):
                    probe = h.PROBE if i<64 else "probe-%02d" % (i//64)
                    run = "%032x" % i
                    raw = h.pl.encode_sample(h._sample(1,probe=probe,run=run))
                    full._conn.execute("INSERT INTO remote_probe_runs VALUES(?,?,?,?,?,?)",
                        (probe,run,1,h.NOW+1,h.NOW,h.NOW))
                    full._conn.execute("INSERT INTO remote_probe_receipts VALUES(?,?,?,?,?)",
                        (probe,run,1,hashlib.sha256(raw).digest(),h.NOW))
            out["real_64_run_per_probe_capacity"] = refused(
                lambda:accept(full,run="f"*32),rs.RunCapacityError)
            out["real_4096_global_run_capacity"] = refused(
                lambda:accept(full,probe=h.PROBE_B),rs.RunCapacityError)
            out["real_full_run_capacity_keeps_receipt_verdict"] = (
                accept(full,run="0"*32) == "duplicate" and full.status()["run_count"] == 4096)
        finally:
            full.close()
    finally:
        plane.close()
        h.clean(root)
        h.clean(os.path.dirname(cfg))
    return out


def group_concurrency():
    out = {}
    root = h.temp_dir()
    plane,cfg,kd = h.make_plane(root)
    server,request,d = h._serve(plane)
    try:
        for name, conflict in (("same_hash",False),("different_hash",True)):
            run = "a"*32 if conflict else h.RUN
            samples = [h._sample(1,run=run) for _ in range(8)]
            if conflict:
                for i in range(4,8):
                    samples[i]["dns"] = h._slot(99)
            barrier = threading.Barrier(8)
            def task(sample):
                raw,headers = h.body_for(sample,run=run)
                barrier.wait(timeout=10)
                return h.post(request,raw,headers)
            with ThreadPoolExecutor(max_workers=8) as pool:
                responses = list(pool.map(task,samples))
            payloads = [json.loads(row[1]) for row in responses]
            counts = {token:sum(p.get("result",p.get("error")) == token for p in payloads)
                      for token in ("accepted","duplicate","equivocation")}
            out[name+"_atomic_threading_http_verdicts"] = (
                counts == {"accepted":1,"duplicate":3 if conflict else 7,"equivocation":4 if conflict else 0}
                and all(row[0] in (200,409) for row in responses))
        out["one_sample_and_receipt_per_concurrent_tuple"] = plane.store.status()["sample_count"] == 2 and plane.store.status()["receipt_count"] == 2
        # Inject failure AFTER run/receipt/sample writes but BEFORE commit.
        original = plane.store._physical_admission
        calls = [0]
        def fail_after_write():
            calls[0] += 1
            if calls[0] == 2:
                raise rs.StorageCapacityError("fixture full")
            return original()
        with patch.object(plane.store,"_physical_admission",side_effect=fail_after_write):
            response = send(plane,h._sample(2))
        out["post_write_failure_rolls_back_all_three_states"] = (
            response[1] == {"error":"remote_storage_capacity"}
            and plane.store.status()["receipt_count"] == 2
            and plane.store.run_state(h.PROBE,h.RUN)["max_seq"] == 1
            and plane.store.receipt_hash(h.PROBE,h.RUN,2) is None)
        # Thread-safe token consumption must not manufacture burst capacity.
        bucket = TokenBucket(2,7,clock=lambda:0)
        with ThreadPoolExecutor(max_workers=16) as pool:
            verdicts = list(pool.map(lambda _:bucket.check()[0],range(100)))
        out["concurrent_token_bucket_has_exact_burst"] = sum(verdicts) == 7
        crash_root = os.path.join(root,"crash")
        seed = rs.RemoteStore(crash_root,clock=lambda:h.NOW).open()
        accept(seed)
        seed.close()
        script = """import os,sys
sys.path.insert(0,sys.argv[1])
from web.remote_store import RemoteStore
s=RemoteStore(sys.argv[2],clock=lambda:%r).open()
original=s._physical_admission
calls=[0]
def crash_before_commit():
    calls[0]+=1
    if calls[0]==2: os._exit(17)
    original()
s._physical_admission=crash_before_commit
s.accept(%r,%r,2,%r,%r)
""" % (h.NOW,h.PROBE,h.RUN,h.NOW+2,h.pl.encode_sample(h._sample(2)))
        child = subprocess.run([sys.executable,"-c",script,
            os.path.join(h.ROOT,"monitor-v2"),crash_root],capture_output=True,timeout=30)
        reopened = rs.RemoteStore(crash_root,clock=lambda:h.NOW).open()
        try:
            out["process_crash_before_commit_preserves_only_prior_tuple"] = (
                child.returncode == 17 and reopened.status()["sample_count"] == 1
                and reopened.status()["receipt_count"] == 1
                and reopened.run_state(h.PROBE,h.RUN)["max_seq"] == 1
                and reopened.receipt_hash(h.PROBE,h.RUN,2) is None)
        finally:
            reopened.close()
    finally:
        server.shutdown()
        server.server_close()
        plane.close()
        h.clean(d)
        h.clean(root)
        h.clean(os.path.dirname(cfg))
    return out


def group_status():
    out = {}
    root = h.temp_dir()
    clock = [h.NOW]
    plane,cfg,kd = h.make_plane(root,clock=lambda:clock[0])
    try:
        out["configured_silence_is_source_unavailable"] = (
            plane.status()["status"] == "source_unavailable" and plane.status()["subcode"] == "probe_not_reporting")
        send(plane,h._sample(1))
        out["reporting_is_fresh_by_sample_time"] = plane.status()["status"] == "fresh"
        rows = plane.read_samples(h.NOW,h.NOW+10,limit=1)
        out["bounded_read_has_only_retained_sample_and_operator_labels"] = (
            len(rows) == 1 and rows[0]["sample"] == h._sample(1)
            and rows[0]["site_label"] == "site-a" and not rows[0]["mapping_retired"]
            and "body_hash" not in json.dumps(rows))
        out["read_refuses_unbounded_window_and_limit"] = (
            refused(lambda:plane.read_samples(h.NOW-8*86400,h.NOW),ValueError)
            and refused(lambda:plane.read_samples(h.NOW,h.NOW+1,limit=257),ValueError)
            and refused(lambda:plane.read_samples(float('nan'),h.NOW),ValueError))
        clock[0] += 1000
        send(plane,h._sample(1))
        out["duplicate_received_time_does_not_make_source_fresh"] = plane.status()["subcode"] == "probe_not_reporting"
        before = plane.store.status()
        history = h._history_fixture(root)
        plane.store.receipt_budget = 256
        send(plane,h._sample(2,epoch=clock[0]))
        status = plane.status()
        out["receipt_capacity_health_is_remote_only"] = (
            status["subcode"] == "remote_receipt_capacity" and history.health()["enabled"]
            and not history.health()["degraded"] and "remote" not in json.dumps(
                history.classifier_bundle(h.NOW-100,h.NOW+100,"fresh"),default=str).lower())
        history.close()
        history_path = os.path.join(root,"diagnostics","history.sqlite3")
        snapshot = open(history_path,"rb").read()
        plane.status()
        plane.read_samples(h.NOW,h.NOW+10)
        out["remote_status_and_read_leave_history_bytes_unchanged"] = open(history_path,"rb").read() == snapshot
        out["capacity_refusal_preserves_receipt_count"] = plane.store.status()["receipt_count"] == before["receipt_count"]
    finally:
        plane.close()
        h.clean(root)
        h.clean(os.path.dirname(cfg))
    return out
