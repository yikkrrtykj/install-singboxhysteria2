"""Server facts behavior, real SQLite/HTTP, fixed proc fixtures. No live mutation."""
import copy
import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'monitor-v2'))
from web import host_evidence as h
from web import incident_history as ih
from web.server import MonitorWebApp, build_server
from web.access import AccessPolicy
from web.auth import AuthStore

NOW = time.time()

def sample(epoch=NOW, **values):
    row = dict.fromkeys(h.FIELDS)
    row.update(epoch=epoch, run='a'*32, boot='b'*64, service_state='active',
               pid=100, restarts=2, start_us=12345, cpu_percent=12,
               memory_percent=30, load_1m=0.5)
    row.update(values)
    return row

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.clock = NOW
        self.store = h.HostStore(self.temp.name, clock=lambda: self.clock).open()
    def tearDown(self):
        self.store.close(); self.temp.cleanup()
    def read(self, start=NOW-20, end=NOW):
        return self.store.window(start, end)
    def test_actual_schema_reopens_without_version_header_confusion(self):
        self.store.close(); self.store.open()
        self.assertEqual(self.store.conn.execute('PRAGMA user_version').fetchone()[0], 1)
        self.assertEqual(self.store.conn.execute('PRAGMA max_page_count').fetchone()[0], 4096)
    def test_unknown_existing_database_refused_without_modification(self):
        self.store.close()
        conn = sqlite3.connect(self.store.path)
        conn.execute('PRAGMA user_version=2'); conn.close()
        before = self.store.path.read_bytes()
        with self.assertRaises(ValueError): self.store.open()
        self.assertEqual(self.store.path.read_bytes(), before)
    def test_existing_trigger_cannot_be_adopted(self):
        self.store.close()
        conn = sqlite3.connect(self.store.path)
        conn.execute('CREATE TRIGGER surprise AFTER INSERT ON samples BEGIN DELETE FROM samples; END')
        conn.close()
        before = self.store.path.read_bytes()
        with self.assertRaises(ValueError): self.store.open()
        self.assertEqual(self.store.path.read_bytes(), before)
    def test_extra_table_refused(self):
        self.store.close()
        conn = sqlite3.connect(self.store.path); conn.execute('CREATE TABLE other(x)'); conn.close()
        with self.assertRaises(ValueError): self.store.open()
    @unittest.skipUnless(os.name == 'posix', 'POSIX ownership enforced in Linux CI')
    def test_wrong_permissions_and_hardlink_refused(self):
        self.store.close(); self.store.path.chmod(0o644)
        with self.assertRaises(ValueError): self.store.open()
        self.store.path.chmod(0o600)
        os.link(self.store.path, Path(self.temp.name)/'linked.sqlite3')
        with self.assertRaises(ValueError): self.store.open()
    def test_empty_is_missing_not_healthy(self):
        result = self.read()
        self.assertEqual(result['availability'], 'no_records')
        self.assertEqual(result['service']['observations'], 0)
        self.assertIsNone(result['resources']['cpu_percent']['peak'])
    def test_window_is_inclusive_and_read_does_not_write(self):
        for delta in (-21, -20, -10, 0, 1): self.store.append(sample(NOW+delta))
        before = self.store.path.read_bytes()
        result = self.read()
        self.assertEqual(result['sample_count'], 3)
        self.assertEqual(result['availability'], 'available')
        self.assertEqual(self.store.path.read_bytes(), before)
    def test_automatic_restart_and_process_change_are_separate_facts(self):
        self.store.append(sample(NOW-10))
        self.store.append(sample(pid=200, start_us=23456, restarts=3))
        service = self.read()['service']
        self.assertEqual(service['automatic_restart_increments'], 1)
        self.assertEqual(service['process_changes_observed'], 1)
    def test_manual_process_change_does_not_fake_auto_restart(self):
        self.store.append(sample(NOW-10)); self.store.append(sample(pid=200))
        self.assertEqual(self.read()['service']['automatic_restart_increments'], 0)
        self.assertEqual(self.read()['service']['process_changes_observed'], 1)
    def test_pid_reuse_is_detected_by_start_timestamp(self):
        self.store.append(sample(NOW-10)); self.store.append(sample(start_us=99999))
        self.assertEqual(self.read()['service']['process_changes_observed'], 1)
    def test_counter_reset_is_unknown_not_negative_restart(self):
        self.store.append(sample(NOW-10)); self.store.append(sample(restarts=0))
        self.assertEqual(self.read()['service']['counter_resets'], 1)
        self.assertEqual(self.read()['service']['automatic_restart_increments'], 0)
    def test_gaps_reboot_monitor_restart_and_duplicate_time_do_not_compare(self):
        for a, b in ((sample(NOW-40), sample(pid=200, restarts=3)),
                     (sample(NOW-10), sample(boot='c'*64, restarts=3)),
                     (sample(NOW-10), sample(run='c'*32, restarts=3)),
                     (sample(), sample(pid=200, restarts=3))):
            result = h.summarize([a,b], NOW-40, NOW, False, NOW-h.RETENTION)
            self.assertEqual(result['availability'], 'partial')
            self.assertEqual(result['service']['automatic_restart_increments'], 0)
            self.assertEqual(result['service']['process_changes_observed'], 0)
    def test_service_unavailable_is_not_failed_or_healthy(self):
        self.store.append(sample(service_state=None, pid=None, restarts=None, start_us=None))
        self.assertEqual(self.read()['service']['observations'], 0)
        self.assertEqual(self.read()['service']['not_running_samples'], 0)
    def test_failed_state_and_resource_peak_are_facts_without_cause(self):
        self.store.append(sample(service_state='failed', pid=0, cpu_percent=99.5))
        result = self.read()
        self.assertEqual(result['service']['not_running_samples'], 1)
        self.assertEqual(result['resources']['cpu_percent']['peak'], 99.5)
        self.assertNotIn('cause', json.dumps(result))
    def test_unknown_resource_never_becomes_zero(self):
        self.store.append(sample(cpu_percent=None))
        result = self.read()['resources']['cpu_percent']
        self.assertEqual(result, {'observations':0, 'peak':None})
    def test_closed_samples_reject_nan_infinity_bool_and_free_text(self):
        for values in ({'cpu_percent':float('nan')}, {'load_1m':float('inf')},
                       {'pid':True}, {'service_state':'private-secret'},
                       {'epoch':10**1000}, {'extra':'private-secret'}):
            with self.assertRaises(ValueError): self.store.append(sample(**values))
        self.assertEqual(self.read()['sample_count'], 0)
    def test_retention_and_row_limit_are_enforced(self):
        self.store.append(sample(NOW-h.RETENTION-1)); self.store.append(sample())
        self.assertEqual(self.store.conn.execute('SELECT count(*) FROM samples').fetchone()[0], 1)
        with patch.object(h, 'MAX_ROWS', 3):
            for i in range(6): self.store.append(sample(NOW+i))
        self.assertEqual(self.store.conn.execute('SELECT count(*) FROM samples').fetchone()[0], 3)
    def test_read_truncation_requires_extra_row(self):
        for i in range(4): self.store.append(sample(NOW-i))
        with patch.object(h, 'READ_LIMIT', 3): result = self.read()
        self.assertEqual(result['sample_count'], 3)
        self.assertTrue(result['truncated']); self.assertEqual(result['availability'], 'partial')
    def test_old_records_are_not_returned_even_when_collector_stopped(self):
        self.store.append(sample()); self.clock = NOW+h.RETENTION+1
        self.assertEqual(self.store.window(NOW-1, NOW+1)['sample_count'], 0)
    def test_corrupt_retained_sample_causes_unavailable(self):
        self.store.append(sample())
        self.store.conn.execute('UPDATE samples SET service_state=?', ('private-secret',)); self.store.conn.commit()
        plane = h.HostEvidence(self.temp.name, store=self.store, clock=lambda: NOW)
        result = plane.incident(1,NOW-20,NOW)
        self.assertEqual(result['availability'], 'unavailable')
        self.assertNotIn('private-secret', json.dumps(result))
    def test_no_run_boot_or_pid_in_response(self):
        self.store.append(sample())
        result = self.read()
        self.assertNotIn('a'*32, json.dumps(result)); self.assertNotIn('b'*64, json.dumps(result))
        self.assertNotIn('pid', json.dumps(result)); self.assertNotIn('start_us', json.dumps(result))
    def test_worker_contains_failure_and_stops_cleanly(self):
        reader = SimpleNamespace(sample=lambda epoch,run: sample(epoch, run=run))
        plane = h.HostEvidence(self.temp.name, reader=reader, store=self.store, clock=lambda: NOW)
        plane.start()
        for _ in range(100):
            if plane.collection_status == 'recording': break
            time.sleep(0.005)
        self.assertEqual(plane.collection_status, 'recording')
        with patch.object(reader, 'sample', side_effect=RuntimeError('private-secret')): plane.cycle()
        self.assertEqual(plane.collection_status, 'unavailable')
        plane.stop(); self.assertIsNone(plane.thread)
    def test_worker_start_refusal_is_isolated_and_leaves_no_open_store(self):
        plane = h.HostEvidence(self.temp.name, store=self.store)
        with patch.object(threading.Thread, 'start', side_effect=RuntimeError('private-secret')):
            plane.start()
        self.assertEqual(plane.collection_status, 'unavailable')
        self.assertIsNone(plane.thread); self.assertIsNone(self.store.conn)
        plane.stop()
    def test_storage_full_refuses_only_host_record_and_preserves_existing_rows(self):
        self.store.conn.execute('PRAGMA max_page_count=4')
        failure = False
        for i in range(1000):
            try: self.store.append(sample(NOW+i))
            except sqlite3.Error:
                failure = True; break
        self.assertTrue(failure)
        self.assertGreater(self.store.conn.execute('SELECT count(*) FROM samples').fetchone()[0],0)

class ReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.proc = Path(self.temp.name)
        self.write('sys/kernel/random/boot_id','12345678-1234-1234-1234-123456789abc\n')
        self.write('stat','cpu 10 0 10 70 10 0 0 0 0 0\n')
        self.write('meminfo','MemTotal: 1000 kB\nMemAvailable: 400 kB\n')
        self.write('loadavg','0.5 0.2 0.1 1/100 9\n')
        self.write('sys/fs/file-nr','20 0 100\n')
        self.write('sys/net/netfilter/nf_conntrack_count','10\n')
        self.write('sys/net/netfilter/nf_conntrack_max','100\n')
        self.calls = []
    def tearDown(self): self.temp.cleanup()
    def write(self, path, text):
        target = self.proc/path; target.parent.mkdir(parents=True, exist_ok=True); target.write_text(text, encoding='ascii')
    def runner(self, argv, **kw):
        self.calls.append((argv, kw))
        return SimpleNamespace(returncode=0, stdout=b'ActiveState=active\nMainPID=100\nNRestarts=2\nExecMainStartTimestampMonotonic=12345\n')
    def test_fixed_reader_and_cpu_delta(self):
        reader = h.HostReader(self.temp.name, self.proc, self.runner)
        first = reader.sample(NOW,'a'*32)
        self.assertIsNone(first['cpu_percent'])
        self.assertEqual(first['memory_percent'], 60)
        self.assertEqual(first['fd_percent'], 20)
        self.assertEqual(first['conntrack_percent'], 10)
        self.write('stat','cpu 20 0 20 140 20 0 0 0 0 0\n')
        second = reader.sample(NOW+10,'a'*32)
        self.assertEqual(second['cpu_percent'], 20)
        argv, kw = self.calls[0]
        self.assertEqual(argv[:3], ['/usr/bin/systemctl','show','sing-box.service'])
        self.assertEqual(kw['timeout'],1)
        self.assertTrue(h.valid(second))
    def test_timeout_permission_denied_and_malformed_output_are_unknown(self):
        for error in (PermissionError('private-secret'), subprocess.TimeoutExpired('systemctl',1)):
            reader = h.HostReader(self.temp.name, self.proc, lambda *a,**k: (_ for _ in ()).throw(error))
            row = reader.sample(NOW,'a'*32)
            self.assertIsNone(row['service_state']); self.assertIsNone(row['pid'])
        reader = h.HostReader(self.temp.name, self.proc, lambda *a,**k: SimpleNamespace(returncode=0,stdout=b'private-secret'))
        self.assertIsNone(reader.sample(NOW,'a'*32)['service_state'])
    def test_absent_proc_fields_and_cpu_gap_do_not_guess(self):
        reader = h.HostReader(self.temp.name, self.proc, self.runner)
        reader.sample(NOW,'a'*32)
        self.assertIsNone(reader.sample(NOW+100,'a'*32)['cpu_percent'])
        (self.proc/'meminfo').unlink()
        self.assertIsNone(reader.sample(NOW+110,'a'*32)['memory_percent'])
    @unittest.skipUnless(sys.platform.startswith('linux'), 'real Linux proc reader runs in Linux CI')
    def test_real_linux_proc_fields_and_read_only_systemd_query(self):
        reader = h.HostReader(self.temp.name)
        first = reader.sample(time.time(),'a'*32)
        time.sleep(0.05)
        second = reader.sample(time.time(),'a'*32)
        self.assertTrue(h.valid(first)); self.assertTrue(h.valid(second))
        self.assertIsNotNone(second['memory_percent'])
        self.assertIsNotNone(second['cpu_percent'])
        self.assertIsNotNone(second['disk_percent'])

class PresenterBoundaryTests(unittest.TestCase):
    def test_summary_limits_do_not_deny_separate_recorded_facts(self):
        from web.incident_presenter import summarize, SUMMARY_KEYS
        result = summarize(dict(category='insufficient_evidence',first_signal_epoch=1,last_signal_epoch=2),())
        self.assertEqual(set(result),set(SUMMARY_KEYS))
        self.assertIn('shown separately',result['limitations'])
        self.assertIn('not inputs to this stored classification',result['limitations'])
        self.assertNotIn('No process-restart or resource-exhaustion history is recorded',result['limitations'])

class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = h.HostStore(self.temp.name, clock=lambda: NOW).open()
        self.store.append(sample())
        self.plane = h.HostEvidence(self.temp.name, store=self.store, clock=lambda: NOW)
        self.calls = []
        def detail(ident):
            self.calls.append(ident)
            if ident != 1: return ih.OUTCOME_MISSING, None
            return ih.OUTCOME_OK, dict(analysis_start_epoch=NOW-20, last_classified_end_epoch=NOW)
        self.history = SimpleNamespace(incident_detail=detail)
        auth = AuthStore(self.temp.name, session_ttl=3600); auth.set_password('fixture-password-only')
        self.app = MonitorWebApp(None, AccessPolicy(self.temp.name), None, auth=auth, incident_history=self.history, host_evidence=self.plane)
        self.server = build_server(self.app,'127.0.0.1',0,None)
        self.thread = threading.Thread(target=self.server.serve_forever,daemon=True); self.thread.start()
        status, _, headers = self.request('POST','/api/v1/login',body={'password':'fixture-password-only'})
        self.assertEqual(status,200); self.cookie=headers['Set-Cookie'].split(';')[0]
    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.thread.join(5)
        self.store.close(); self.temp.cleanup()
    def request(self, method='GET',path='/api/v1/incidents/1/host-evidence',cookie=None,body=None):
        conn = http.client.HTTPConnection('127.0.0.1',self.server.server_address[1],timeout=5)
        headers={'Content-Type':'application/json'}
        if cookie: headers['Cookie']=cookie
        try:
            conn.request(method,path,body=json.dumps(body) if body is not None else None,headers=headers)
            res=conn.getresponse(); return res.status,json.loads(res.read()),dict(res.getheaders())
        finally: conn.close()
    def test_requires_session_before_history_access(self):
        self.calls.clear(); self.assertEqual(self.request()[0],401); self.assertEqual(self.calls,[])
    def test_stored_bounds_ignore_url_and_no_cache(self):
        status,data,headers=self.request(path='/api/v1/incidents/1/host-evidence?start_epoch=0&end_epoch=9999999999&limit=999999',cookie=self.cookie)
        self.assertEqual(status,200); self.assertEqual(data['window'],dict(start_epoch=NOW-20,end_epoch=NOW))
        self.assertIn('no-store',headers['Cache-Control'])
    def test_missing_noncanonical_ids_and_post_refused(self):
        for ident in ('0','01','-1','abc','999','9'*100):
            self.assertEqual(self.request(path='/api/v1/incidents/'+ident+'/host-evidence',cookie=self.cookie)[0],404)
        self.assertEqual(self.request('POST',cookie=self.cookie,body={})[0],405)
    def test_unreadable_history_or_missing_plane_never_empty_success(self):
        self.history.incident_detail=lambda ident:(ih.OUTCOME_STORE_UNAVAILABLE,None)
        self.assertEqual(self.request(cookie=self.cookie)[0],503)
        self.history.incident_detail=lambda ident:(ih.OUTCOME_OK,dict(analysis_start_epoch=NOW-20,last_classified_end_epoch=NOW))
        self.app.host_evidence=None
        self.assertEqual(self.request(cookie=self.cookie)[0],503)

if __name__ == '__main__': unittest.main(verbosity=2)
