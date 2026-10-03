"""Report validation tests; synthetic inputs are never physical acceptance."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / 'tools/p6-resource-report.py'
if not TOOL.exists():
    TOOL = Path(__file__).with_name('p6-resource-report.py')
spec = importlib.util.spec_from_file_location('resource_report', TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.binding = dict(service='lab-service', probe='p6-test', profile='a' * 64)
        self.report = dict(v=1, lab_only=True, kind='resource_window', reason='window_finished',
                           service='lab-service', probe_id='p6-test', profile_id='a' * 64,
                           interval_seconds=15, summary=dict(failures=0), samples=[
            dict(process_id=123, process_start_ticks=456, logical_processors=4,
                 service_state='Running', profile_enabled=True, configured_profiles=1,
                 enabled_profiles=1, monotonic_seconds=i*15, system_uptime_seconds=9000+i*15,
                 cpu_total_seconds=50+i/2, private_working_set_bytes=100*1024*1024)
            for i in range(121)])

    def check(self):
        return tool.validate(self.report, **self.binding)

    def refuses(self):
        with self.assertRaises(tool.InvalidReport):
            self.check()

    def test_correct_units_and_no_whole_acceptance(self):
        result = self.check()
        self.assertAlmostEqual(result['cpu_average_total_machine_percent'], 100*60/1800/4)
        self.assertTrue(result['cpu_target_met'])
        self.assertFalse(result['whole_resource_acceptance_pass'])
        self.assertFalse(result['matched_latency_measured'])

    def test_short_window(self):
        self.report['samples'] = self.report['samples'][:-1]
        self.refuses()

    def test_process_restart_even_if_same_pid(self):
        self.report['samples'][20]['process_start_ticks'] += 1
        self.refuses()

    def test_gap(self):
        self.report['samples'][20]['monotonic_seconds'] += 31
        self.refuses()

    def test_nonmonotonic_time(self):
        self.report['samples'][20]['monotonic_seconds'] -= 15
        self.refuses()

    def test_cpu_rollback_and_nonfinite(self):
        for value in (0, float('nan'), True):
            self.report['samples'][20]['cpu_total_seconds'] = value
            self.refuses()

    def test_missing_private_metric(self):
        del self.report['samples'][20]['private_working_set_bytes']
        self.refuses()

    def test_binding(self):
        self.report['service'] = 'another-service'
        self.refuses()

    def test_multiple_profiles_and_pause(self):
        self.report['samples'][20]['configured_profiles'] = 2
        self.refuses()
        self.report['samples'][20]['configured_profiles'] = 1
        self.report['samples'][20]['profile_enabled'] = False
        self.refuses()

    def test_recorded_failure_and_early_close(self):
        self.report['summary']['failures'] = 1
        self.refuses()
        self.report['summary']['failures'] = 0
        self.report['reason'] = 'operator_closed_window'
        self.refuses()

    def test_budget_and_recompute_untrusted_summary(self):
        self.report['summary'].update(cpu_target_met=True, memory_sampled_target_met=True)
        for i, point in enumerate(self.report['samples']):
            point['cpu_total_seconds'] = 50+i*15
        self.report['samples'][20]['private_working_set_bytes'] = 129*1024*1024
        result = self.check()
        self.assertFalse(result['cpu_target_met'])
        self.assertFalse(result['memory_sampled_target_met'])

    def test_digest_and_duplicate_keys(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'report.json'
            raw = json.dumps(self.report).encode()
            path.write_bytes(raw)
            self.assertEqual(tool.read_report(path, hashlib.sha256(raw).hexdigest()), self.report)
            with self.assertRaises(tool.InvalidReport):
                tool.read_report(path, '0'*64)
            raw = b'{"v":1,"v":2}'
            path.write_bytes(raw)
            with self.assertRaises(tool.InvalidReport):
                tool.read_report(path, hashlib.sha256(raw).hexdigest())


if __name__ == '__main__':
    unittest.main(verbosity=2)
