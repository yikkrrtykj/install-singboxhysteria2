"""Readonly validation of the existing LAB sampler's single-profile report.

This validates recorded CPU/private-working-set metrics, not their provenance
or the complete resource acceptance (network and matched latency are separate).
No service, controller, credential, network or signing operation is performed.
"""
import argparse
import hashlib
import json
import math
from pathlib import Path
import stat


class InvalidReport(ValueError):
    pass


def require(condition):
    if not condition:
        raise InvalidReport('invalid_or_incomplete_resource_report')


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0)
    return value


def integer(value, minimum=0):
    require(type(value) is int and value >= minimum)
    return value


def validate(report, *, service, probe, profile):
    require(isinstance(report, dict) and type(report.get('v')) is int and report['v'] == 1)
    require(report.get('kind') == 'resource_window' and report.get('lab_only') is True)
    require(report.get('reason') == 'window_finished')
    require(report.get('service') == service and report.get('probe_id') == probe
            and report.get('profile_id') == profile)
    require(integer(report.get('interval_seconds'), 1) == 15)
    points = report.get('samples')
    require(isinstance(points, list) and 121 <= len(points) <= 128)
    summary = report.get('summary')
    require(isinstance(summary, dict) and integer(summary.get('failures')) == 0)
    first = points[0]
    require(isinstance(first, dict))
    pid = integer(first.get('process_id'), 1)
    started = integer(first.get('process_start_ticks'), 1)
    processors = integer(first.get('logical_processors'), 1)
    require(processors <= 4096)
    prior = None
    private_max = 0
    for point in points:
        require(isinstance(point, dict))
        require(integer(point.get('process_id'), 1) == pid)
        require(integer(point.get('process_start_ticks'), 1) == started)
        require(integer(point.get('logical_processors'), 1) == processors)
        require(point.get('service_state') == 'Running' and point.get('profile_enabled') is True)
        require(integer(point.get('configured_profiles'), 1) == 1)
        require(integer(point.get('enabled_profiles'), 1) == 1)
        number(point.get('monotonic_seconds'))
        number(point.get('system_uptime_seconds'))
        number(point.get('cpu_total_seconds'))
        private_max = max(private_max, integer(point.get('private_working_set_bytes')))
        if prior is not None:
            delta = point['monotonic_seconds'] - prior['monotonic_seconds']
            require(0 < delta <= 30)
            require(point['system_uptime_seconds'] > prior['system_uptime_seconds'])
            require(point['cpu_total_seconds'] >= prior['cpu_total_seconds'])
        prior = point
    elapsed = points[-1]['monotonic_seconds'] - first['monotonic_seconds']
    require(1800 <= elapsed <= 1830)
    cpu = 100 * (points[-1]['cpu_total_seconds'] - first['cpu_total_seconds']) / (elapsed * processors)
    require(0 <= cpu <= 100)
    return dict(v=1, report_structure_valid=True, samples=len(points), duration_seconds=elapsed,
                cpu_average_total_machine_percent=cpu,
                private_working_set_sampled_max_bytes=private_max,
                cpu_target_met=cpu <= 2, memory_sampled_target_met=private_max <= 128 * 1024 * 1024,
                source='operator_recorded_lab_report_not_independently_attested',
                network_bytes_measured=False, matched_latency_measured=False,
                whole_resource_acceptance_pass=False, whole_p6b2_pass=False)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_report(path, expected_digest):
    path = Path(path).absolute()
    for part in (path, *path.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    require(path.is_file())
    with path.open('rb') as handle:
        raw = handle.read(262145)
    require(len(raw) <= 262144 and hashlib.sha256(raw).hexdigest() == expected_digest)
    return json.loads(raw, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(InvalidReport()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--service', required=True)
    parser.add_argument('--probe', required=True)
    parser.add_argument('--profile', required=True)
    args = parser.parse_args()
    try:
        result = validate(read_report(args.report, args.sha256), service=args.service,
                          probe=args.probe, profile=args.profile)
    except (ValueError, OSError, TypeError, KeyError, RecursionError):
        print(json.dumps(dict(ok=False, error='invalid_or_incomplete_resource_report',
                              whole_resource_acceptance_pass=False)))
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0 if result['cpu_target_met'] and result['memory_sampled_target_met'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
