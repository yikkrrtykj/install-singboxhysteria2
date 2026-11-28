"""UM-LT restricted monitor-v2 traffic export: contract, precision, safety.

Everything here is stdlib + the real monitor-v2 modules (no server mocks for the
core contract): Tracker -> sanitized projection -> atomic writer -> the exact
rules the rev-7 Linux agent applies to the file. The subprocess cases run the
REAL ``webapp.py serve`` runtime to prove default-disabled behavior and the
enabled startup/stale-removal path.
"""
import contextlib
import glob
import io
import json
import math
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'monitor-v2'))

from collector import EXPORT_SAFE_INT_MAX, Collector, Tracker  # noqa: E402
from export import (EXPORT_KEYS, INBOUND_KEYS, MAX_EXPORT_BYTES,  # noqa: E402
                    MAX_INBOUNDS, SCHEMA, SCHEMA_VERSION, SOURCE, InboundSpec,
                    TrafficExportConfigError, TrafficExportDocumentError,
                    TrafficExportWriter, build_document, encode_document,
                    parse_inbound_specs, validate_export_path)
from web.broker import SnapshotBroker  # noqa: E402

WEBAPP = str(ROOT / 'monitor-v2' / 'webapp.py')
SAFE = EXPORT_SAFE_INT_MAX

SENTINEL_USER = 'SENTINEL-USER-9f3a'
SENTINEL_SOURCE = '203.0.113.77:51000'
SENTINEL_DEST = 'sentinel.example:443'
SENTINEL_ID = 'conn-SENTINEL-ID-9f3a'
SENTINEL_SECRET = 'SUPER-SECRET-TOKEN-9f3a'
SENTINEL_PROXY = 'proxy-SENTINEL-NAME'

# The frozen rev-7 consumer key sets (mirrors um/internal/linuxobs and
# um/internal/contract; duplicated ON PURPOSE so a wire drift fails here).
REV7_TOP_KEYS = frozenset({
    'schema', 'schema_version', 'source', 'source_epoch', 'sequence',
    'generated_at', 'observed_at', 'monitor_stale',
    'monitor_last_success_at', 'counter_scope', 'exactness',
    'active_connections', 'rate_window_seconds', 'inbounds'})
REV7_ROW_KEYS = frozenset({
    'inbound_tag', 'kind', 'observed_uplink_bytes', 'observed_downlink_bytes',
    'uplink_observed_rate_bps', 'downlink_observed_rate_bps',
    'active_connections', 'observed_at', 'quality'})
REV7_KINDS = {'reality', 'hysteria2', 'other'}
REV7_QUALITIES = {'lower_bound', 'partial', 'unavailable'}
REV7_EPOCH_RE = re.compile(r'^[0-9a-f]{32}$')
REV7_TAG_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$')
REV7_MAX_RATE_BPS = 1e12
REV7_MAX_WINDOW_SECONDS = 3600.0
REV7_MAX_ACTIVE = 1000000
REV7_MAX_AGE = 86400
REV7_FRESH_MAX_AGE = 15
REV7_FUTURE_TOLERANCE = 5


class FakeClock:
    def __init__(self, value=1000.0):
        self.value = value

    def __call__(self):
        return self.value


def spec_pairs(*pairs):
    return parse_inbound_specs(list(pairs))


def read_bytes(path):
    with open(path, 'rb') as handle:
        return handle.read()


def read_document(path):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)

def clean_projection(now=1000, last_success=None, stale=False, **overrides):
    projection = {
        'observed_at': int(now),
        'monitor_stale': bool(stale),
        'monitor_last_success_at': None if stale else (
            int(now) - 1 if last_success is None else last_success),
        # null is legal at the document level (unavailable total); the tracker
        # always supplies the exact per-inbound sum.
        'active_connections': None,
        'rate_window_seconds': None,
        'inbounds': [],
    }
    projection.update(overrides)
    return projection


def clean_row(tag='vless-in', kind='reality', uplink=1000, downlink=2000,
              up_rate=None, down_rate=None, active=1, observed_at=1000,
              quality='lower_bound'):
    return {
        'inbound_tag': tag,
        'kind': kind,
        'observed_uplink_bytes': uplink,
        'observed_downlink_bytes': downlink,
        'uplink_observed_rate_bps': up_rate,
        'downlink_observed_rate_bps': down_rate,
        'active_connections': active,
        'observed_at': observed_at,
        'quality': quality,
    }


def rev7_validate(document):
    """Strict mirror of the rev-7 consumer checks that constrain the producer."""
    assert set(document) == REV7_TOP_KEYS, sorted(set(document) ^ REV7_TOP_KEYS)
    assert document['schema'] == 'singbox-monitor-traffic-export'
    assert document['schema_version'] == 1
    assert document['source'] == 'monitor-v2'
    assert REV7_EPOCH_RE.match(document['source_epoch']), document['source_epoch']
    assert isinstance(document['sequence'], int) and not isinstance(
        document['sequence'], bool) and 0 <= document['sequence'] <= SAFE
    generated = document['generated_at']
    observed = document['observed_at']
    for label, value in (('generated_at', generated), ('observed_at', observed)):
        assert isinstance(value, int) and not isinstance(value, bool)
        assert 0 <= value <= SAFE, label
    assert observed <= generated
    assert generated - observed <= REV7_MAX_AGE
    stale = document['monitor_stale']
    assert isinstance(stale, bool)
    last_success = document['monitor_last_success_at']
    if stale:
        if last_success is not None:
            assert last_success <= generated
    else:
        assert last_success is not None, 'fresh export needs last success'
        assert last_success <= generated
    assert document['counter_scope'] == 'observation_epoch'
    assert document['exactness'] == 'lower_bound'
    total_active = document['active_connections']
    if total_active is not None:
        assert isinstance(total_active, int) and not isinstance(
            total_active, bool) and 0 <= total_active <= REV7_MAX_ACTIVE
    window = document['rate_window_seconds']
    if window is not None:
        assert isinstance(window, (int, float)) and not isinstance(window, bool)
        assert math.isfinite(window) and 0 < window <= REV7_MAX_WINDOW_SECONDS
    inbounds = document['inbounds']
    assert isinstance(inbounds, list) and len(inbounds) <= 16
    seen = set()
    active_sum = 0
    any_rate = False
    for index, row in enumerate(inbounds):
        assert isinstance(row, dict) and set(row) == REV7_ROW_KEYS, (
            index, sorted(set(row) ^ REV7_ROW_KEYS))
        tag = row['inbound_tag']
        assert isinstance(tag, str) and REV7_TAG_RE.match(tag) and len(tag) <= 64
        assert tag not in seen
        seen.add(tag)
        assert row['kind'] in REV7_KINDS
        row_observed = row['observed_at']
        assert isinstance(row_observed, int) and not isinstance(
            row_observed, bool)
        assert row_observed <= generated + REV7_FUTURE_TOLERANCE
        assert row_observed >= generated - REV7_MAX_AGE
        active = row['active_connections']
        assert isinstance(active, int) and not isinstance(active, bool)
        assert 0 <= active <= REV7_MAX_ACTIVE
        active_sum += active
        for label in ('observed_uplink_bytes', 'observed_downlink_bytes'):
            value = row[label]
            if value is not None:
                assert isinstance(value, int) and not isinstance(value, bool)
                assert 0 <= value <= SAFE, (label, value)
        for label in ('uplink_observed_rate_bps',
                      'downlink_observed_rate_bps'):
            value = row[label]
            if value is not None:
                assert isinstance(value, (int, float)) and not isinstance(
                    value, bool)
                assert math.isfinite(value) and 0 <= value <= REV7_MAX_RATE_BPS
        quality = row['quality']
        assert quality in REV7_QUALITIES
        values = [row['observed_uplink_bytes'], row['observed_downlink_bytes'],
                  row['uplink_observed_rate_bps'],
                  row['downlink_observed_rate_bps']]
        if quality == 'lower_bound':
            assert row['observed_uplink_bytes'] is not None
            assert row['observed_downlink_bytes'] is not None
        elif quality == 'partial':
            assert any(value is not None for value in values), row
        else:
            assert all(value is None for value in values), row
        if stale:
            # The rev-7 consumer refuses a stale export carrying anything but
            # partial rows: a stale monitor cannot vouch for a fresh/lower-bound
            # or a fully-unavailable reading; unobserved tags are omitted.
            assert quality == 'partial', row
        if row['uplink_observed_rate_bps'] is not None or \
                row['downlink_observed_rate_bps'] is not None:
            any_rate = True
    if any_rate:
        assert window is not None, 'rates require a rate window'
    if total_active is not None:
        assert total_active >= active_sum
    assert not stale or not any_rate, 'stale exports must have null rates'
    return document


def tracker_with_traffic():
    tracker = Tracker()
    tracker.apply_batch({'reset': True, 'events': [
        {'type': 'NEW', 'id': 'r1', 'connection': {
            'id': 'r1', 'user': 'vmix-01', 'inbound': 'vless-in',
            'inbound_type': 'vless', 'network': 'tcp',
            'source': SENTINEL_SOURCE, 'destination': SENTINEL_DEST,
            'created_at': 1700000000000,
            'uplink_total': 1000, 'downlink_total': 2000}},
        {'type': 'NEW', 'id': 'h1', 'connection': {
            'id': 'h1', 'user': 'vmix-02', 'inbound': 'hy2-in',
            'inbound_type': 'hysteria2', 'network': 'udp',
            'source': SENTINEL_SOURCE, 'destination': SENTINEL_DEST,
            'uplink_total': 5, 'downlink_total': 10}},
        {'type': 'NEW', 'id': 'x1', 'connection': {
            'id': 'x1', 'user': 'other-user', 'inbound': 'trojan-in',
            'inbound_type': 'trojan', 'network': 'tcp',
            'source': SENTINEL_SOURCE, 'destination': SENTINEL_DEST,
            'uplink_total': 7, 'downlink_total': 8}},
    ]}, 1000.0)
    return tracker


def projection_from_tracker(tracker, pairs, now=1005.0, stale=False,
                            last_success=1000):
    return tracker.export_traffic(
        now, [(spec.tag, spec.kind) for spec in spec_pairs(*pairs)],
        monitor_stale=stale, monitor_last_success_at=last_success)


class ConfigTests(unittest.TestCase):
    def test_parse_valid_pairs_and_ordered(self):
        specs = spec_pairs('vless-in:reality', 'hy2-in:hysteria2')
        self.assertEqual(specs, (InboundSpec('vless-in', 'reality'),
                                 InboundSpec('hy2-in', 'hysteria2')))

    def test_requires_at_least_one_pair(self):
        with self.assertRaises(TrafficExportConfigError):
            parse_inbound_specs([])
        with self.assertRaises(TrafficExportConfigError):
            parse_inbound_specs(None)

    def test_max_eight_pairs(self):
        parse_inbound_specs(['t%d:other' % i for i in range(MAX_INBOUNDS)])
        with self.assertRaises(TrafficExportConfigError):
            parse_inbound_specs(
                ['t%d:other' % i for i in range(MAX_INBOUNDS + 1)])

    def test_duplicate_tag_rejected_even_with_other_kind(self):
        with self.assertRaises(TrafficExportConfigError):
            spec_pairs('vless-in:reality', 'vless-in:other')
        with self.assertRaises(TrafficExportConfigError):
            spec_pairs('vless-in:reality', 'vless-in:reality')

    def test_unknown_kind_and_malformed_separator_rejected(self):
        for bad in ('vless-in:trojan', 'vless-in', 'vless-in:', ':reality',
                    'a:b:c', 'vless in:reality', 'vless-in:Reality'):
            with self.assertRaises(TrafficExportConfigError, msg=bad):
                parse_inbound_specs([bad])

    def test_strict_tag_grammar(self):
        for tag in ('a', 'A', 'vless-in', 'hy2.in_1', 'x' * 64):
            spec_pairs(tag + ':other')
        for tag in ('', '-lead', '.lead', '_lead', 'x' * 65, 'a b', 'a\tb',
                    'a:b', 'ümlaut'):
            with self.assertRaises(TrafficExportConfigError, msg=tag):
                parse_inbound_specs([tag + ':other'])

    def test_relative_and_non_file_paths_rejected(self):
        for bad in ('', 'relative.json', './relative.json', '../x.json',
                    'a/b.json'):
            with self.assertRaises(TrafficExportConfigError, msg=bad):
                validate_export_path(bad)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(TrafficExportConfigError):
                validate_export_path(directory)  # a directory, not a file
            accepted = validate_export_path(
                os.path.join(directory, 'traffic.json'))
            self.assertTrue(os.path.isabs(accepted))

    def test_missing_parent_and_non_regular_target_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, 'no-such-dir', 'traffic.json')
            with self.assertRaises(TrafficExportConfigError):
                validate_export_path(missing)
            as_dir = os.path.join(directory, 'as-dir')
            os.mkdir(as_dir)
            with self.assertRaises(TrafficExportConfigError):
                validate_export_path(as_dir)

    def test_symlinked_final_path_and_parent_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, 'real.json')
            with open(target, 'w') as handle:
                handle.write('{}')
            link = os.path.join(directory, 'link.json')
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation not permitted here')
            with self.assertRaises(TrafficExportConfigError):
                validate_export_path(link)
            real_dir = os.path.join(directory, 'real-dir')
            os.mkdir(real_dir)
            dir_link = os.path.join(directory, 'dir-link')
            os.symlink(real_dir, dir_link)
            with self.assertRaises(TrafficExportConfigError):
                validate_export_path(os.path.join(dir_link, 'traffic.json'))

    def test_frozen_key_sets_are_exact_allow_lists(self):
        self.assertEqual(EXPORT_KEYS, REV7_TOP_KEYS)
        self.assertEqual(INBOUND_KEYS, REV7_ROW_KEYS)
        self.assertEqual(len(EXPORT_KEYS), 14)
        self.assertEqual(len(INBOUND_KEYS), 9)
        self.assertEqual(SCHEMA, 'singbox-monitor-traffic-export')
        self.assertEqual(SCHEMA_VERSION, 1)
        self.assertEqual(SOURCE, 'monitor-v2')
        self.assertEqual(MAX_INBOUNDS, 8)
        self.assertEqual(MAX_EXPORT_BYTES, 64 * 1024)


class TrackerProjectionTests(unittest.TestCase):
    def test_only_configured_tags_and_kinds_appear(self):
        tracker = tracker_with_traffic()
        projection = projection_from_tracker(
            tracker, ('vless-in:reality', 'hy2-in:hysteria2'))
        tags = [row['inbound_tag'] for row in projection['inbounds']]
        self.assertEqual(tags, ['vless-in', 'hy2-in'])
        self.assertEqual([row['kind'] for row in projection['inbounds']],
                         ['reality', 'hysteria2'])
        raw = json.dumps(projection)
        self.assertNotIn('trojan-in', raw)
        self.assertNotIn('trojan', raw)

    def test_counters_are_exact_integers(self):
        tracker = tracker_with_traffic()
        projection = projection_from_tracker(tracker, ('vless-in:reality',))
        row = projection['inbounds'][0]
        self.assertIs(type(row['observed_uplink_bytes']), int)
        self.assertEqual(row['observed_uplink_bytes'], 1000)
        self.assertEqual(row['observed_downlink_bytes'], 2000)
        self.assertEqual(row['quality'], 'lower_bound')
        # The legacy dashboard snapshot keeps its historic float projection.
        snapshot = tracker.snapshot(1005.0)
        self.assertEqual(
            snapshot['devices']['vmix-01']['protocols']['vless-in'][
                'uplink_total'], 1000.0)
        self.assertIs(type(snapshot['devices']['vmix-01']['protocols'][
            'vless-in']['uplink_total']), float)

    def test_large_exact_integer_still_publishes(self):
        tracker = Tracker()
        tracker.apply_batch({'reset': True, 'events': [{'type': 'NEW',
            'id': 'big', 'connection': {'id': 'big', 'user': 'u',
            'inbound': 'vless-in', 'uplink_total': SAFE,
            'downlink_total': SAFE}}]}, 1000.0)
        projection = projection_from_tracker(tracker, ('vless-in:reality',))
        row = projection['inbounds'][0]
        self.assertEqual(row['observed_uplink_bytes'], SAFE)
        self.assertEqual(row['observed_downlink_bytes'], SAFE)

    def test_above_safe_integer_is_null_not_float_rounded(self):
        oversized = SAFE + 2  # 2**53 + 1
        tracker = Tracker()
        tracker.apply_batch({'reset': True, 'events': [{'type': 'NEW',
            'id': 'big', 'connection': {'id': 'big', 'user': 'u',
            'inbound': 'vless-in', 'uplink_total': oversized,
            'downlink_total': 5}}]}, 1000.0)
        projection = projection_from_tracker(tracker, ('vless-in:reality',))
        row = projection['inbounds'][0]
        self.assertIsNone(row['observed_uplink_bytes'])  # never rounded
        self.assertEqual(row['observed_downlink_bytes'], 5)
        self.assertEqual(row['quality'], 'partial')
        # ...while the legacy snapshot keeps its (float) compatibility contract.
        snapshot = tracker.snapshot(1005.0)
        legacy = snapshot['devices']['u']['protocols']['vless-in']['uplink_total']
        self.assertEqual(legacy, 9007199254740992.0)
        self.assertIs(type(legacy), float)

    def test_unknown_configured_tag_is_unavailable_never_zero(self):
        tracker = Tracker()
        projection = projection_from_tracker(
            tracker,
            ('vless-in:reality', 'never-seen-in:hysteria2'))
        rows = {row['inbound_tag']: row for row in projection['inbounds']}
        unavailable = rows['never-seen-in']
        self.assertIsNone(unavailable['observed_uplink_bytes'])
        self.assertIsNone(unavailable['observed_downlink_bytes'])
        self.assertIsNone(unavailable['uplink_observed_rate_bps'])
        self.assertIsNone(unavailable['downlink_observed_rate_bps'])
        self.assertEqual(unavailable['active_connections'], 0)
        self.assertEqual(unavailable['quality'], 'unavailable')

    def test_known_zero_bytes_is_zero_not_null(self):
        tracker = Tracker()
        tracker.apply_batch({'reset': True, 'events': [{'type': 'NEW',
            'id': 'z1', 'connection': {'id': 'z1', 'user': 'u',
            'inbound': 'vless-in', 'uplink_total': 0,
            'downlink_total': 0}}]}, 1000.0)
        projection = projection_from_tracker(tracker, ('vless-in:reality',))
        row = projection['inbounds'][0]
        self.assertEqual(row['observed_uplink_bytes'], 0)
        self.assertEqual(row['observed_downlink_bytes'], 0)
        self.assertEqual(row['quality'], 'lower_bound')

    def test_no_raw_identifiers_users_sources_destinations_secrets(self):
        tracker = tracker_with_traffic()
        projection = projection_from_tracker(
            tracker, ('vless-in:reality', 'hy2-in:hysteria2'))
        raw = json.dumps(projection, sort_keys=True)
        for sentinel in (SENTINEL_USER, SENTINEL_SOURCE, SENTINEL_DEST,
                         SENTINEL_ID, SENTINEL_SECRET, SENTINEL_PROXY,
                         '203.0.113.77', 'vmix-01', 'r1'):
            self.assertNotIn(sentinel, raw)
        self.assertEqual(set(projection), {
            'observed_at', 'monitor_stale', 'monitor_last_success_at',
            'active_connections', 'rate_window_seconds', 'inbounds'})
        for row in projection['inbounds']:
            self.assertEqual(set(row), REV7_ROW_KEYS)

    def test_stale_keeps_counters_but_degrades_quality_and_rates(self):
        tracker = tracker_with_traffic()
        tracker.apply_batch({'reset': False, 'events': [
            {'type': 'UPDATE', 'id': 'r1', 'uplink_delta': 300,
             'downlink_delta': 700}]}, 1002.0)
        fresh = projection_from_tracker(tracker, ('vless-in:reality',),
                                        now=1003.0, stale=False,
                                        last_success=1002)
        stale = projection_from_tracker(tracker, ('vless-in:reality',),
                                        now=1004.0, stale=True,
                                        last_success=1002)
        self.assertEqual(fresh['inbounds'][0]['quality'], 'lower_bound')
        self.assertEqual(stale['inbounds'][0]['quality'], 'partial')
        self.assertTrue(stale['monitor_stale'])
        self.assertIsNone(stale['inbounds'][0]['uplink_observed_rate_bps'])
        self.assertIsNone(stale['inbounds'][0]['downlink_observed_rate_bps'])
        self.assertEqual(stale['inbounds'][0]['observed_uplink_bytes'], 1300)
        self.assertIsNone(stale['rate_window_seconds'])
        self.assertEqual(stale['monitor_last_success_at'], 1002)
        # Every row of a stale export is partial (rev-7 consumer rule).
        document = build_document(stale, source_epoch='cd' * 16,
                                  sequence=0, generated_at=1004)
        rev7_validate(document)

    def test_stale_omits_never_observed_tags_but_fresh_reports_unavailable(self):
        tracker = tracker_with_traffic()
        pairs = ('vless-in:reality', 'never-seen-in:hysteria2')
        fresh = projection_from_tracker(tracker, pairs, now=1003.0,
                                        stale=False, last_success=1000)
        self.assertEqual([row['inbound_tag'] for row in fresh['inbounds']],
                         ['vless-in', 'never-seen-in'])
        self.assertEqual(fresh['inbounds'][1]['quality'], 'unavailable')
        stale = projection_from_tracker(tracker, pairs, now=1004.0,
                                        stale=True, last_success=1000)
        # A stale monitor cannot vouch for a tag it never observed: the row is
        # omitted (the consumer fills missing expected tags as unavailable).
        self.assertEqual([row['inbound_tag'] for row in stale['inbounds']],
                         ['vless-in'])
        self.assertTrue(all(row['quality'] == 'partial'
                            for row in stale['inbounds']))
        self.assertEqual(stale['active_connections'], 1)
        rev7_validate(build_document(stale, source_epoch='cd' * 16,
                                     sequence=0, generated_at=1004))

    def test_rate_sample_requires_an_update_and_sets_window(self):
        tracker = tracker_with_traffic()
        before = projection_from_tracker(tracker, ('vless-in:reality',),
                                         now=1003.0, last_success=1000)
        self.assertIsNone(before['inbounds'][0]['uplink_observed_rate_bps'])
        self.assertIsNone(before['rate_window_seconds'])
        tracker.apply_batch({'reset': False, 'events': [
            {'type': 'UPDATE', 'id': 'r1', 'uplink_delta': 300,
             'downlink_delta': 700}]}, 1002.0)
        after = projection_from_tracker(tracker, ('vless-in:reality',),
                                        now=1003.0, last_success=1002)
        self.assertEqual(after['inbounds'][0]['uplink_observed_rate_bps'],
                         150.0)
        self.assertEqual(after['inbounds'][0]['downlink_observed_rate_bps'],
                         350.0)
        self.assertEqual(after['rate_window_seconds'], 2.0)

    def test_banked_closed_totals_are_exact_and_counted_once(self):
        tracker = Tracker()
        tracker.apply_batch({'reset': False, 'events': [
            {'type': 'NEW', 'id': 'c1', 'connection': {
                'id': 'c1', 'user': 'u', 'inbound': 'vless-in',
                'uplink_total': 100, 'downlink_total': 200}},
            {'type': 'NEW', 'id': 'c2', 'connection': {
                'id': 'c2', 'user': 'u', 'inbound': 'vless-in',
                'uplink_total': 7, 'downlink_total': 9}},
        ]}, 1000.0)
        tracker.apply_batch({'reset': False, 'events': [
            {'type': 'CLOSED', 'id': 'c1', 'closed_at': 1001},
            {'type': 'CLOSED', 'id': 'c1', 'closed_at': 1002}]}, 1002.0)
        projection = projection_from_tracker(tracker, ('vless-in:reality',),
                                             now=1005.0, last_success=1002)
        row = projection['inbounds'][0]
        self.assertEqual(row['observed_uplink_bytes'], 107)
        self.assertEqual(row['observed_downlink_bytes'], 209)
        self.assertEqual(row['active_connections'], 1)
        self.assertEqual(projection['active_connections'], 1)

    def test_export_traffic_is_read_only_for_the_snapshot(self):
        tracker = tracker_with_traffic()
        before = json.dumps(tracker.snapshot(1005.0), sort_keys=True)
        projection_from_tracker(tracker, ('vless-in:reality',))
        after = json.dumps(tracker.snapshot(1005.0), sort_keys=True)
        self.assertEqual(before, after)

    def test_document_from_real_projection_is_rev7_valid(self):
        tracker = tracker_with_traffic()
        tracker.apply_batch({'reset': False, 'events': [
            {'type': 'UPDATE', 'id': 'r1', 'uplink_delta': 300,
             'downlink_delta': 700}]}, 1002.0)
        projection = projection_from_tracker(
            tracker, ('vless-in:reality', 'hy2-in:hysteria2'),
            now=1003.0, last_success=1002)
        document = build_document(projection, source_epoch='ab' * 16,
                                  sequence=0, generated_at=1004)
        rev7_validate(document)


class DocumentBuilderTests(unittest.TestCase):
    def build(self, projection=None, **overrides):
        projection = clean_projection(inbounds=[clean_row()]) \
            if projection is None else projection
        arguments = {'source_epoch': 'ab' * 16, 'sequence': 0,
                     'generated_at': 1000}
        arguments.update(overrides)
        return build_document(projection, **arguments)

    def test_exact_key_allow_list(self):
        document = self.build()
        self.assertEqual(set(document), REV7_TOP_KEYS)
        self.assertEqual(set(document['inbounds'][0]), REV7_ROW_KEYS)
        raw = json.dumps(document)
        self.assertNotIn('user', raw)
        self.assertNotIn('source_ip', raw)
        self.assertNotIn('connection_id', raw)

    def test_unknown_projection_and_row_fields_rejected(self):
        projection = clean_projection(inbounds=[clean_row()])
        projection['user'] = SENTINEL_USER
        with self.assertRaises(TrafficExportDocumentError):
            self.build(projection)
        row = clean_row()
        row['source'] = SENTINEL_SOURCE
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(inbounds=[row]))

    def test_observed_at_clamped_below_generated_at(self):
        projection = clean_projection(now=5000,
                                      inbounds=[clean_row(observed_at=5000)])
        document = self.build(projection, generated_at=4000)
        self.assertEqual(document['observed_at'], 4000)
        self.assertEqual(document['inbounds'][0]['observed_at'], 4000)
        rev7_validate(document)

    def test_last_success_clamped_and_required_when_fresh(self):
        projection = clean_projection(last_success=9999)
        document = self.build(projection, generated_at=4000)
        self.assertLessEqual(document['monitor_last_success_at'], 4000)
        fresh_without_success = clean_projection(stale=False)
        fresh_without_success['monitor_last_success_at'] = None
        with self.assertRaises(TrafficExportDocumentError):
            self.build(fresh_without_success)

    def test_safe_integer_bound_is_enforced_not_rounded(self):
        projection = clean_projection(
            inbounds=[clean_row(uplink=SAFE + 1)])
        with self.assertRaises(TrafficExportDocumentError):
            self.build(projection)
        projection = clean_projection(inbounds=[clean_row(uplink=SAFE)])
        self.assertEqual(
            self.build(projection)['inbounds'][0]['observed_uplink_bytes'],
            SAFE)

    def test_negative_or_float_counters_rejected(self):
        for bad in (-1, 1.5, '12', True):
            with self.assertRaises(TrafficExportDocumentError, msg=repr(bad)):
                self.build(clean_projection(
                    inbounds=[clean_row(uplink=bad)]))

    def test_stale_document_only_allows_partial_rows(self):
        # stale + partial with counters is the only stale row shape (the
        # rev-7 consumer refuses lower_bound and unavailable rows when stale).
        projection = clean_projection(
            stale=True, inbounds=[clean_row(quality='partial')])
        rev7_validate(self.build(projection))
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(
                stale=True, inbounds=[clean_row()]))  # lower_bound
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(
                stale=True, inbounds=[clean_row(
                    uplink=None, downlink=None, quality='unavailable')]))
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(
                stale=True, rate_window_seconds=2.0,
                inbounds=[clean_row(up_rate=1.0, quality='partial')]))

    def test_quality_coherence_rules(self):
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(inbounds=[clean_row(
                uplink=None, quality='lower_bound')]))
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(inbounds=[clean_row(
                quality='unavailable')]))
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(inbounds=[clean_row(
                uplink=None, downlink=None, quality='partial')]))

    def test_rate_without_window_rejected_and_bounds(self):
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(
                rate_window_seconds=None,
                inbounds=[clean_row(up_rate=1.0)]))
        document = self.build(clean_projection(
            rate_window_seconds=2.0, inbounds=[clean_row(up_rate=1.0)]))
        rev7_validate(document)
        for bad in (0, -1, 3600.5, float('inf'), float('nan')):
            with self.assertRaises(TrafficExportDocumentError, msg=repr(bad)):
                self.build(clean_projection(rate_window_seconds=bad,
                                            inbounds=[clean_row()]))

    def test_source_epoch_strictness(self):
        for bad in ('', 'A' * 32, 'a' * 31, 'a' * 33, 'g' * 32, None):
            with self.assertRaises(TrafficExportDocumentError, msg=repr(bad)):
                self.build(source_epoch=bad)

    def test_duplicate_tags_and_too_many_inbounds_rejected(self):
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(
                inbounds=[clean_row(), clean_row(active=0)]))
        too_many = [clean_row(tag='t%d' % i) for i in range(MAX_INBOUNDS + 1)]
        with self.assertRaises(TrafficExportDocumentError):
            self.build(clean_projection(inbounds=too_many))

    def test_sequence_must_be_non_negative_int(self):
        for bad in (-1, 1.5, True, '0'):
            with self.assertRaises(TrafficExportDocumentError, msg=repr(bad)):
                self.build(sequence=bad)


class WriterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.directory = self.temp.name
        self.path = os.path.join(self.directory, 'traffic.json')
        self.specs = spec_pairs('vless-in:reality', 'hy2-in:hysteria2')

    def tearDown(self):
        self.temp.cleanup()

    def writer(self, clock=None, epoch=None):
        return TrafficExportWriter(
            self.path, self.specs,
            clock=clock or FakeClock(1000.0), source_epoch=epoch)

    def projection(self, now=1000, **overrides):
        values = clean_projection(
            now=now, last_success=now - 1,
            inbounds=[clean_row(observed_at=int(now))])
        values.update(overrides)
        return values

    def leftover_temps(self):
        return glob.glob(os.path.join(self.directory, '.traffic-export-*'))

    def test_publish_writes_complete_document_mode_0640(self):
        writer = self.writer().prepare()
        document = writer.publish(self.projection())
        self.assertEqual(document['sequence'], 0)
        with open(self.path, 'rb') as handle:
            raw = handle.read()
        self.assertTrue(raw.endswith(b'\n'))
        stored = json.loads(raw)
        self.assertEqual(set(stored), REV7_TOP_KEYS)
        rev7_validate(stored)
        self.assertEqual(self.leftover_temps(), [])
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(os.stat(self.path).st_mode), 0o640)

    def test_sequence_monotonic_and_epoch_random_per_writer(self):
        writer = self.writer().prepare()
        sequences = []
        for index in range(3):
            writer.publish(self.projection(now=1000 + index),
                           now=1000 + index)
            sequences.append(read_document(self.path)['sequence'])
        self.assertEqual(sequences, [0, 1, 2])
        second = TrafficExportWriter(self.path, self.specs,
                                     clock=FakeClock(2000.0))
        self.assertNotEqual(writer.source_epoch, second.source_epoch)
        self.assertRegex(writer.source_epoch, r'^[0-9a-f]{32}$')
        self.assertRegex(second.source_epoch, r'^[0-9a-f]{32}$')

    def test_prepare_removes_stale_file_and_new_epoch(self):
        with open(self.path, 'w') as handle:
            handle.write('{"stale":"previous-process"}')
        writer = self.writer().prepare()
        self.assertFalse(os.path.exists(self.path))
        writer.publish(self.projection())
        stored = read_document(self.path)
        self.assertEqual(stored['source_epoch'], writer.source_epoch)
        self.assertNotIn('previous-process', read_bytes(self.path).decode())

    def test_prepare_fails_closed_when_stale_file_cannot_be_removed(self):
        with open(self.path, 'w') as handle:
            handle.write('{}')
        writer = self.writer()
        with patch('export.writer.os.unlink', side_effect=OSError('denied')):
            with self.assertRaises(TrafficExportConfigError):
                writer.prepare()
        self.assertFalse(writer.prepared)

    def test_failed_replace_keeps_previous_complete_file_and_sequence(self):
        writer = self.writer().prepare()
        writer.publish(self.projection(now=1000), now=1000)
        before = read_bytes(self.path)
        with patch('export.writer.os.replace', side_effect=OSError('disk')):
            with self.assertRaises(OSError):
                writer.publish(self.projection(now=1001), now=1001)
        self.assertEqual(read_bytes(self.path), before)
        self.assertEqual(writer._sequence, 1)
        self.assertEqual(self.leftover_temps(), [])
        writer.publish(self.projection(now=1002), now=1002)
        self.assertEqual(read_document(self.path)['sequence'], 1)

    def test_oversized_document_fails_closed(self):
        writer = self.writer().prepare()
        with patch('export.writer.MAX_EXPORT_BYTES', 64):
            with self.assertRaises(TrafficExportDocumentError):
                writer.publish(self.projection())
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(self.leftover_temps(), [])
        self.assertEqual(writer._sequence, 0)

    def test_document_stays_within_bounds_with_max_inbounds(self):
        specs = parse_inbound_specs(['inbound-%d:other' % i
                                     for i in range(MAX_INBOUNDS)])
        writer = TrafficExportWriter(self.path, specs,
                                     clock=FakeClock(1000.0)).prepare()
        rows = [clean_row(tag='inbound-%d' % i, kind='other',
                          uplink=SAFE, downlink=SAFE)
                for i in range(MAX_INBOUNDS)]
        writer.publish(clean_projection(
            inbounds=rows, active_connections=MAX_INBOUNDS, last_success=999))
        self.assertLessEqual(os.path.getsize(self.path), MAX_EXPORT_BYTES)
        stored = read_document(self.path)
        rev7_validate(stored)

    def test_constructor_and_prepare_reject_symlinks(self):
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, 'real.json')
            with open(target, 'w') as handle:
                handle.write('{}')
            link = os.path.join(directory, 'link.json')
            try:
                os.symlink(target, link)
            except (OSError, NotImplementedError):
                self.skipTest('symlink creation not permitted here')
            with self.assertRaises(TrafficExportConfigError):
                TrafficExportWriter(link, self.specs)
            writer = self.writer()
            writer.path = link
            with self.assertRaises(TrafficExportConfigError):
                writer.prepare()

    def test_disabled_means_no_writer_and_no_file(self):
        self.assertFalse(os.path.exists(self.path))
        # Constructing nothing is the disabled mode; the CLI path is covered by
        # the real-server subprocess test below.
        self.assertEqual(os.listdir(self.directory), [])

    def test_bounded_queue_drops_older_pending_projection(self):
        writer = self.writer().prepare()
        self.assertTrue(writer.submit(self.projection(now=1000)))
        self.assertTrue(writer.submit(self.projection(now=1001)))
        self.assertEqual(writer.dropped_count, 1)
        self.assertEqual(writer._queue.qsize(), 1)
        writer._stop.set()
        self.assertFalse(writer.submit(self.projection(now=1002)))

    def test_writer_thread_publishes_and_stops_cleanly(self):
        writer = self.writer().prepare()
        writer.start()
        try:
            writer.submit(self.projection(now=1000))
            deadline = time.time() + 8.0
            while time.time() < deadline and writer.published_count < 1:
                time.sleep(0.02)
            self.assertGreaterEqual(writer.published_count, 1)
            self.assertTrue(writer.running())
            stored = read_document(self.path)
            rev7_validate(stored)
        finally:
            self.assertTrue(writer.stop())
        self.assertFalse(writer.running())

    def test_publish_errors_are_contained_and_rate_limited(self):
        clock = FakeClock(1000.0)
        writer = self.writer(clock=clock).prepare()
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            writer._record_error(RuntimeError('a'))
            writer._record_error(RuntimeError('b'))
            clock.value += 61.0
            writer._record_error(RuntimeError('c'))
        lines = [line for line in buffer.getvalue().splitlines() if line]
        self.assertEqual(len(lines), 2)  # first + one after the interval
        self.assertEqual(writer.error_count, 3)
        self.assertEqual(writer.last_error_kind, 'RuntimeError')
        self.assertNotIn('RuntimeError: b', '\n'.join(lines))  # no message leak

    @unittest.skipUnless(os.name == 'posix', 'atomic rename visibility on POSIX')
    def test_concurrent_readers_never_observe_partial_json(self):
        writer = self.writer().prepare()
        writer.publish(self.projection(now=1000), now=1000)
        errors = []
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                try:
                    with open(self.path, 'rb') as handle:
                        data = handle.read()
                    document = json.loads(data)
                    if set(document) != REV7_TOP_KEYS:
                        errors.append('incomplete keys')
                except FileNotFoundError:
                    errors.append('missing file')
                except ValueError as exc:  # partial/torn JSON
                    errors.append('torn: %s' % exc)

        threads = [threading.Thread(target=reader) for _ in range(3)]
        for thread in threads:
            thread.start()
        try:
            for index in range(60):
                writer.publish(self.projection(now=1000 + index),
                               now=1000 + index)
        finally:
            stop.set()
            for thread in threads:
                thread.join(timeout=10)
        self.assertEqual(errors, [])

    def test_rev7_consumer_accepts_every_produced_shape(self):
        writer = self.writer().prepare()
        # fresh + lower_bound
        writer.publish(self.projection(now=1000), now=1000)
        # stale + partial counters
        stale_projection = clean_projection(
            now=1001, stale=True, last_success=999,
            inbounds=[clean_row(observed_at=1001, quality='partial')])
        writer.publish(stale_projection, now=1001)
        # fully unavailable tag
        unavailable = clean_projection(
            now=1002, last_success=1001,
            inbounds=[clean_row(uplink=None, downlink=None, active=0,
                                quality='unavailable', observed_at=1002)])
        writer.publish(unavailable, now=1002)
        stored = read_document(self.path)
        rev7_validate(stored)
        self.assertEqual(stored['sequence'], 2)


class BrokerTests(unittest.TestCase):
    def make_collector(self):
        batch = {'reset': True, 'events': [{'type': 'NEW', 'id': 'c1',
            'connection': {'id': 'c1', 'user': SENTINEL_USER,
                           'inbound': 'vless-in', 'source': SENTINEL_SOURCE,
                           'destination': SENTINEL_DEST, 'uplink_total': 100,
                           'downlink_total': 200}}]}

        def factory():
            yield batch
            raise RuntimeError('EOF')

        return Collector(url='http://127.0.0.1:1',
                         stream_factory=factory)

    def wait_for(self, predicate, timeout=10.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return True
            time.sleep(0.02)
        return False

    def test_broker_hands_only_sanitized_projection_to_writer(self):
        class CapturingWriter:
            def __init__(self):
                self.inbounds = spec_pairs('vless-in:reality')
                self.projected = []

            def submit(self, projection):
                self.projected.append(projection)
                return True

        writer = CapturingWriter()
        broker = SnapshotBroker(self.make_collector(), poll_seconds=0.05,
                                traffic_export_writer=writer)
        broker.start()
        try:
            self.assertTrue(self.wait_for(lambda: bool(writer.projected)))
            projection = writer.projected[-1]
            self.assertEqual(set(projection), {
                'observed_at', 'monitor_stale', 'monitor_last_success_at',
                'active_connections', 'rate_window_seconds', 'inbounds'})
            raw = json.dumps(projection)
            for sentinel in (SENTINEL_USER, SENTINEL_SOURCE, SENTINEL_DEST,
                             'c1', '"devices"', '"connections"',
                             '"last_error"', '"user"', '"source"'):
                self.assertNotIn(sentinel, raw)
        finally:
            broker.stop()

    def test_broker_export_failure_never_kills_publisher(self):
        class ExplodingWriter:
            inbounds = spec_pairs('vless-in:reality')

            def submit(self, projection):
                raise RuntimeError('export exploded')

        broker = SnapshotBroker(self.make_collector(), poll_seconds=0.05,
                                traffic_export_writer=ExplodingWriter())
        broker.start()
        try:
            self.assertTrue(broker.wait_for_snapshot(timeout=10.0))
            first = broker.snapshot_json()[0]
            self.assertTrue(self.wait_for(
                lambda: broker.snapshot_json()[0] > first))
            self.assertTrue(broker._publisher_alive())
            self.assertTrue(broker._consumer_alive())
            snapshot = broker.snapshot()
            self.assertIn('devices', snapshot)
            self.assertIn('snapshot_version', snapshot)
        finally:
            broker.stop()

    def test_broker_export_projection_exception_is_contained(self):
        collector = self.make_collector()
        collector.tracker.export_traffic = lambda *args, **kwargs: (
            _raise('projection exploded'))

        def _raise(message):
            raise RuntimeError(message)

        class Writer:
            inbounds = spec_pairs('vless-in:reality')

            def __init__(self):
                self.submitted = 0

            def submit(self, projection):
                self.submitted += 1
                return True

        writer = Writer()
        broker = SnapshotBroker(collector, poll_seconds=0.05,
                                traffic_export_writer=writer)
        broker.start()
        try:
            self.assertTrue(broker.wait_for_snapshot(timeout=10.0))
            first = broker.snapshot_json()[0]
            self.assertTrue(self.wait_for(
                lambda: broker.snapshot_json()[0] > first))
            self.assertEqual(writer.submitted, 0)
            self.assertTrue(broker._publisher_alive())
        finally:
            broker.stop()

    def test_no_writer_means_no_projection_call_at_all(self):
        collector = self.make_collector()
        calls = []
        collector.tracker.export_traffic = lambda *args, **kwargs: calls.append(1)
        broker = SnapshotBroker(collector, poll_seconds=0.05)
        broker.start()
        try:
            self.assertTrue(broker.wait_for_snapshot(timeout=10.0))
            first = broker.snapshot_json()[0]
            self.assertTrue(self.wait_for(
                lambda: broker.snapshot_json()[0] > first + 2))
            self.assertEqual(calls, [])
        finally:
            broker.stop()

    def test_snapshot_shape_unchanged_with_writer_configured(self):
        class CapturingWriter:
            inbounds = spec_pairs('vless-in:reality')

            def submit(self, projection):
                return True

        plain = SnapshotBroker(self.make_collector(), poll_seconds=0.05)
        with_export = SnapshotBroker(self.make_collector(), poll_seconds=0.05,
                                     traffic_export_writer=CapturingWriter())
        plain.start()
        with_export.start()
        try:
            self.assertTrue(plain.wait_for_snapshot(timeout=10.0))
            self.assertTrue(with_export.wait_for_snapshot(timeout=10.0))
            # Both publishers must have consumed the same reset batch before
            # the state comparison can be meaningful.
            self.assertTrue(self.wait_for(
                lambda: bool(plain.snapshot().get('devices'))))
            self.assertTrue(self.wait_for(
                lambda: bool(with_export.snapshot().get('devices'))))
            plain_view = plain.snapshot()
            export_view = with_export.snapshot()
            for field in ('monitor_started_at', 'snapshot_generated_at',
                          'collector_uptime_seconds', 'last_publish_at',
                          'snapshot_version', 'generated_at',
                          'last_success_at'):
                plain_view.pop(field, None)
                export_view.pop(field, None)
            self.assertEqual(set(plain_view), set(export_view))
            self.assertEqual(plain_view['active_connections'],
                             export_view['active_connections'])
            self.assertEqual(plain_view['batch_count'],
                             export_view['batch_count'])
            self.assertEqual(set(plain_view['devices']),
                             set(export_view['devices']))
            for name in plain_view['devices']:
                plain_device = plain_view['devices'][name]
                export_device = export_view['devices'][name]
                self.assertEqual(set(plain_device['protocols']),
                                 set(export_device['protocols']))
                self.assertEqual(plain_device['status'],
                                 export_device['status'])
                self.assertEqual(plain_device['active_connections'],
                                 export_device['active_connections'])
                for total in ('uplink_total', 'downlink_total'):
                    self.assertEqual(plain_device[total],
                                     export_device[total])
                    for protocol in plain_device['protocols']:
                        self.assertEqual(
                            plain_device['protocols'][protocol][total],
                            export_device['protocols'][protocol][total])
            self.assertEqual(
                [row['id'] for row in plain_view['connections']],
                [row['id'] for row in export_view['connections']])
        finally:
            plain.stop()
            with_export.stop()


class RealServerTests(unittest.TestCase):
    """The REAL webapp.py serve subprocess: default-disabled / enabled."""

    def free_port(self):
        sock = socket.socket()
        try:
            sock.bind(('127.0.0.1', 0))
            return sock.getsockname()[1]
        finally:
            sock.close()

    def start_serve(self, workdir, export_args, port):
        data_dir = os.path.join(workdir, 'data')
        command = [sys.executable, WEBAPP, 'serve', '--listen', '127.0.0.1',
                   '--port', str(port), '--url', 'http://127.0.0.1:1',
                   '--data-dir', data_dir, '--poll', '0.2'] + export_args
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            cwd=str(ROOT))
        return process

    def wait_dashboard(self, port, timeout=20.0):
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        'http://127.0.0.1:%d/' % port, timeout=1.0) as response:
                    if response.status == 200:
                        return True
            except OSError:
                time.sleep(0.1)
        return False

    def stop(self, process):
        process.terminate()
        try:
            process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=10)

    def test_disabled_serve_creates_no_export_file_and_keeps_dashboard(self):
        with tempfile.TemporaryDirectory() as workdir:
            export_path = os.path.join(workdir, 'export', 'traffic.json')
            os.makedirs(os.path.dirname(export_path))
            port = self.free_port()
            process = self.start_serve(workdir, [], port)
            try:
                self.assertTrue(self.wait_dashboard(port), 'dashboard did not start')
                time.sleep(0.8)
                self.assertFalse(os.path.exists(export_path),
                                 'disabled export created a file')
                self.assertIsNone(process.poll())
            finally:
                self.stop(process)

    def test_enabled_serve_publishes_valid_export_and_keeps_dashboard(self):
        with tempfile.TemporaryDirectory() as workdir:
            export_path = os.path.join(workdir, 'export', 'traffic.json')
            os.makedirs(os.path.dirname(export_path))
            # A leftover file from a previous process must be removed on
            # startup and replaced by a fresh source_epoch document.
            with open(export_path, 'w') as handle:
                handle.write('{"schema":"stale-previous-process"}')
            port = self.free_port()
            process = self.start_serve(workdir, [
                '--traffic-export-file', export_path,
                '--traffic-export-inbound', 'vless-in:reality',
                '--traffic-export-inbound', 'hy2-in:hysteria2'], port)
            try:
                self.assertTrue(self.wait_dashboard(port), 'dashboard did not start')
                deadline = time.time() + 15.0
                document = None
                while time.time() < deadline:
                    if os.path.exists(export_path):
                        try:
                            with open(export_path) as handle:
                                document = json.load(handle)
                            if document.get('schema') == \
                                    'singbox-monitor-traffic-export' and \
                                    isinstance(document.get('sequence'), int) \
                                    and document['sequence'] >= 0:
                                break
                        except ValueError:
                            document = None
                    time.sleep(0.1)
                self.assertIsNotNone(document)
                rev7_validate(document)
                # dead service.api -> monitor stale, never a fake fresh zero;
                # a stale monitor omits tagged rows it never observed.
                self.assertTrue(document['monitor_stale'])
                self.assertIsNone(document['monitor_last_success_at'])
                self.assertEqual(document['inbounds'], [])
                self.assertEqual(document['active_connections'], 0)
                # dashboard stays alive while the export is enabled
                self.assertEqual(process.poll(), None)
                with urllib.request.urlopen(
                        'http://127.0.0.1:%d/' % port, timeout=2.0) as response:
                    self.assertEqual(response.status, 200)
            finally:
                self.stop(process)

    def test_startup_config_errors_fail_closed(self):
        with tempfile.TemporaryDirectory() as workdir:
            data_dir = os.path.join(workdir, 'data')
            base = [sys.executable, WEBAPP, 'serve', '--listen', '127.0.0.1',
                    '--port', str(self.free_port()), '--url',
                    'http://127.0.0.1:1', '--data-dir', data_dir]
            relative = subprocess.run(
                base + ['--traffic-export-file', 'relative.json',
                        '--traffic-export-inbound', 'vless-in:reality'],
                capture_output=True, timeout=60, cwd=str(ROOT))
            self.assertEqual(relative.returncode, 2)
            self.assertIn(b'ABSOLUTE', relative.stderr)
            no_inbound = subprocess.run(
                base + ['--traffic-export-file',
                        os.path.join(workdir, 'traffic.json')],
                capture_output=True, timeout=60, cwd=str(ROOT))
            self.assertEqual(no_inbound.returncode, 2)
            self.assertIn(b'required', no_inbound.stderr)
            orphan_inbound = subprocess.run(
                base + ['--traffic-export-inbound', 'vless-in:reality'],
                capture_output=True, timeout=60, cwd=str(ROOT))
            self.assertEqual(orphan_inbound.returncode, 2)
            missing_parent = subprocess.run(
                base + ['--traffic-export-file',
                        os.path.join(workdir, 'no-such-dir', 'traffic.json'),
                        '--traffic-export-inbound', 'vless-in:reality'],
                capture_output=True, timeout=60, cwd=str(ROOT))
            self.assertEqual(missing_parent.returncode, 2)
            self.assertIn(b'parent directory', missing_parent.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
