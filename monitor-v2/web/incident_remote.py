"""Incident-bound P6C presentation. No History/classifier writes or imports.

GET /api/v1/incidents/<incident_id>/remote-probes presents retained facts.
Current source status and historical samples are deliberately separate. The
only evidence source is retained, authenticated samples, never tuple receipts.
Registry labels are current operator assertions; no IP-to-provider inference.
"""
from contextlib import nullcontext
import math
import time

from remote_probe.payload import validate_sample
from web.remote_registry import RegistryError
from web.remote_store import MAX_AGE_SECONDS, RemoteStoreError

ROW_LIMIT = 255  # existing store cap 256 permits one truncation witness
ROW_KEYS = ('sample_epoch', 'probe_id', 'dns', 'https', 'vps_tcp', 'egress',
            'mihomo_api', 'flags')
ACTIVE_KEYS = ('role', 'source', 'outcome', 'delay_ms', 'independent')


def incident_remote(plane, incident_id, start_epoch, end_epoch, now=None):
    """Closed, bounded response for the SERVER's stored analysis window.

    HTTP callers cannot supply bounds, limits or probe filters. Retention is
    enforced by the existing store before every read, including an idle read.
    A registry lifecycle fence prevents current labels changing across reads.
    """
    now = float(time.time() if now is None else now)
    if not all(type(x) in (int, float) and math.isfinite(x) and x >= 0
               for x in (start_epoch, end_epoch, now)) or end_epoch < start_epoch:
        raise ValueError('invalid incident window')
    result = {
        'v': 1, 'incident_id': incident_id,
        'window': {'start_epoch': start_epoch, 'end_epoch': end_epoch},
        'retention': {'max_age_seconds': MAX_AGE_SECONDS,
                      'retention_cutoff_epoch': max(0, now - MAX_AGE_SECONDS),
                      'retained_since_epoch': None, 'budget_pruned': False},
        'current_status': {'observed_epoch': now, 'status': 'not_configured',
                           'subcode': None, 'probes': []},
        'rows': [], 'truncated': False, 'limit': ROW_LIMIT,
    }
    if plane is None:
        return result
    registry = plane.registry
    fence = registry.live() if hasattr(registry, 'config_path') else nullcontext()
    try:
        with fence:
            status = plane.status()
            current = result['current_status']
            current.update(status=status['status'], subcode=status['subcode'])
            current['probes'] = [dict(probe_id=probe_id, **{
                key: row[key] for key in ('status', 'subcode', 'last_sample_epoch',
                                         'site_label', 'path_label')})
                for probe_id, row in sorted(status['probes'].items())]
            store_status = status['store']
            if store_status is not None:
                result['retention'].update(
                    retained_since_epoch=store_status['retained_since_epoch'],
                    budget_pruned=store_status['budget_pruned'])
            # Read historical evidence even after all mappings are retired;
            # a currently absent mapping must not erase retained samples.
            if status['subcode'] in ('remote_store_unavailable', 'remote_config_invalid'):
                return result
            read_start = max(start_epoch, result['retention']['retention_cutoff_epoch'])
            read_end = min(end_epoch, now)
            if read_start > read_end:
                return result
            rows = plane.read_samples(read_start, read_end, limit=ROW_LIMIT + 1)
            result['truncated'] = len(rows) > ROW_LIMIT
            for entry in rows[:ROW_LIMIT]:
                sample = entry['sample']
                # Reuse the admission schema before exposing nested slots;
                # malformed retained data must never leak extra fields.
                try:
                    invalid = validate_sample(sample)
                except (TypeError, ValueError, KeyError):
                    invalid = True
                if invalid:
                    raise RemoteStoreError('invalid retained sample')
                row = {key: sample[key] for key in ROW_KEYS}
                row.update(mapping_retired=entry['mapping_retired'],
                           site_label=entry['site_label'], path_label=entry['path_label'])
                row['active'] = [{key: item[key] for key in ACTIVE_KEYS}
                                 for item in sample['active']]
                result['rows'].append(row)
    except RegistryError:
        result['rows'] = []
        result['current_status'].update(status='degraded',
                                       subcode='remote_config_invalid', probes=[])
    except (RemoteStoreError, OSError):
        # Failure is remote-only and closed, never an apparently healthy empty
        # history; no raw filesystem path or exception message is returned.
        result['rows'] = []
        result['current_status'].update(status='degraded',
                                       subcode='remote_store_unavailable', probes=[])
    return result
