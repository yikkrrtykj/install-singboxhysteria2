"""OPTIONAL restricted traffic export for the local Linux Go Agent (UM-LT).

The monitor-v2 web runtime (``webapp.py serve`` -> Collector -> SnapshotBroker)
can publish a bounded, sanitized, atomically replaced JSON document that the
local agent reads as a PLAIN FILE. It never exposes the sing-box ``service.api``
secret or raw Monitor state (no connection ids, users, source/destination
addresses, proxy names, config or secrets); the document is aggregate counters
for an operator-declared inbound allow-list only.

Default DISABLED: without the operator argv flags no writer exists, no thread
starts and no file is read/written/created. This package is pure stdlib.
"""

from .contract import (COUNTER_SCOPE, EXACTNESS, EXPORT_KEYS, INBOUND_KEYS,
                       KINDS, KIND_HYSTERIA2, KIND_OTHER, KIND_REALITY,
                       MAX_EXPORT_BYTES, MAX_INBOUNDS, PROJECTION_KEYS,
                       QUALITIES, QUALITY_LOWER_BOUND, QUALITY_PARTIAL,
                       QUALITY_UNAVAILABLE, SAFE_INT_MAX, SCHEMA,
                       SCHEMA_VERSION, SOURCE, InboundSpec,
                       TrafficExportConfigError,
                       TrafficExportDocumentError, build_document,
                       parse_inbound_specs, validate_export_path)
from .writer import (FINAL_FILE_MODE, TrafficExportWriter, encode_document)

__all__ = [
    "COUNTER_SCOPE", "EXACTNESS", "EXPORT_KEYS", "INBOUND_KEYS", "KINDS",
    "KIND_HYSTERIA2", "KIND_OTHER", "KIND_REALITY", "MAX_EXPORT_BYTES",
    "MAX_INBOUNDS", "PROJECTION_KEYS", "QUALITIES", "QUALITY_LOWER_BOUND",
    "QUALITY_PARTIAL", "QUALITY_UNAVAILABLE", "SAFE_INT_MAX", "SCHEMA",
    "SCHEMA_VERSION", "SOURCE", "InboundSpec", "TrafficExportConfigError",
    "TrafficExportDocumentError", "build_document", "parse_inbound_specs",
    "validate_export_path", "FINAL_FILE_MODE", "TrafficExportWriter",
    "encode_document",
]
