#!/usr/bin/env python3
"""Phase A evidence analyzer for the sing-box API feasibility question.

Everything here is derived mechanically from captured API responses:

* the meaning of the byte counters is inferred from which counter grows while a
  transfer of known size and known direction runs -- no field name is hard-coded
  to a human meaning;
* the user/attribution field is discovered by looking for a key whose value
  equals one of the configured probe user names;
* direction verdicts follow a strict-evidence policy: each transfer must be
  backed by its own curl evidence files (<label>-curl.json / .err / .rc) with
  exit code 0, HTTP 200 and actually-moved bytes within tolerance of the
  request. There is NO fallback to meta.payload_bytes -- that value is the
  requested test size and may only be displayed, never used as evidence;
* when no runtime snapshot is available every item reports
  "NOT TESTED / WAITING FOR RUNTIME DATA" instead of a verdict.

Snapshots carrying the ``_fixture`` marker are synthetic and are ignored unless
``--fixture-mode`` is given; in that mode the report is banner-marked as
synthetic so it can never be mistaken for runtime evidence.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys

NOT_TESTED = "NOT TESTED / WAITING FOR RUNTIME DATA"
SYNTHETIC_BANNER = "SYNTHETIC FIXTURE OUTPUT - NOT RUNTIME DATA (validates derivation math only)"
FIXTURE_MARKER = "_fixture"
TOLERANCE = 0.85
BIDIRECTIONAL_NOISE = 0.20
# A direction verdict requires the actually-transferred bytes to fall within this
# window of the requested bytes: <= 90% or >= 110% must never produce VERIFIED.
CURL_SIZE_FLOOR = 0.98
CURL_SIZE_CEILING = 1.02

STATUS_ORDER = ["FAILED", "NO", "INCONCLUSIVE", "PARTIAL", "VERIFIED", NOT_TESTED]

IPV4 = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IPV6 = re.compile(r"^[0-9A-Fa-f:]*:[0-9A-Fa-f:]+$")
LOOPBACK_PREFIXES = ("127.", "::1", "::ffff:127.")


def load_json(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return json.load(handle), None
    except FileNotFoundError:
        return None, "missing"
    except Exception as exc:  # any unreadable snapshot is simply "no data"
        return None, "unreadable: %s" % exc


def read_text(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read(), None
    except FileNotFoundError:
        return None, "missing"
    except Exception as exc:  # noqa: BLE001
        return None, "unreadable: %s" % exc


def is_fixture(obj):
    return isinstance(obj, dict) and FIXTURE_MARKER in obj


def ip_like(value):
    return isinstance(value, str) and bool(IPV4.match(value) or IPV6.match(value))


def is_loopback(value):
    return isinstance(value, str) and value.startswith(LOOPBACK_PREFIXES)


def numeric(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def tag_matches(value, tag):
    """Accept both a bare tag and the "type/tag" shape some APIs report."""
    if not isinstance(value, str) or not tag:
        return False
    if value == tag:
        return True
    return value.split("/")[-1] == tag


def conn_flat(conn):
    """Flatten one level of nesting: enough for every known connection shape."""
    flat = {}
    for key, value in conn.items():
        if isinstance(value, dict):
            for sub, subval in value.items():
                flat["%s.%s" % (key, sub)] = subval
        else:
            flat[key] = value
    return flat


class CurlTransfer:
    """Strict, machine-checked evidence for one curl transfer.

    Three files must back a transfer before any verdict may use its bytes:

    * ``<label>-curl.json`` -- the machine-readable ``curl -w`` result carrying
      ``requested_bytes`` / ``bytes_downloaded`` / ``bytes_uploaded`` / ``http_code``;
    * ``<label>-curl.err`` -- curl's stderr, kept separate so it can never corrupt
      the JSON;
    * ``<label>-curl.rc``  -- curl's exit code.

    A transfer is ``ok`` only when exit code == 0, HTTP code == 200 and the
    actually-transferred bytes are within tolerance of the requested bytes.
    ``meta.payload_bytes`` is NEVER a fallback here: it only states what size the
    test *asked* for and may at most be displayed as the expected size.
    """

    def __init__(self, label, edir, fixture_mode=False):
        self.label = label
        self.json_path = os.path.join(edir, "%s-curl.json" % label)
        self.err_path = os.path.join(edir, "%s-curl.err" % label)
        self.rc_path = os.path.join(edir, "%s-curl.rc" % label)
        self.exit_code = None
        self.http_code = None
        self.requested = None
        self.actual = None
        self.byte_field = None
        self.reasons = []
        self._load(fixture_mode)

    def _load(self, fixture_mode):
        rc_text, rc_error = read_text(self.rc_path)
        rc_stripped = rc_text.strip() if rc_text is not None else ""
        if rc_error is None and rc_stripped.isdigit():
            self.exit_code = int(rc_stripped)
            if self.exit_code != 0:
                self.reasons.append("curl exit code=%d (要求 0)" % self.exit_code)
        else:
            self.reasons.append("curl exit code 证据缺失或不可读 (%s-curl.rc %s)"
                                % (self.label, rc_error or "not an integer"))
        raw, error = load_json(self.json_path)
        if error is not None or not isinstance(raw, dict):
            self.reasons.append("curl JSON 不可解析 (%s-curl.json: %s)"
                                % (self.label, error or "not an object"))
            return
        if is_fixture(raw) and not fixture_mode:
            self.reasons.append("合成 curl fixture 已忽略（未开启 --fixture-mode）")
            return
        http = raw.get("http_code")
        self.http_code = float(http) if numeric(http) else None
        if self.http_code != 200:
            self.reasons.append("HTTP code=%s (要求 200)" % http)
        req = raw.get("requested_bytes")
        self.requested = float(req) if numeric(req) and req > 0 else None
        for key in ("bytes_downloaded", "bytes_uploaded"):
            value = raw.get(key)
            if numeric(value) and value > 0:
                self.actual = float(value)
                self.byte_field = key
                break
        if self.actual is None:
            self.reasons.append("curl 未报告实际传输字节 (size_download/size_upload)")
        elif self.requested is None:
            self.reasons.append("curl 未报告 requested_bytes，无法核对实际传输量")
        elif self.actual < self.requested * CURL_SIZE_FLOOR:
            self.reasons.append("实际传输 %.0fB 明显小于请求 %.0fB（仅 %.1f%%，"
                                "允许误差 %.0f%%–%.0f%%）"
                                % (self.actual, self.requested,
                                   100.0 * self.actual / self.requested,
                                   100.0 * CURL_SIZE_FLOOR, 100.0 * CURL_SIZE_CEILING))
        elif self.actual > self.requested * CURL_SIZE_CEILING:
            self.reasons.append("实际传输 %.0fB 明显大于请求 %.0fB（%.1f%%，"
                                "允许误差 %.0f%%–%.0f%%）"
                                % (self.actual, self.requested,
                                   100.0 * self.actual / self.requested,
                                   100.0 * CURL_SIZE_FLOOR, 100.0 * CURL_SIZE_CEILING))

    @property
    def ok(self):
        return not self.reasons

    def files(self):
        return sorted(os.path.basename(p) for p in (self.json_path, self.err_path, self.rc_path))

    def as_dict(self):
        return {
            "label": self.label,
            "ok": self.ok,
            "exit_code": self.exit_code,
            "http_code": self.http_code,
            "requested_bytes": self.requested,
            "actual_bytes": self.actual,
            "byte_field": self.byte_field,
            "reasons": list(self.reasons),
            "files": self.files(),
        }


class Snapshot:
    def __init__(self, evidence_dir, label, fixture_mode):
        self.label = label
        self.path = os.path.join(evidence_dir, "%s.connections.json" % label)
        raw, error = load_json(self.path)
        self.error = error
        self.fixture = is_fixture(raw)
        self.raw = raw if isinstance(raw, dict) else {}
        self.api_error = self.raw.get("_probe_api_error")
        if self.fixture and not fixture_mode:
            self.error = self.error or "synthetic fixture ignored (pass --fixture-mode)"
            self.raw = {}
            self.api_error = None
        connections = self.raw.get("connections")
        self.connections = [c for c in connections if isinstance(c, dict)] if isinstance(connections, list) else []

    @property
    def usable(self):
        return self.error is None and self.api_error is None

    @classmethod
    def synthetic(cls, label, connections, raw=None):
        """View over an already loaded snapshot with a subset of connections."""
        obj = cls.__new__(cls)
        obj.label = label
        obj.path = ""
        obj.error = None
        obj.fixture = False
        obj.api_error = None
        obj.raw = raw if isinstance(raw, dict) else {}
        obj.connections = list(connections)
        return obj

    def why_unusable(self):
        if self.error:
            return self.error
        if self.api_error:
            return str(self.api_error)
        return "no data"

    def counters(self):
        out = {}
        for key, value in self.raw.items():
            if numeric(value):
                out["root.%s" % key] = float(value)
        sums = {}
        for conn in self.connections:
            for key, value in conn.items():
                if numeric(value):
                    sums[key] = sums.get(key, 0.0) + float(value)
        for key, value in sums.items():
            out["conn_sum.%s" % key] = value
        return out

    def flat_union(self):
        union = {}
        for conn in self.connections:
            for key, value in conn_flat(conn).items():
                union.setdefault(key, []).append(value)
        return union

    def by_tag(self, tag_key, tag):
        if tag_key is None:
            return list(self.connections)
        return [c for c in self.connections if tag_matches(conn_flat(c).get(tag_key), tag)]


class Row:
    def __init__(self, item, status, detail, evidence=(), extra=None):
        self.item = item
        self.status = status
        self.detail = detail
        self.evidence = list(evidence)
        self.extra = extra or {}

    def sort_key(self):
        try:
            return STATUS_ORDER.index(self.status)
        except ValueError:
            return len(STATUS_ORDER)

    def as_dict(self):
        return {
            "item": self.item,
            "status": self.status,
            "detail": self.detail,
            "evidence": self.evidence,
            "extra": self.extra,
        }


def max_counter_deltas(before, samples):
    """Delta of the largest value each counter reached across the samples.

    Cumulative counters end at their maximum, and per-connection counters are only
    visible while the connection lives -- taking the maximum over the samples taken
    during (and just after) the transfer covers both without depending on a
    post-transfer snapshot.
    """
    base = before.counters()
    peak = {}
    for snap in samples:
        for key, value in snap.counters().items():
            if value > peak.get(key, float("-inf")):
                peak[key] = value
    return {key: value - base.get(key, 0.0) for key, value in peak.items()}


def largest_growth(delta_map):
    positives = [(k, v) for k, v in delta_map.items() if v > 0]
    if not positives:
        return None, 0.0
    return max(positives, key=lambda kv: kv[1])


def counter_name(key):
    """Drop the origin prefix so root.x and conn_sum.x can be compared."""
    return key.split(".", 1)[1] if "." in key else key


def counter_family(key):
    """Normalise a counter name to its direction family.

    The same measurement can be reported as ``downloadTotal`` at the response root
    and as ``download`` per connection, so both have to collapse to one family --
    otherwise the reverse-direction noise check would flag a single-direction
    transfer as bidirectional.
    """
    name = counter_name(key).lower()
    for suffix in ("total", "sum"):
        if name.endswith(suffix) and len(name) > len(suffix):
            name = name[: -len(suffix)]
    return name


def family_keys(keys, key):
    family = counter_family(key)
    return {k for k in keys if counter_family(k) == family}


def magnitude_match(delta_map, expected, exclude=()):
    best = None
    for key, value in delta_map.items():
        if key in exclude or value <= 0:
            continue
        if expected > 0 and value >= expected * TOLERANCE:
            score = abs(value - expected)
            if best is None or score < best[1]:
                best = (key, score, value)
    if best is None:
        key, value = largest_growth(delta_map)
        return key, value, False
    return best[0], best[2], True


def name_perspective(key):
    lowered = key.lower()
    if "down" in lowered or "recv" in lowered:
        return "downish"
    if "up" in lowered or "sent" in lowered:
        return "upish"
    return "unknown"


def discover_key(snapshots, predicate):
    hits = {}
    for snap in snapshots:
        if not snap.usable:
            continue
        for key, values in snap.flat_union().items():
            for value in values:
                if predicate(value):
                    hits.setdefault(key, set()).add(value)
    return hits


class Analyzer:
    def __init__(self, args):
        self.args = args
        self.edir = args.evidence_dir
        meta, _ = load_json(os.path.join(self.edir, "meta.json"))
        self.meta = meta if isinstance(meta, dict) else {}
        self.user_a = self.meta.get("user_a", "probe-a")
        self.user_b = self.meta.get("user_b", "probe-b")
        self.users = {self.user_a, self.user_b}
        self.payload = int(self.meta.get("payload_bytes", args.bytes or 67108864))
        self.reality_tag = self.meta.get("reality_tag", "probe-reality-in")
        self.hy2_tag = self.meta.get("hy2_tag", "probe-hy2-in")
        self.proto_tags = {"reality": self.reality_tag, "hy2": self.hy2_tag}
        self.fixture_mode = args.fixture_mode
        labels = ["version-prep"]
        for proto in ("reality", "hy2"):
            for suffix in ("dl-pre", "dl-closed", "ul-pre", "ul-closed",
                           "ab-pre", "ab-closed"):
                labels.append("%s-%s" % (proto, suffix))
        labels.append("final-idle")
        self.snaps = {label + ".connections": Snapshot(self.edir, label, self.fixture_mode) for label in labels}
        known = {os.path.basename(s.path) for s in self.snaps.values()}
        self.extras = []
        try:
            for name in sorted(os.listdir(self.edir)):
                if name.endswith(".connections.json") and name not in known:
                    self.extras.append(Snapshot(self.edir, name[: -len(".connections.json")], self.fixture_mode))
        except OSError:
            pass
        self.rows = []
        self.notes = []
        self._curl_cache = {}

    def snap(self, label):
        return self.snaps[label + ".connections"]

    def runtime_present(self, snapshots=None):
        pool = snapshots if snapshots is not None else list(self.snaps.values())
        return any(s.usable and s.connections for s in pool)

    def filtered_view(self, snapshots, tag_key, tag):
        """Snapshots reduced to this inbound's connections, skipping empty ones."""
        out = []
        for snap in snapshots:
            if not snap.usable:
                continue
            conns = snap.by_tag(tag_key, tag) if tag_key else list(snap.connections)
            if conns:
                out.append(Snapshot.synthetic(snap.label, conns, snap.raw))
        return out

    def evidence_names(self, snapshots):
        return sorted({os.path.basename(s.path) for s in snapshots if s.path})

    def all_snapshots(self):
        return list(self.snaps.values()) + list(self.extras)

    def samples(self, proto, kind):
        """In-transfer samples of one test, e.g. samples('reality', 'dl')."""
        rx = re.compile(r"^%s-%s-s\d+$" % (re.escape(proto), re.escape(kind)))
        return sorted((s for s in self.all_snapshots() if rx.match(s.label) and s.usable),
                      key=lambda s: s.label)

    def last_active(self, proto, kind):
        pool = [s for s in self.samples(proto, kind) if s.connections]
        return pool[-1] if pool else None

    def curl_transfer(self, label):
        """Strict evidence for one transfer, read once and cached."""
        if label not in self._curl_cache:
            self._curl_cache[label] = CurlTransfer(label, self.edir, self.fixture_mode)
        return self._curl_cache[label]

    def any_fixture(self):
        return [s.label for s in self.snaps.values() if s.fixture]

    # ------------------------------------------------------------- global rows ---

    def endpoint_row(self, item, filename, endpoint):
        raw, error = load_json(os.path.join(self.edir, filename))
        if isinstance(raw, dict) and raw:
            if is_fixture(raw) and not self.fixture_mode:
                self.rows.append(Row(item, NOT_TESTED,
                                     "%s 是合成 fixture，已忽略（未开启 --fixture-mode）" % filename))
            else:
                self.rows.append(Row(item, "VERIFIED",
                                     "%s 可读，keys=%s" % (endpoint, ",".join(sorted(raw)[:8])),
                                     [filename]))
        else:
            self.rows.append(Row(item, NOT_TESTED, "%s 未采集到: %s" % (endpoint, error or "empty")))

    def global_rows(self):
        self.endpoint_row("api.version", "00-api-version.json", "/version")
        self.endpoint_row("api.traffic", "version-prep.traffic.json", "/traffic")
        self.endpoint_row("api.memory", "version-prep.memory.json", "/memory")

        schema_pool = [s for s in self.all_snapshots() if s.usable and s.connections]
        if schema_pool:
            response_keys = sorted({k for s in schema_pool for k in s.raw})
            conn_keys = set()
            meta_keys = set()
            for snap in schema_pool:
                for conn in snap.connections:
                    for key, value in conn.items():
                        if isinstance(value, dict):
                            for sub in value:
                                meta_keys.add("%s.%s" % (key, sub))
                        else:
                            conn_keys.add(key)
            self.rows.append(Row("schema.response_keys", "VERIFIED",
                                 "/connections 响应顶层 keys: %s" % ", ".join(response_keys)))
            self.rows.append(Row("schema.connection_keys", "VERIFIED",
                                 "connection 顶层 keys: %s" % ", ".join(sorted(conn_keys))))
            self.rows.append(Row("schema.metadata_keys", "VERIFIED",
                                 "connection 嵌套字段 keys (%d): %s"
                                 % (len(meta_keys), ", ".join(sorted(meta_keys)))))
        else:
            for item in ("schema.response_keys", "schema.connection_keys", "schema.metadata_keys"):
                self.rows.append(Row(item, NOT_TESTED, "无活动连接快照，无法枚举 schema"))

    def production_untouched_row(self):
        before = os.path.join(self.edir, "00-production-before.txt")
        after = os.path.join(self.edir, "90-production-after.txt")
        if not (os.path.exists(before) and os.path.exists(after)):
            self.rows.append(Row("probe.production_untouched", NOT_TESTED,
                                 "缺少 before/after 基线文件，未验证"))
            return
        try:
            with open(before, encoding="utf-8") as fh:
                b_lines = [l.strip() for l in fh if l.strip() and "listening_ports" not in l and not l.startswith("  ")]
            with open(after, encoding="utf-8") as fh:
                a_lines = {l.strip() for l in fh}
        except Exception as exc:  # noqa: BLE001
            self.rows.append(Row("probe.production_untouched", NOT_TESTED, "基线文件不可读: %s" % exc))
            return
        drift = [l for l in b_lines if l not in a_lines]
        if drift:
            self.rows.append(Row("probe.production_untouched", "FAILED",
                                 "生产基线出现变化: %s" % " | ".join(drift),
                                 [os.path.basename(before), os.path.basename(after)]))
        else:
            self.rows.append(Row("probe.production_untouched", "VERIFIED",
                                 "生产版本/服务状态/config 与 sbconfig_server.json 的 sha256 未变化",
                                 [os.path.basename(before), os.path.basename(after)]))

    # ---------------------------------------------------------- protocol rows ---

    def protocol_rows(self, proto):
        tag = self.proto_tags.get(proto, "")
        dl_pre = self.snap("%s-dl-pre" % proto)
        ab_pre = self.snap("%s-ab-pre" % proto)
        ul_pre = self.snap("%s-ul-pre" % proto)
        dl_closed = self.snap("%s-dl-closed" % proto)
        dl_samples = self.samples(proto, "dl")
        ul_samples = self.samples(proto, "ul")
        ab_samples = self.samples(proto, "ab")
        active_samples = [s for s in dl_samples + ul_samples + ab_samples if s.connections]

        # Active-transfer samples come first: user / inbound / source-IP evidence has
        # to come from a moment when this inbound actually had connections.
        ordered = active_samples + [dl_pre, ab_pre] + list(self.extras)
        tag_hits = discover_key(ordered, lambda v: tag_matches(v, tag))
        tag_key = sorted(tag_hits)[0] if tag_hits else None
        dl_peak = max(dl_samples, key=lambda s: len(s.connections), default=dl_pre)
        ab_peak = max(ab_samples, key=lambda s: len(s.connections), default=ab_pre)

        # --- source IP ---------------------------------------------------------
        # Extra snapshots (e.g. collected after external clients ran) are folded in
        # here: that is the only way a public source address can ever be observed.
        ip_pool = self.filtered_view([dl_peak, ab_peak] + list(self.extras), tag_key, tag)
        ip_hits = discover_key(ip_pool, ip_like)
        source_keys = [k for k in ip_hits if "source" in k.lower() or k.lower().startswith("src")]
        if not ip_pool:
            self.rows.append(Row("%s.source_ip" % proto, NOT_TESTED,
                                 "无活动连接快照: %s" % dl_peak.why_unusable()))
        elif not ip_hits:
            self.rows.append(Row("%s.source_ip" % proto, "NO",
                                 "NO - 未在任何 connection 字段中发现 IP 形态取值；已检查字段: %s"
                                 % ", ".join(sorted({k for s in ip_pool for k in s.flat_union()}))))
        else:
            non_loop = sorted({v for k in source_keys for v in ip_hits[k] if not is_loopback(v)})
            all_vals = sorted({v for k in (source_keys or list(ip_hits)) for v in ip_hits[k]})
            detail = "source 类字段=%s 取值=%s" % (",".join(source_keys) or "(未识别 source 前缀)",
                                                  ",".join(all_vals[:6]))
            if non_loop:
                self.rows.append(Row("%s.source_ip" % proto, "VERIFIED",
                                     "VERIFIED - %s；含非回环地址 %s"
                                     % (detail, ",".join(non_loop[:3])),
                                     self.evidence_names(ip_pool)))
            else:
                self.rows.append(Row("%s.source_ip" % proto, "PARTIAL",
                                     "PARTIAL - %s；仅在回环下观测（公网源 IP 未验证，"
                                     "需外部客户端并重新 --collect）" % detail,
                                     self.evidence_names(ip_pool)))

        # --- inbound -----------------------------------------------------------
        if not self.runtime_present(ordered):
            self.rows.append(Row("%s.inbound" % proto, NOT_TESTED, "无活动连接快照"))
        elif tag_key:
            values = sorted({str(conn_flat(c).get(tag_key)) for s in active_samples + [dl_peak, ab_peak]
                             for c in s.by_tag(tag_key, tag)})
            self.rows.append(Row("%s.inbound" % proto, "VERIFIED",
                                 "字段 %s 取值 %s（期望 tag %s）"
                                 % (tag_key, ",".join(values), tag),
                                 self.evidence_names(active_samples or [dl_peak])))
        else:
            self.rows.append(Row("%s.inbound" % proto, "NO",
                                 "NO - 未找到取值等于 %s 的字段；无法从 API 区分该 inbound" % tag,
                                 self.evidence_names(active_samples or [dl_peak])))

        # --- user attribution --------------------------------------------------
        conns_for_proto = dl_peak.by_tag(tag_key, tag) if tag_key else list(dl_peak.connections)
        ab_conns = ab_peak.by_tag(tag_key, tag) if tag_key else list(ab_peak.connections)
        user_pool = self.filtered_view([ab_peak, dl_peak] + active_samples + list(self.extras), tag_key, tag)
        user_hits = discover_key(user_pool, lambda v: isinstance(v, str) and v in self.users)
        if not self.runtime_present(user_pool):
            self.rows.append(Row("%s.user_field" % proto, NOT_TESTED,
                                 "%s - 无活动连接快照，inbound user 未验证" % NOT_TESTED))
        elif not (conns_for_proto or ab_conns):
            self.rows.append(Row("%s.user_field" % proto, NOT_TESTED,
                                 "%s - 未捕获到该 inbound 的连接" % NOT_TESTED))
        elif user_hits:
            key = sorted(user_hits, key=lambda k: -len(user_hits[k]))[0]
            values = sorted(user_hits[key])
            ab_users = {conn_flat(c).get(key) for c in ab_conns
                        if isinstance(conn_flat(c).get(key), str) and conn_flat(c).get(key) in self.users}
            label = "YES" if ab_users == self.users else ("PARTIAL" if ab_users else "NO")
            status = "VERIFIED" if label == "YES" else ("PARTIAL" if label == "PARTIAL" else "NO")
            self.rows.append(Row("%s.user_field" % proto, status,
                                 "%s - 字段名 %s，观测取值 %s；并发归因快照命中 %s"
                                 % (label, key, ",".join(values), ",".join(sorted(ab_users)) or "(none)"),
                                 self.evidence_names([ab_peak, dl_peak])))
        else:
            candidate_keys = sorted({k for s in user_pool if s.usable for k in s.flat_union()})
            self.rows.append(Row("%s.user_field" % proto, "NO",
                                 "NO - 全字段扫描未发现任何字段的取值等于 %s；已检查 %d 个字段，"
                                 "该 inbound 观测到 %d 条连接"
                                 % ("/".join(sorted(self.users)), len(candidate_keys), len(conns_for_proto)),
                                 self.evidence_names([ab_peak, dl_peak])))

        # --- direction ---------------------------------------------------------
        # Strict-evidence mode. A VERIFIED/PARTIAL verdict is only allowed when BOTH
        # transfers are backed by complete curl evidence (exit code 0, HTTP 200 and
        # actually-moved bytes within tolerance of the request) AND in-transfer
        # connection sampling exists. meta.payload_bytes is display-only here: it is
        # the requested test size and NEVER substitutes for measured bytes.
        if not dl_pre.usable or not dl_samples:
            self.rows.append(Row("%s.direction" % proto, NOT_TESTED,
                                 "缺少客户端下载期间的活动采样（pre=%s, samples=%d）"
                                 % (dl_pre.why_unusable(), len(dl_samples))))
        elif not ul_pre.usable or not ul_samples:
            self.rows.append(Row("%s.direction" % proto, NOT_TESTED,
                                 "缺少客户端上传期间的活动采样（pre=%s, samples=%d）"
                                 % (ul_pre.why_unusable(), len(ul_samples))))
        else:
            dl_evi = self.curl_transfer("%s-dl" % proto)
            ul_evi = self.curl_transfer("%s-ul" % proto)
            curl_extra = {"meta_payload_bytes_display": self.payload,
                          "meta_payload_bytes_role": "期望测试大小（仅显示），不作为传输证据",
                          "download_curl": dl_evi.as_dict(),
                          "upload_curl": ul_evi.as_dict()}
            if not dl_evi.ok or not ul_evi.ok:
                self.rows.append(Row(
                    "%s.direction" % proto, "INCONCLUSIVE",
                    "INCONCLUSIVE - download: %s；upload: %s"
                    "（不回退到 meta.payload_bytes；严格证据条件: curl exit code=0、"
                    "HTTP 200、实测字节≈requested_bytes 三者缺一不可）"
                    % ("；".join(dl_evi.reasons) or "证据完整",
                       "；".join(ul_evi.reasons) or "证据完整"),
                    dl_evi.files() + ul_evi.files()
                    + self.evidence_names(dl_samples + ul_samples),
                    curl_extra))
            else:
                dl_delta = max_counter_deltas(dl_pre, dl_samples)
                ul_delta = max_counter_deltas(ul_pre, ul_samples)
                exp_dl, src_dl = dl_evi.actual, "curl %s" % dl_evi.byte_field
                exp_ul, src_ul = ul_evi.actual, "curl %s" % ul_evi.byte_field
                recv_key, recv_val, recv_ok = magnitude_match(dl_delta, exp_dl)
                send_key, send_val, send_ok = magnitude_match(ul_delta, exp_ul)
                # Reverse-direction noise = the counter family that the upload test
                # identified as client->server grew during the client-download test.
                reverse_seen = max((dl_delta.get(k, 0.0) for k in family_keys(dl_delta, send_key)),
                                   default=0.0)
                extra = dict(curl_extra)
                extra.update({"download_test_deltas": dl_delta, "upload_test_deltas": ul_delta,
                              "download_samples": len(dl_samples), "upload_samples": len(ul_samples),
                              "expected_download_bytes": exp_dl, "expected_upload_bytes": exp_ul,
                              "expected_basis": {"download": src_dl, "upload": src_ul}})
                if not recv_ok or not send_ok:
                    self.rows.append(Row("%s.direction" % proto, "INCONCLUSIVE",
                                         "INCONCLUSIVE - 未找到与实测流量匹配的计数器增量；"
                                         "下载 %.0fB 期间最大增长 %s=%s，上传 %.0fB 期间最大增长 %s=%s"
                                         % (exp_dl, recv_key, recv_val, exp_ul, send_key, send_val),
                                         self.evidence_names(dl_samples + ul_samples),
                                         extra))
                elif recv_key == send_key:
                    self.rows.append(Row("%s.direction" % proto, "INCONCLUSIVE",
                                         "INCONCLUSIVE - 同一個计数器 %s 在两个方向都增长，无法归因方向" % recv_key,
                                         self.evidence_names(dl_samples + ul_samples), extra))
                else:
                    lines = [
                        "客户端下载 %.0fB（基准=%s，%d 个活动采样）期间 %s 峰值增长 %.0f"
                        " -> 语义=客户端下行(服务器->客户端)" % (exp_dl, src_dl, len(dl_samples), recv_key, recv_val),
                        "客户端上传 %.0fB（基准=%s，%d 个活动采样）期间 %s 峰值增长 %.0f"
                        " -> 语义=客户端上行(客户端->服务器)" % (exp_ul, src_ul, len(ul_samples), send_key, send_val),
                    ]
                    perspective = name_perspective(recv_key)
                    if perspective == "downish":
                        lines.append("字段命名与客户端视角一致: 下行计数器名为 %s" % recv_key)
                        status = "VERIFIED"
                    elif perspective == "upish":
                        lines.append("字段命名与客户端视角相反: 下行计数器名为 %s（upload/sent 类）"
                                     "-> 渲染时必须对调" % recv_key)
                        status = "VERIFIED"
                    else:
                        lines.append("字段命名无法判断视角（%s），方向语义以上面的实测增量结论为准" % recv_key)
                        status = "PARTIAL"
                    if reverse_seen >= exp_dl * BIDIRECTIONAL_NOISE:
                        lines.append("注意: 反向计数器 %s 族同时增长 %.0f，测试可能不是单向的"
                                     % (counter_family(send_key), reverse_seen))
                        status = "PARTIAL"
                    self.rows.append(Row("%s.direction" % proto, status, " | ".join(lines),
                                         dl_evi.files() + ul_evi.files()
                                         + self.evidence_names([dl_pre] + dl_samples + [ul_pre] + ul_samples),
                                         extra))

        # --- connection granularity -------------------------------------------
        if not self.runtime_present(dl_samples + ab_samples):
            self.rows.append(Row("%s.connection_granularity" % proto, NOT_TESTED,
                                 "无活动连接采样（dl=%d, ab=%d）" % (len(dl_samples), len(ab_samples))))
        else:
            single = max((len(s.by_tag(tag_key, tag)) for s in dl_samples), default=0)
            pair = max((len(s.by_tag(tag_key, tag)) for s in ab_samples), default=0)
            status = "VERIFIED" if (single == 1 and pair == 2) else "PARTIAL"
            self.rows.append(Row("%s.connection_granularity" % proto, status,
                                 "单流峰值 %d 条连接（期望 1）；双用户并发峰值 %d 条（期望 2）"
                                 % (single, pair),
                                 self.evidence_names([dl_peak, ab_peak])))

        # --- connection close behaviour ---------------------------------------
        # The only row allowed to look at the post-transfer snapshot.
        last_active = self.last_active(proto, "dl")
        if last_active is None or not dl_closed.usable:
            self.rows.append(Row("%s.connection_close" % proto, NOT_TESTED,
                                 "缺少最后一个活动采样或 closed 快照（closed=%s）" % dl_closed.why_unusable()))
        else:
            active_ids = [c.get("id") for c in last_active.connections if isinstance(c.get("id"), str)]
            closed_ids = {c.get("id") for c in dl_closed.connections if isinstance(c.get("id"), str)}
            if not active_ids:
                self.rows.append(Row("%s.connection_close" % proto, "PARTIAL",
                                     "未发现连接 id 字段，无法判断关闭后是否从列表消失；"
                                     "closed 快照连接数=%d" % len(dl_closed.connections)))
            else:
                lingering = [i for i in active_ids if i in closed_ids]
                if lingering:
                    self.rows.append(Row("%s.connection_close" % proto, "PARTIAL",
                                         "传输结束后 %d/%d 条连接仍在列表中"
                                         % (len(lingering), len(active_ids)),
                                         self.evidence_names([last_active, dl_closed])))
                else:
                    self.rows.append(Row("%s.connection_close" % proto, "VERIFIED",
                                         "传输结束后 %d 条连接均已从列表消失；closed 快照剩余连接 %d 条"
                                         % (len(active_ids), len(dl_closed.connections)),
                                         self.evidence_names([last_active, dl_closed])))

    # ---------------------------------------------------------------- render ---

    def payload_rows(self):
        """Prove every transfer moved exactly the number of bytes that was asked for.

        This is what makes the half-payload attribution test meaningful: probe-a and
        probe-b must each have moved half, and the direction tests the full size.
        Only complete strict curl evidence counts (rc=0, HTTP 200, bytes parsed);
        a transfer with failed evidence is reported, never silently accepted.
        """
        checks = []
        for proto in ("reality", "hy2"):
            for label, expected in (("%s-dl" % proto, self.payload),
                                    ("%s-ul" % proto, self.payload),
                                    ("%s-ab-a" % proto, self.payload // 2),
                                    ("%s-ab-b" % proto, self.payload // 2)):
                checks.append((label, expected, self.curl_transfer(label)))
        present = [c for c in checks if c[2].actual is not None]
        if not present:
            self.rows.append(Row("payload.matches_request", NOT_TESTED,
                                 "没有 curl 实测字节数（未运行传输，或 curl 证据不可用）"))
            return
        bad = [c for c in present
               if not c[2].ok or not (c[1] * 0.99 <= c[2].actual <= c[1] * 1.01)]
        if bad:
            self.rows.append(Row("payload.matches_request", "NO",
                                 "NO - 实际传输字节与请求不一致或 curl 证据不完整: %s"
                                 % "; ".join("%s: %s" % (l, "；".join(e.reasons) or
                                                        "请求 %d 实测 %.0f" % (exp, e.actual))
                                             for l, exp, e in bad)))
        elif len(present) < len(checks):
            self.rows.append(Row("payload.matches_request", "PARTIAL",
                                 "部分传输缺少 curl 实测（%d/%d）"
                                 % (len(present), len(checks))))
        else:
            self.rows.append(Row("payload.matches_request", "VERIFIED",
                                 "全部传输 curl 证据完整（exit code=0、HTTP 200）且实际字节与请求一致"
                                 "（含 probe-a/probe-b 各 half）: %s"
                                 % "; ".join("%s 请求 %d 实测 %.0f" % (l, exp, e.actual)
                                             for l, exp, e in present)))

    def run(self):
        self.global_rows()
        self.payload_rows()
        for proto in ("reality", "hy2"):
            self.protocol_rows(proto)
        self.production_untouched_row()
        return self.rows

    def notes_section(self):
        return [
            "API 能被非 root 读取，只能证明业务监控的字节数据源可以降权，以及可以去掉 conntrack / nf_conntrack_acct。",
            "如果将来仍需要 Reality TCP RTT/retrans，ss 继续作为只读辅助数据源保留，不要因为 API 可用就提前删除。",
            "本工具是开发/诊断工具，不属于 Monitor v2，不会被安装器自动安装到用户服务器。",
            "结论仅对本次采集时的 sing-box 版本与配置有效，版本见 api.version 与 00-production-before.txt。",
            "source IP 与 user 归因的最终判定需要外部客户端（不同公网出口 / 同一 NAT 后两个具名用户）。",
            "TODO(enhancement, 不阻塞本机 Phase A): 外部测试时支持 expected source IP 参数，"
            "并对 API 观测到的 sourceIP 做机械精确比对（API sourceIP == expected IP 才判 VERIFIED）；"
            "当前 source_ip 行只区分回环/非回环，公网源 IP 的精确一致性验证留待外部测试阶段实现。",
        ]

    def summary_text(self):
        lines = []
        if self.fixture_mode:
            lines += [SYNTHETIC_BANNER, ""]
        width = max((len(r.item) for r in self.rows), default=20)
        lines.append("%-*s  %-11s %s" % (width, "ITEM", "STATUS", "VERDICT / DETAIL"))
        lines.append("%s  %s %s" % ("-" * width, "-" * 11, "-" * 60))
        for row in self.rows:
            detail = row.detail
            if len(detail) > 150:
                detail = detail[:147] + "..."
            lines.append("%-*s  %-11s %s" % (width, row.item, row.status, detail))
        lines.append("")
        lines.append("NOTES")
        for note in self.notes_section():
            lines.append("  - " + note)
        return "\n".join(lines) + "\n"

    def md_text(self):
        out = ["# Phase A - sing-box API feasibility report", ""]
        if self.fixture_mode:
            out += ["> **%s**" % SYNTHETIC_BANNER, ""]
        out += ["Generated: %s" % _now(), ""]
        meta_lines = ["| key | value |", "| --- | --- |"]
        for key in ("production_version", "expose", "reality_port", "hy2_port", "clash_api",
                    "reality_tag", "hy2_tag", "user_a", "user_b", "payload_bytes"):
            meta_lines.append("| %s | %s |" % (key, self.meta.get(key, "(unknown)")))
        out += ["## Collection context", ""] + meta_lines + [""]
        out += ["## Result table", "", "| item | status | detail |", "| --- | --- | --- |"]
        for row in self.rows:
            out.append("| `%s` | %s | %s |" % (row.item, row.status, row.detail.replace("|", "\\|")))
        out.append("")
        out += ["## Evidence files", ""]
        for row in self.rows:
            if row.evidence:
                out.append("- `%s`: %s" % (row.item, ", ".join("`%s`" % e for e in row.evidence)))
        out.append("")
        out += ["## Raw counter deltas", "", "```json",
                json.dumps({r.item: r.extra for r in self.rows if r.extra}, indent=2, sort_keys=True), "```", ""]
        out += ["## Standing notes", ""] + ["- " + n for n in self.notes_section()] + [""]
        return "\n".join(out) + "\n"


def _now():
    import datetime
    return datetime.datetime.now().isoformat(timespec="seconds")


# ------------------------------------------------------------------- commands ---

def cmd_keys(path):
    raw, error = load_json(path)
    if error:
        print("unreadable: %s" % error)
        return 1
    if not isinstance(raw, dict):
        print("unexpected root type")
        return 1
    print("# /connections response top-level keys")
    for key in sorted(raw):
        print("root.%s" % key)
    print("# connection top-level keys")
    conn_keys = set()
    meta_keys = set()
    connections = raw.get("connections")
    if isinstance(connections, list):
        for conn in connections:
            if not isinstance(conn, dict):
                continue
            for key, value in conn.items():
                if isinstance(value, dict):
                    for sub in value:
                        meta_keys.add("%s.%s" % (key, sub))
                else:
                    conn_keys.add(key)
    for key in sorted(conn_keys):
        print("conn.%s" % key)
    print("# connection nested keys")
    for key in sorted(meta_keys):
        print("conn.%s" % key)
    return 0


def cmd_count(path):
    raw, error = load_json(path)
    if error or not isinstance(raw, dict):
        print("0")
        return 0
    connections = raw.get("connections")
    print(len(connections) if isinstance(connections, list) else 0)
    return 0


def cmd_getkey(path, key):
    raw, error = load_json(path)
    if error or not isinstance(raw, dict):
        return 1
    value = raw.get(key)
    if value is None:
        return 1
    print(value)
    return 0


def cmd_prod_ports(path):
    """Read-only listing of the production inbound ports, for collision checks."""
    raw, error = load_json(path)
    if error or not isinstance(raw, dict):
        return 1
    ports = []
    for inbound in raw.get("inbounds") or []:
        if isinstance(inbound, dict) and isinstance(inbound.get("listen_port"), int):
            ports.append(inbound["listen_port"])
    print(" ".join(str(port) for port in ports))
    return 0


def cmd_prod_server_ip(path):
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("SERVER_IP="):
                    print(line.split("=", 1)[1].strip().strip("'\""))
                    return 0
    except Exception:  # noqa: BLE001
        return 1
    return 1


def _int(value, default=0):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _sha256(path):
    try:
        import hashlib
        with open(path, "rb") as handle:
            return hashlib.sha256(handle.read()).hexdigest()
    except Exception:  # noqa: BLE001
        return ""


def _manifest_values(args):
    return {
        "probe_root": args.probe_root,
        "expose": str(_int(args.expose)),
        "reality_port": str(_int(args.reality_port)),
        "hy2_port": str(_int(args.hy2_port)),
        "clash_port": str(_int(args.clash_port)),
        "sink_port": str(_int(args.sink_port)),
        "public_ip": args.public_ip,
        "payload_bytes": str(_int(args.payload_bytes)),
        "transfer_rate": str(_int(args.transfer_rate)),
    }


def add_manifest_args(parser):
    parser.add_argument("--out")
    parser.add_argument("--manifest")
    parser.add_argument("--probe-root", default="")
    parser.add_argument("--expose", default="0")
    parser.add_argument("--reality-port", default="")
    parser.add_argument("--hy2-port", default="")
    parser.add_argument("--clash-port", default="")
    parser.add_argument("--sink-port", default="")
    parser.add_argument("--public-ip", default="")
    parser.add_argument("--payload-bytes", default="")
    parser.add_argument("--transfer-rate", default="")
    parser.add_argument("--probe-config", default="")


def cmd_write_manifest(args):
    """Record the parameters the generated probe config was built from."""
    data = _manifest_values(args)
    data["written_at"] = _now()
    data["probe_config"] = args.probe_config
    data["probe_config_sha256"] = _sha256(args.probe_config) if args.probe_config else ""
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    return 0


def cmd_check_manifest(args):
    """Exit 0 when the stored parameters still match, 1 with the diffs otherwise."""
    data, error = load_json(args.manifest)
    if error or not isinstance(data, dict):
        print("manifest unreadable: %s" % (error or "not an object"))
        return 1
    current = _manifest_values(args)
    diffs = ["%s(%s->%s)" % (key, data.get(key), value)
             for key, value in current.items() if str(data.get(key)) != value]
    if not args.probe_config or not os.path.isfile(args.probe_config):
        diffs.append("probe_config(missing)")
    elif data.get("probe_config_sha256") != _sha256(args.probe_config):
        diffs.append("probe_config(sha256 changed)")
    if diffs:
        print("stale: " + ", ".join(diffs))
        return 1
    print("current")
    return 0


def cmd_write_meta(args):
    """Write the expectation file the analyzer reads, so it is always valid JSON."""
    data = {
        "collected_at": _now(),
        "probe_root": args.probe_root,
        "production_version": args.production_version,
        "expose": _int(args.expose),
        "reality_port": _int(args.reality_port),
        "hy2_port": _int(args.hy2_port),
        "clash_api": args.clash_api,
        "reality_tag": args.reality_tag,
        "hy2_tag": args.hy2_tag,
        "user_a": args.user_a,
        "user_b": args.user_b,
        "payload_bytes": _int(args.payload_bytes, 67108864),
        "transfer_rate_bps": _int(args.transfer_rate, 4194304),
    }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(data, handle, ensure_ascii=False, indent=2)
    return 0


def cmd_analyze(args):
    if not os.path.isdir(args.evidence_dir):
        print("evidence dir not found: %s" % args.evidence_dir, file=sys.stderr)
        return 2
    analyzer = Analyzer(args)
    analyzer.run()

    fixtures = analyzer.any_fixture()
    if fixtures and not args.fixture_mode:
        print("note: %d synthetic fixture snapshot(s) ignored (pass --fixture-mode to use them)"
              % len(fixtures), file=sys.stderr)

    summary = analyzer.summary_text()
    payload = {
        "generated_at": _now(),
        "fixture_mode": args.fixture_mode,
        "synthetic": bool(args.fixture_mode),
        "meta": analyzer.meta,
        "rows": [r.as_dict() for r in analyzer.rows],
        "notes": analyzer.notes_section(),
    }
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
    if args.md_out:
        with open(args.md_out, "w", encoding="utf-8") as handle:
            handle.write(analyzer.md_text())
    summary_path = os.path.join(args.evidence_dir, "SUMMARY.txt")
    with open(summary_path, "w", encoding="utf-8") as handle:
        handle.write(summary)
    print(summary)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description="Phase A sing-box API evidence analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_keys = sub.add_parser("keys", help="dump root and connection key names")
    p_keys.add_argument("path")

    p_count = sub.add_parser("count", help="print number of connections in a snapshot")
    p_count.add_argument("path")

    p_get = sub.add_parser("getkey", help="read a value from the probe keys.json")
    p_get.add_argument("path")
    p_get.add_argument("key")

    p_ip = sub.add_parser("prod-server-ip", help="read SERVER_IP from the production state file")
    p_ip.add_argument("path")

    p_pp = sub.add_parser("prod-ports", help="read production inbound listen ports")
    p_pp.add_argument("path")

    p_meta = sub.add_parser("write-meta", help="write the expectation file for one collection run")
    p_meta.add_argument("--out", required=True)
    p_meta.add_argument("--probe-root", default="")
    p_meta.add_argument("--production-version", default="")
    p_meta.add_argument("--expose", default="0")
    p_meta.add_argument("--reality-port", default="18443")
    p_meta.add_argument("--hy2-port", default="18444")
    p_meta.add_argument("--clash-api", default="127.0.0.1:19090")
    p_meta.add_argument("--reality-tag", default="probe-reality-in")
    p_meta.add_argument("--hy2-tag", default="probe-hy2-in")
    p_meta.add_argument("--user-a", default="probe-a")
    p_meta.add_argument("--user-b", default="probe-b")
    p_meta.add_argument("--payload-bytes", default="67108864")
    p_meta.add_argument("--transfer-rate", default="4194304")

    p_wm = sub.add_parser("write-manifest", help="record the parameters used to generate the probe config")
    add_manifest_args(p_wm)

    p_cm = sub.add_parser("check-manifest", help="report whether the stored parameters still match")
    add_manifest_args(p_cm)

    p_an = sub.add_parser("analyze", help="derive the feasibility verdicts from captured evidence")
    p_an.add_argument("--evidence-dir", required=True)
    p_an.add_argument("--json-out")
    p_an.add_argument("--md-out")
    p_an.add_argument("--fixture-mode", action="store_true")
    p_an.add_argument("--bytes", type=int, default=None)

    args = parser.parse_args(argv)
    if args.cmd == "keys":
        return cmd_keys(args.path)
    if args.cmd == "count":
        return cmd_count(args.path)
    if args.cmd == "getkey":
        return cmd_getkey(args.path, args.key)
    if args.cmd == "prod-server-ip":
        return cmd_prod_server_ip(args.path)
    if args.cmd == "prod-ports":
        return cmd_prod_ports(args.path)
    if args.cmd == "write-meta":
        return cmd_write_meta(args)
    if args.cmd == "write-manifest":
        return cmd_write_manifest(args)
    if args.cmd == "check-manifest":
        return cmd_check_manifest(args)
    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
