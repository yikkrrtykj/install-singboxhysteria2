#!/usr/bin/env python3
"""Phase A evidence analyzer for the sing-box API feasibility question.

Everything here is derived mechanically from captured API responses:

* the meaning of the byte counters is inferred from which counter grows while a
  transfer of known size and known direction runs -- no field name is hard-coded
  to a human meaning;
* the user/attribution field is discovered by looking for a key whose value
  equals one of the configured probe user names;
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


def counter_deltas(before, after):
    cb, ca = before.counters(), after.counters()
    out = {}
    for key in set(cb) | set(ca):
        out[key] = ca.get(key, 0.0) - cb.get(key, 0.0)
    return out


def largest_growth(delta_map):
    positives = [(k, v) for k, v in delta_map.items() if v > 0]
    if not positives:
        return None, 0.0
    return max(positives, key=lambda kv: kv[1])


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


def sample_connections(snap, limit=3):
    out = []
    for conn in snap.connections[:limit]:
        out.append(conn_flat(conn))
    return out


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
            for suffix in ("dl-pre", "dl-mid", "dl-post", "ul-pre", "ul-mid", "ul-post",
                           "ab-pre", "ab-mid", "ab-post", "final"):
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
        dl_pre, dl_mid, dl_post = (self.snap("%s-%s" % (proto, x)) for x in ("dl-pre", "dl-mid", "dl-post"))
        ul_pre, ul_post = (self.snap("%s-%s" % (proto, x)) for x in ("ul-pre", "ul-post"))
        ab_mid = self.snap("%s-ab-mid" % proto)
        final = self.snap("%s-final" % proto)

        active = [s for s in (dl_mid, ab_mid, dl_post, final) + tuple(self.extras) if s.usable and s.connections]
        tag_hits = discover_key(active, lambda v: tag_matches(v, tag))
        tag_key = sorted(tag_hits)[0] if tag_hits else None
        evidence_files = ["%s.connections.json" % s.label for s in (dl_mid, ab_mid, dl_post)]

        # --- source IP ---------------------------------------------------------
        # Extra snapshots (e.g. collected after external clients ran) are folded in
        # here: that is the only way a public source address can ever be observed.
        ip_pool = self.filtered_view([dl_mid, ab_mid] + self.extras, tag_key, tag)
        ip_hits = discover_key(ip_pool, ip_like)
        source_keys = [k for k in ip_hits if "source" in k.lower() or k.lower().startswith("src")]
        if not ip_pool:
            self.rows.append(Row("%s.source_ip" % proto, NOT_TESTED,
                                 "无活动连接快照: %s" % dl_mid.why_unusable()))
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
        if not self.runtime_present(active):
            self.rows.append(Row("%s.inbound" % proto, NOT_TESTED, "无活动连接快照"))
        elif tag_key:
            vals = sorted({conn_flat(c).get(tag_key) for c in dl_mid.by_tag(tag_key, tag)})
            self.rows.append(Row("%s.inbound" % proto, "VERIFIED",
                                 "字段 %s 取值 %s（期望 tag %s）" % (tag_key, ",".join(str(v) for v in vals), tag),
                                 evidence_files))
        else:
            self.rows.append(Row("%s.inbound" % proto, "NO",
                                 "NO - 未找到取值等于 %s 的字段；无法从 API 区分该 inbound" % tag,
                                 evidence_files))

        # --- user attribution --------------------------------------------------
        conns_for_proto = dl_mid.by_tag(tag_key, tag) if tag_key else list(dl_mid.connections)
        ab_conns = ab_mid.by_tag(tag_key, tag) if tag_key else list(ab_mid.connections)
        # Only connections of this inbound may be inspected, otherwise the other
        # inbound's snapshots would supply a field name that this one does not have.
        user_pool = self.filtered_view([ab_mid, dl_mid] + self.extras, tag_key, tag)
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
                                 ["%s.connections.json" % s.label for s in (ab_mid, dl_mid)]))
        else:
            candidate_keys = sorted({k for s in user_pool if s.usable for k in s.flat_union()})
            self.rows.append(Row("%s.user_field" % proto, "NO",
                                 "NO - 全字段扫描未发现任何字段的取值等于 %s；已检查 %d 个字段，"
                                 "该 inbound 观测到 %d 条连接"
                                 % ("/".join(sorted(self.users)), len(candidate_keys), len(conns_for_proto)),
                                 ["%s.connections.json" % s.label for s in (ab_mid, dl_mid)]))

        # --- direction ---------------------------------------------------------
        if not (dl_pre.usable and dl_post.usable and ul_pre.usable and ul_post.usable):
            missing = [s.label for s in (dl_pre, dl_post, ul_pre, ul_post) if not s.usable]
            self.rows.append(Row("%s.direction" % proto, NOT_TESTED,
                                 "缺少方向测试前后快照: %s" % ", ".join(missing),
                                 ["%s.connections.json" % s.label for s in (dl_pre, dl_post)]))
        else:
            dl_delta = counter_deltas(dl_pre, dl_post)
            ul_delta = counter_deltas(ul_pre, ul_post)
            recv_key, recv_val, recv_ok = magnitude_match(dl_delta, self.payload)
            send_key, send_val, send_ok = magnitude_match(ul_delta, self.payload)
            _, recv_second = largest_growth({k: v for k, v in dl_delta.items() if k != recv_key})
            extra = {"download_test_deltas": dl_delta, "upload_test_deltas": ul_delta}
            if not recv_ok or not send_ok:
                self.rows.append(Row("%s.direction" % proto, "INCONCLUSIVE",
                                     "INCONCLUSIVE - 未找到与已知流量 %dB 匹配的计数器增量；"
                                     "下载测试最大增长 %s=%s，上传测试最大增长 %s=%s"
                                     % (self.payload, recv_key, recv_val, send_key, send_val),
                                     ["%s-dl-*.connections.json" % proto, "%s-ul-*.connections.json" % proto],
                                     extra))
            elif recv_key == send_key:
                self.rows.append(Row("%s.direction" % proto, "INCONCLUSIVE",
                                     "INCONCLUSIVE - 同一個计数器 %s 在两个方向都增长，无法归因方向" % recv_key,
                                     [], extra))
            else:
                lines = [
                    "客户端下载 %dB 期间: %s 增长 %.0f -> 语义=客户端下行(服务器->客户端)" % (self.payload, recv_key, recv_val),
                    "客户端上传 %dB 期间: %s 增长 %.0f -> 语义=客户端上行(客户端->服务器)" % (self.payload, send_key, send_val),
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
                noise = recv_second if recv_second else 0.0
                if noise >= self.payload * BIDIRECTIONAL_NOISE:
                    lines.append("注意: 反向计数器同时增长 %.0f，测试可能不是单向的" % noise)
                    status = "PARTIAL"
                self.rows.append(Row("%s.direction" % proto, status, " | ".join(lines),
                                     ["%s-dl-pre.connections.json" % proto, "%s-dl-post.connections.json" % proto,
                                      "%s-ul-pre.connections.json" % proto, "%s-ul-post.connections.json" % proto],
                                     extra))

        # --- connection granularity -------------------------------------------
        if not self.runtime_present([dl_mid, ab_mid]):
            self.rows.append(Row("%s.connection_granularity" % proto, NOT_TESTED,
                                 "无活动连接快照"))
        else:
            single = len(dl_mid.by_tag(tag_key, tag))
            pair = len(ab_mid.by_tag(tag_key, tag))
            status = "VERIFIED" if (single == 1 and pair == 2) else "PARTIAL"
            self.rows.append(Row("%s.connection_granularity" % proto, status,
                                 "单流快照 %d 条连接（期望 1）；双用户并发快照 %d 条（期望 2）"
                                 % (single, pair),
                                 ["%s-dl-mid.connections.json" % proto, "%s-ab-mid.connections.json" % proto]))

        # --- connection close behaviour ---------------------------------------
        mid_ids = [c.get("id") for c in dl_mid.connections if isinstance(c.get("id"), str)]
        post_ids = {c.get("id") for c in dl_post.connections if isinstance(c.get("id"), str)}
        if not dl_mid.usable or not dl_post.usable:
            self.rows.append(Row("%s.connection_close" % proto, NOT_TESTED,
                                 "缺少 mid/post 快照: %s" % dl_mid.why_unusable()))
        elif not mid_ids:
            self.rows.append(Row("%s.connection_close" % proto, "PARTIAL",
                                 "未发现连接 id 字段，无法判断关闭后是否从列表消失；"
                                 "post 快照连接数=%d" % len(dl_post.connections)))
        else:
            lingering = [i for i in mid_ids if i in post_ids]
            if lingering:
                self.rows.append(Row("%s.connection_close" % proto, "PARTIAL",
                                     "传输结束后 %d/%d 条连接仍在列表中" % (len(lingering), len(mid_ids))))
            else:
                self.rows.append(Row("%s.connection_close" % proto, "VERIFIED",
                                     "传输结束后 %d 条连接均已从列表消失；post 快照剩余连接 %d 条"
                                     % (len(mid_ids), len(dl_post.connections))))

    # ---------------------------------------------------------------- render ---

    def run(self):
        self.global_rows()
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
    return cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
