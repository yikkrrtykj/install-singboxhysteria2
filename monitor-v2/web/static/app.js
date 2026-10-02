/* sing-box Monitor — dashboard logic (vanilla JS, no dependencies).
 *
 * Data sources: the E1 snapshot (GET /api/v1/snapshot + SSE stream) and,
 * since 0.6.0 (#33 PR-5), the closed incidents read family
 * (/api/v1/incidents*, /api/v1/evidence, /api/v1/markers). The timeline
 * endpoint is NOT consumed here. Stale semantics are inherited verbatim:
 * when snapshot.stale is true the last state keeps being rendered and an
 * explicit banner says so — the dashboard never fakes zeros, never clears
 * devices, never invents CLOSED. All dynamic values are rendered through
 * textContent / DOM node APIs; no dynamic innerHTML anywhere.
 */
(function () {
  "use strict";

  var PROTOCOL_LABELS = { "vless-in": "Reality", "hy2-in": "Hysteria2",
                          reality: "Reality", hy2: "Hysteria2", hysteria2: "Hysteria2" };
  function clientLabel(name) { return name === "legacy" ? "默认客户端" : name; }
  function protocolLabel(tag) { return PROTOCOL_LABELS[tag] || "其他"; }
  function stateLabel(value) {
    var labels = {HEALTHY: "正常", CONNECTED: "已连接", ACTIVE: "活动",
      "RECENT ACTIVITY": "近期有活动", IDLE: "空闲", CLOSED: "已关闭",
      NONE: "无", open: "进行中", closed: "已结束", ok: "正常",
      degraded: "已降级", unavailable: "不可用", stale: "已过期", unknown: "未知",
      dark: "未启用", warmup: "预热中", rearm: "等待重新启动", running: "运行中",
      idle: "空闲", connecting: "连接中", STALE: "已过期", FROZEN: "停止更新",
      RECONNECTING: "重新连接中", DISCONNECTED: "已断开"};
    return Object.prototype.hasOwnProperty.call(labels, value) ? labels[value] : value;
  }
  function errorText(error) {
    if (error.status === 429) return "请求过于频繁，请稍后重试。";
    if (error.status === 401) return "认证未通过，请检查密码或重新登录。";
    if (error.status === 403) return "当前请求未获授权，请检查访问权限。";
    return "操作失败，请刷新状态后手动重试。";
  }
  // Translate only server-supplied display copy. Never decode, replace or
  // classify raw evidence tokens; unknown future copy remains verbatim.
  var INCIDENT_COPY = {
    "TT Live Studio login failed": "TT Live Studio 登录失败",
    "Operator-observed event": "人工观察到的事件",
    "Analysed buckets in this window showed no anomaly signal.": "此窗口内已分析的时间段没有出现异常信号。",
    "The total active-connection count fell far below its own baseline.": "总活动连接数远低于自身基线。",
    "Reality active connections fell far below their baseline.": "Reality 活动连接数远低于其基线。",
    "Hysteria2 active connections fell far below their baseline.": "Hysteria2 活动连接数远低于其基线。",
    "Other inbounds' active connections fell far below their baseline.": "其他入站的活动连接数远低于其基线。",
    "Every observed device/inbound pair went quiet in the same buckets.": "所有已观察到的设备与入站组合在相同时间段内均无活动。",
    "Reality-classed sing-box error records spiked above their baseline.": "Reality 类 sing-box 错误记录大幅超过其基线。",
    "Hysteria2-classed sing-box error records spiked above their baseline.": "Hysteria2 类 sing-box 错误记录大幅超过其基线。",
    "Generic (non-protocol) sing-box error records spiked above baseline.": "通用（非协议）sing-box 错误记录大幅超过基线。",
    "Destination-classed sing-box error records spiked above their baseline.": "目标地址类 sing-box 错误记录大幅超过其基线。",
    "sing-box error records spiked, but their closed classes cannot be attributed to one protocol family.": "sing-box 错误记录激增，但这些封闭类别无法归属于单一协议族。",
    "The server-side DNS probe failed.": "服务器端 DNS 探测失败。",
    "The server-side HTTPS probe failed.": "服务器端 HTTPS 探测失败。",
    "The server-side UDP probe failed.": "服务器端 UDP 探测失败。",
    "The server-side public-egress probe failed.": "服务器端公网出口探测失败。",
    "A probe could not adjudicate its own answer, so that plane proves nothing about the network.": "探测未能判定自身结果，因此该探测层不能证明网络状态。",
    "A generic TCP/HTTPS probe succeeded against its configured endpoint in these buckets; one successful probe does not prove general Internet reachability.": "通用 TCP/HTTPS 探测在这些时间段内成功访问了配置的端点；一次探测成功不能证明互联网整体可达。",
    "The server's public egress IP changed.": "服务器公网出口 IP 发生变化。",
    "The sing-box service API was reported stale by the collector.": "采集器报告 sing-box 服务 API 数据已过期。",
    "The collector marked its own snapshot stale.": "采集器将自身快照标为已过期。",
    "Some buckets in this window hold too few samples to judge.": "此窗口内部分时间段的样本不足，无法判断。",
    "The evidence store reported its own degradation during this window.": "证据存储在此窗口内报告自身处于降级状态。",
    "The journal ingest recorded a sequence gap.": "日志接收记录了序列缺口。",
    "A journal batch was terminally rejected by the ingest contract.": "一批日志被接收契约最终拒绝。",
    "sing-box error records of the DNS class were present.": "存在 DNS 类 sing-box 错误记录。",
    "sing-box dial-timeout error records were present.": "存在 sing-box 拨号超时错误记录。",
    "sing-box connection-reset error records were present.": "存在 sing-box 连接重置错误记录。",
    "sing-box network-unreachable error records were present.": "存在 sing-box 网络不可达错误记录。",
    "sing-box TLS-handshake error records were present.": "存在 sing-box TLS 握手错误记录。",
    "sing-box QUIC-class error records were present.": "存在 sing-box QUIC 类错误记录。",
    "sing-box EOF/cancellation error records were present.": "存在 sing-box EOF / 取消错误记录。",
    "sing-box error records outside the named classes were present.": "存在命名类别以外的 sing-box 错误记录。",
    "The journal ingest audit recorded a missing sequence interval.": "日志接收审计记录了缺失的序列区间。",
    "The journal ingest rejected a reader file (invalid JSON).": "日志接收拒绝了读取器文件（JSON 无效）。",
    "The journal ingest rejected a reader file (invalid file name).": "日志接收拒绝了读取器文件（文件名无效）。",
    "The journal ingest rejected a reader file (invalid shape).": "日志接收拒绝了读取器文件（结构无效）。",
    "The journal ingest rejected an empty reader file.": "日志接收拒绝了空的读取器文件。",
    "The journal ingest rejected a reader file (an event failed validation).": "日志接收拒绝了读取器文件（事件验证失败）。",
    "The journal ingest rejected a reader file (invalid header).": "日志接收拒绝了读取器文件（头部无效）。",
    "The journal ingest rejected a reader file (misplaced header).": "日志接收拒绝了读取器文件（头部位置错误）。",
    "The journal ingest rejected a reader file (no header).": "日志接收拒绝了读取器文件（缺少头部）。",
    "The journal ingest refused a non-regular reader file.": "日志接收拒绝了非常规读取器文件。",
    "The journal ingest rejected a reader file (sequence mismatch).": "日志接收拒绝了读取器文件（序列不匹配）。",
    "The journal ingest rejected an oversized reader file.": "日志接收拒绝了过大的读取器文件。",
    "The journal ingest could not read a reader file.": "日志接收无法读取读取器文件。",
    "No independent evidence family corroborated the anomaly.": "没有独立的证据类别印证此异常。",
    "The only signal was a connection-count drop, which alone cannot name a fault domain.": "唯一信号是连接数下降，仅凭这一点无法确定故障域。",
    "The evidence points in more than one direction; no single attribution is supported.": "证据指向多个方向，不支持单一归因。",
    "There is not enough baseline evidence to judge the anomaly against.": "基线证据不足，无法据此判断异常。",
    "The evidence cannot prove transport-level causes were absent.": "证据不能证明传输层原因不存在。",
    "Negative checks were not proven in the same buckets as the anomaly.": "未能证明排除性检查与异常发生在相同时间段。",
    "No probe evidence covers this window.": "没有覆盖此窗口的探测证据。",
    "Probe evidence exists but cannot adjudicate this window.": "存在探测证据，但无法判定此窗口。",
    "The probes share external endpoints, so one endpoint outage can look like a VPS outbound failure.": "探测共用外部端点，因此单一端点故障可能表现为 VPS 出站故障。",
    "The window holds more than one separated anomaly episode; no single verdict can describe both.": "此窗口包含多个相互分离的异常阶段，单一结论无法描述所有阶段。",
    "No journal evidence covers this window.": "没有覆盖此窗口的日志证据。",
    "Journal evidence covers this window only partially.": "日志证据仅部分覆盖此窗口。",
    "No evidence can single out one specific destination.": "没有证据可以指明某个具体目标地址。",
    "Errors span several destination classes, so no single destination fits.": "错误跨越多个目标地址类别，无法归属于单一目标地址。",
    "Process and network evidence disagree; neither attribution is supported.": "进程与网络证据相互冲突，两种归因均不受支持。",
    "Device rows in this window are ordinary change records, not failure proof.": "此窗口内的设备记录是普通变更记录，不能证明故障。",
    "Evidence is present that no closed rule can attribute.": "存在无法由任何封闭规则归因的证据。",
    "The evidence bundle was malformed and was refused.": "证据包结构无效，已被拒绝。",
    "Evidence outside the analysed window was refused.": "分析窗口以外的证据已被拒绝。",
    "The evidence says where it hurt, not why; the root cause is not established.": "证据表明问题发生在哪个范围，但无法解释原因；根因尚未确定。",
    "The samples section of the evidence was refused.": "样本证据部分已被拒绝。",
    "The device-states section of the evidence was refused.": "设备状态证据部分已被拒绝。",
    "The probe-rows section of the evidence was refused.": "探测记录证据部分已被拒绝。",
    "The journal-events section of the evidence was refused.": "日志事件证据部分已被拒绝。",
    "The ingest-audit section of the evidence was refused.": "接收审计证据部分已被拒绝。",
    "The evidence window itself was unusable.": "证据窗口本身不可用。",
    "The evidence health section was refused.": "证据健康状态部分已被拒绝。",
    "The evidence reader-freshness section was refused.": "证据读取器新鲜度部分已被拒绝。",
    "Reality/TCP path incident": "Reality/TCP 链路事件",
    "Reality traffic degraded during the signal window.": "信号窗口内 Reality 流量出现降级。",
    "Assessed fault domain: the Reality/TCP path. This evidence does not prove Hysteria2 was healthy.": "评估故障域：Reality/TCP 链路。此证据不能证明 Hysteria2 当时正常。",
    "No evidence in this window attributes the fault to the sing-box process or its control API.": "此窗口内没有证据将故障归因于 sing-box 进程或其控制 API。",
    "Server-side evidence cannot tell which clients or networks were affected.": "服务器端证据无法确定哪些客户端或网络受到影响。",
    "The evidence-based fault domain is the Reality/TCP path.": "证据支持的故障域为 Reality/TCP 链路。",
    "If Hysteria2 is independently confirmed healthy, prefer it while the Reality/TCP path is investigated.": "如果已经独立确认 Hysteria2 正常，可在调查 Reality/TCP 链路期间优先使用它。",
    "Hysteria2/UDP path incident": "Hysteria2/UDP 链路事件",
    "Hysteria2 traffic degraded during the signal window.": "信号窗口内 Hysteria2 流量出现降级。",
    "Assessed fault domain: the Hysteria2/UDP path. This evidence does not prove Reality was healthy.": "评估故障域：Hysteria2/UDP 链路。此证据不能证明 Reality 当时正常。",
    "The evidence-based fault domain is the Hysteria2/UDP path.": "证据支持的故障域为 Hysteria2/UDP 链路。",
    "If Reality is independently confirmed healthy, prefer it while the Hysteria2/UDP path is investigated.": "如果已经独立确认 Reality 正常，可在调查 Hysteria2/UDP 链路期间优先使用它。",
    "VPS outbound connectivity incident": "VPS 出站连接事件",
    "The server lost reachability to parts of the internet during the signal window.": "信号窗口内服务器无法访问部分互联网目标。",
    "Assessed fault domain: VPS outbound connectivity (DNS/HTTPS/UDP/egress), upstream of both proxy protocols.": "评估故障域：VPS 出站连接（DNS/HTTPS/UDP/出口），位于两种代理协议的上游。",
    "The evidence-based fault domain is VPS outbound connectivity.": "证据支持的故障域为 VPS 出站连接。",
    "Inspect the outbound DNS/HTTPS/UDP probe rows below and the public-egress context; if the egress IP changed, check the provider network state before changing sing-box.": "检查下方出站 DNS/HTTPS/UDP 探测记录与公网出口上下文；若出口 IP 发生变化，请先检查服务商网络状态，再考虑修改 sing-box。",
    "sing-box process / control API incident": "sing-box 进程 / 控制 API 事件",
    "The sing-box process or its service API showed failure evidence during the signal window.": "信号窗口内 sing-box 进程或其服务 API 出现故障证据。",
    "Assessed fault domain: the control plane and process health, not one proxy path.": "评估故障域：控制平面与进程健康状态，并非某一条代理链路。",
    "This window was attributed to the sing-box process / service API domain.": "此窗口归属于 sing-box 进程 / 服务 API 故障域。",
    "The evidence-based fault domain is the sing-box process / service API.": "证据支持的故障域为 sing-box 进程 / 服务 API。",
    "Inspect the process and control-API evidence below (API status, connection counts, error classes). Do not assume a restart without restart evidence.": "检查下方进程与控制 API 证据（API 状态、连接数、错误类别）；没有重启证据时，不要假定发生了重启。",
    "Common inbound / client-office path incident": "公共入站 / 客户端现场链路事件",
    "The shared inbound path observed for the clients showed failure evidence during the signal window.": "信号窗口内，观察到客户端共用的入站链路出现故障证据。",
    "Assessed fault domain: the common inbound / client-office domain shared by the affected paths.": "评估故障域：受影响链路共用的公共入站 / 客户端现场范围。",
    "The evidence-based fault domain is the common inbound / client-office path.": "证据支持的故障域为公共入站 / 客户端现场链路。",
    "Inspect the shared-domain evidence below. The current evidence cannot distinguish which component of that domain caused this window.": "检查下方公共范围证据；当前证据无法区分该范围内具体哪个组件导致了此窗口的异常。",
    "Unclassified incident window (insufficient evidence)": "未分类事件窗口（证据不足）",
    "An anomaly window was recorded, but the retained evidence cannot say what it affected.": "已记录异常窗口，但保留的证据无法确定影响范围。",
    "No protocol or path attribution is supported by this evidence.": "此证据不支持任何协议或链路归因。",
    "No server-side fault can be claimed or excluded from this evidence.": "此证据无法确认或排除服务器端故障。",
    "The evidence supports no fault domain: insufficient evidence.": "证据不支持任何故障域：证据不足。",
    "Correlation is not causation: the root cause is not established. Server-side sparse device state cannot authoritatively determine which logical clients were affected, and it cannot infer ISP ownership or path identity; nor does it name a specific destination. No process-restart or resource-exhaustion history is recorded that could support such a claim.": "相关性不等于因果关系：根因尚未确定。服务器端有限的设备状态记录无法权威判断哪些逻辑客户端受到影响，也不能推断 ISP 归属、链路身份或某个具体目标地址。没有记录可以支持进程重启或资源耗尽判断的历史数据。",
    "Correlation is not causation: the root cause is not established.": "相关性不等于因果关系：根因尚未确定。",
    "No open questions were recorded for this verdict.": "此结论没有记录待解问题。"
};
  function incidentCopy(value) {
    if (Object.prototype.hasOwnProperty.call(INCIDENT_COPY, value)) return INCIDENT_COPY[value];
    var question = /^The evidence records ([1-9][0-9]*) open questions?; see the reasons below\.$/.exec(value);
    if (question) return "证据记录了 " + question[1] + " 个待解问题，请查看下方原因。";
    return value;
  }
  var CLIENT_UNAVAILABLE = "客户端管理暂不可用，请先检查服务器状态。";
  var RESULT_UNCONFIRMED = "结果尚未确认，请先刷新客户端列表。在确认当前状态前，请勿发起另一项修改。";

  /* ---------- incidents (0.6.0, #33 PR-5) ---------- */

  // The six emittable categories' display names (the frozen 6-entry
  // presentation enum; the 45/28 token vocabularies are NOT mirrored
  // here -- the server decodes those, and this file holds no token copy).
  var CATEGORY_LABELS = {
    "reality_tcp_path": "Reality/TCP 链路",
    "hysteria2_udp_path": "Hysteria2/UDP 链路",
    "vps_outbound": "VPS 出站",
    "vps_process_or_api": "sing-box 进程 / API",
    "common_inbound_client_office": "公共入站 / 客户端现场",
    "insufficient_evidence": "证据不足"
  };
  var INC_EMPTY_EVIDENCE = "此窗口内没有保留的证据。";
  var INC_EVIDENCE_UNAVAILABLE = "证据暂不可用，无法据此得出结论。";
  var INC_RETENTION_NOTE = "部分证据可能已超出保留时间。";
  var INC_REARM_ACCEPTED = "已接受重新启动请求，等待事件扫描器进入预热。";
  var INC_EMPTY_LIST = "暂无事件记录。";
  var INC_EMPTY_DEGRADED = "事件历史当前处于降级状态，空结果不能证明没有记录过事件。";
  var INC_DEVICE_DISCLAIMER = "设备记录仅提供有限上下文，不能证明具体哪些逻辑客户端受到影响。";
  var INC_TRUNCATED_NOTE = "仅显示按时间排序的前 2000 条记录，其余记录未展示。";
  var INC_AGGREGATE_PARTIAL = "本节已截断，下方汇总只覆盖已展示记录，而非完整时间窗口。";

  var state = {
    snapshot: null,
    session: null,
    whitelist: null,
    filter: "all",
    view: "overview",
    es: null,
    esGeneration: 0,
    lastSnapshotAt: 0,
    lastVersion: 0,
    incidents: null,
    selectedIncidentId: null,
    incSubject: null,          // {type: "incident"|"marker", id, label}
    incSection: "samples"
  };
  // Non-secret metadata and pending-operation key only, in page memory.
  var p6View = {name: null, busy: false, retry: null, rows: [], next: null};

  function $(id) { return document.getElementById(id); }
  function show(el) { el.classList.remove("hidden"); }
  function hide(el) { el.classList.add("hidden"); }

  /* ---------- formatting ---------- */

  function fmtBytes(value) {
    if (value === null || value === undefined || isNaN(value)) return "—";
    var units = ["B", "KB", "MB", "GB", "TB", "PB"];
    var v = Number(value), i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return (i === 0 ? String(Math.round(v)) : v.toFixed(i === 1 ? 1 : 2)) + " " + units[i];
  }
  function fmtRate(value) {
    if (value === null || value === undefined || isNaN(value)) return "—";
    return fmtBytes(value) + "/s";
  }
  function fmtTime(iso) {
    if (!iso) return "—";
    var d = new Date(iso);
    if (isNaN(d.getTime())) return "—";
    var today = new Date();
    var sameDay = d.toDateString() === today.toDateString();
    var time = d.toLocaleTimeString();
    return sameDay ? time : d.toLocaleDateString() + " " + time;
  }
  function fmtEpoch(seconds) {
    if (seconds === null || seconds === undefined || isNaN(seconds)) return "—";
    var d = new Date(Number(seconds) * 1000);
    if (isNaN(d.getTime())) return "—";
    var today = new Date();
    var sameDay = d.toDateString() === today.toDateString();
    var time = d.toLocaleTimeString();
    return sameDay ? time : d.toLocaleDateString() + " " + time;
  }
  function fmtUptime(seconds) {
    if (seconds === null || seconds === undefined || isNaN(seconds)) return "—";
    var s = Math.floor(seconds);
    var days = Math.floor(s / 86400); s %= 86400;
    var hours = Math.floor(s / 3600); s %= 3600;
    var mins = Math.floor(s / 60); s %= 60;
    if (days) return days + "d " + hours + "h " + mins + "m";
    if (hours) return hours + "h " + mins + "m " + s + "s";
    if (mins) return mins + "m " + s + "s";
    return s + "s";
  }
  function shortId(id) {
    return id && id.length > 8 ? id.slice(0, 8) + "…" : (id || "—");
  }

  var toastTimer = null;
  function toast(message) {
    var el = $("toast");
    el.textContent = message;
    show(el);
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { hide(el); }, 2200);
  }

  function copyText(text, label) {
    function done() { toast(label || "已复制"); }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, function () { legacyCopy(text); done(); });
    } else {
      legacyCopy(text); done();
    }
  }
  function legacyCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    try { document.execCommand("copy"); } catch (err) { /* best effort */ }
    document.body.removeChild(area);
  }

  /* ---------- API ---------- */

  // Login and recovery bootstrap run BEFORE a session (and therefore a CSRF
  // token) exists; every other mutation carries the session-bound token.
  var CSRF_EXEMPT_PATHS = /^\/api\/v1\/(login|recovery)$/;

  function api(path, options) {
    options = options || {};
    var init = {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: {}
    };
    var isMutation = init.method !== "GET";
    if (isMutation && !CSRF_EXEMPT_PATHS.test(path) && state.session &&
        state.session.csrf_token) {
      // Attach to EVERY mutation, including body-less ones (logout).
      init.headers["X-CSRF-Token"] = state.session.csrf_token;
    }
    if (options.idempotencyKey !== undefined) {
      // M2: the Idempotency-Key travels ONLY as this header. The caller
      // keeps the SAME value across a 401 step-up replay and an explicit
      // post-uncertain retry (the replay re-sends the whole options object).
      init.headers["Idempotency-Key"] = options.idempotencyKey;
    }
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    return fetch(path, init).then(function (response) {
      if (options.raw && response.ok) {
        // M4 export: a FILE response. The bytes go straight to the caller's
        // Blob handling -- never parsed, rendered, logged or stored here.
        return response;
      }
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok) {
          var error = new Error(data.error || ("HTTP " + response.status));
          error.status = response.status;
          // stable machine code: M0.5 endpoints use {"error": code}; M2 E3
          // endpoints use {"code": code, "error": detail}
          error.code = data.code || data.error;
          error.detail = data.error;
          error.retriable = data.retriable === true;
          error.uncertain = data.uncertain === true;
          error.recovery = data.recovery || null;
          throw error;
        }
        return data;
      });
    });
  }

  /* ---------- step-up (re-authentication) ----------
   *
   * Privileged mutations answer 401 {"error":"reauth_required"} when this
   * session has no live step-up window. ONLY that response opens the password
   * panel: the page never asks for a second password on load. After a
   * successful POST /api/v1/step-up the ORIGINAL request is replayed
   * unchanged (same body, same CSRF token).
   */

  var stepUpPending = null;

  function promptStepUp() {
    if (stepUpPending) return stepUpPending;   // one panel at a time
    stepUpPending = new Promise(function (resolve, reject) {
      var overlay = $("stepup-overlay");
      var input = $("stepup-password");
      var errorEl = $("stepup-error");
      var form = $("stepup-form");
      var cancel = $("stepup-cancel");

      function close() {
        hide(overlay);
        input.value = "";
        hide(errorEl);
        form.removeEventListener("submit", onSubmit);
        cancel.removeEventListener("click", onCancel);
        stepUpPending = null;
      }
      function fail(message) {
        errorEl.textContent = message;
        show(errorEl);
        input.focus();
      }
      function onSubmit(event) {
        event.preventDefault();
        var password = input.value;
        if (!password) { fail("请输入密码。"); return; }
        api("/api/v1/step-up", { method: "POST", body: { password: password } })
          .then(function () {
            close();
            loadSession().catch(function () { /* status refresh is best effort */ });
            resolve();
          })
          .catch(function (error) {
            if (error.status === 429) {
              fail("失败次数过多，请稍后重试。");
            } else if (error.status === 401) {
              fail("密码错误。");
            } else {
              fail(errorText(error));
            }
          });
      }
      function onCancel(event) {
        event.preventDefault();
        close();
        reject(new Error("step-up cancelled"));
      }

      show(overlay);
      errorEl.className = "form-msg error hidden";
      errorEl.textContent = "";
      input.value = "";
      form.addEventListener("submit", onSubmit);
      cancel.addEventListener("click", onCancel);
      input.focus();
    });
    return stepUpPending;
  }

  function apiWithStepUp(path, options) {
    return api(path, options).catch(function (error) {
      if (error.status === 401 && error.code === "reauth_required") {
        return promptStepUp().then(function () { return api(path, options); });
      }
      throw error;
    });
  }

  /* ---------- views ---------- */

  var VIEW_TITLES = { overview: "概览", devices: "设备",
                      connections: "连接", incidents: "事件",
                      settings: "设置" };

  function setView(name) {
    state.view = name;
    Object.keys(VIEW_TITLES).forEach(function (key) {
      var section = $("view-" + key);
      if (key === name) show(section); else hide(section);
    });
    document.querySelectorAll(".nav-item").forEach(function (item) {
      item.classList.toggle("active", item.getAttribute("data-view") === name);
    });
    $("view-title").textContent = VIEW_TITLES[name];
    if (name === "settings") {
      loadAccess();
      loadE3Status();
      loadE3Clients();
    }
    if (name === "incidents") {
      loadIncidents();
      loadMarkers();
    }
  }

  /* ---------- rendering ---------- */

  function setChip(el, label, status, stateName) {
    el.textContent = label + " · " + stateLabel(status);
    el.setAttribute("data-state", stateName);
  }

  function render() {
    var snap = state.snapshot;
    if (!snap) return;

    if (snap.snapshot_version && snap.snapshot_version > state.lastVersion) {
      state.lastVersion = snap.snapshot_version;
    }

    setChip($("chip-monitor"), "监控",
            snap.web_status || "—",
            snap.web_status === "HEALTHY" ? "ok" : "bad");
    setChip($("chip-api"), "sing-box API",
            snap.api_status || "—",
            snap.api_status === "CONNECTED" ? "ok" : "bad");

    // Two distinct degradation modes, one banner slot:
    //   stale  -- the E1 stream to service.api is broken (last state kept);
    //   frozen -- the web backend itself stopped publishing new snapshots.
    var banner = $("stale-text");
    if (snap.stale) {
      banner.textContent = "数据已过期，最近一次 API 事件：" +
        fmtTime(snap.last_success_at);
      show($("stale-banner"));
    } else if (snap.web_status !== "HEALTHY") {
      banner.textContent = "监控数据停止更新，最近发布：" +
        fmtTime(snap.last_publish_at);
      show($("stale-banner"));
    } else {
      hide($("stale-banner"));
    }

    $("st-uptime").textContent = fmtUptime(snap.collector_uptime_seconds);
    $("st-last-event").textContent = fmtTime(snap.last_success_at);

    var devices = Object.keys(snap.devices || {});
    $("st-devices").textContent = String(devices.length);
    $("st-active").textContent = String(snap.active_connections || 0);
    $("st-up-rate").textContent = fmtRate(totalRate(snap, "uplink_rate"));
    $("st-down-rate").textContent = fmtRate(totalRate(snap, "downlink_rate"));
    $("st-up-total").textContent = fmtBytes(totalRate(snap, "uplink_total"));
    $("st-down-total").textContent = fmtBytes(totalRate(snap, "downlink_total"));

    renderDevices(devices.map(function (name) { return snap.devices[name]; }));
    renderConnections(snap.connections || []);
    renderMonitorInfo(snap);
    renderWhitelistFromSession();
  }

  function totalRate(snap, field) {
    var sum = 0;
    Object.keys(snap.devices || {}).forEach(function (name) {
      var value = Number(snap.devices[name][field]);
      if (!isNaN(value)) sum += value;
    });
    return sum;
  }

  function renderDevices(devices) {
    var grid = $("devices-grid");
    grid.textContent = "";
    if (!devices.length) {
      var empty = document.createElement("div");
      empty.className = "empty";
      empty.textContent = "尚未观察到设备。";
      grid.appendChild(empty);
      return;
    }
    var cardTemplate = $("device-card-template");
    var rowTemplate = $("protocol-row-template");
    devices.forEach(function (device) {
      var card = cardTemplate.content.cloneNode(true);
      card.querySelector(".device-name").textContent = clientLabel(device.name);
      var badge = card.querySelector(".device-status");
      badge.textContent = stateLabel(device.status);
      badge.className = "badge device-status " +
        (device.status === "ACTIVE" ? "active"
         : device.status === "RECENT ACTIVITY" ? "recent" : "idle");
      var container = card.querySelector(".device-protocols");
      var tags = Object.keys(device.protocols || {});
      if (!tags.length) {
        var none = document.createElement("div");
        none.className = "empty";
        none.textContent = "尚未观察到流量。";
        container.appendChild(none);
      }
      tags.forEach(function (tag) {
        var proto = device.protocols[tag];
        var row = rowTemplate.content.cloneNode(true);
        row.querySelector(".proto-label").textContent =
          protocolLabel(tag);
        row.querySelector(".pr-up").textContent = fmtRate(proto.uplink_rate);
        row.querySelector(".pr-down").textContent = fmtRate(proto.downlink_rate);
        row.querySelector(".pt-up").textContent = fmtBytes(proto.uplink_total);
        row.querySelector(".pt-down").textContent = fmtBytes(proto.downlink_total);
        row.querySelector(".pc-count").textContent = String(proto.active_connections);
        container.appendChild(row);
      });
      card.querySelector(".device-last").textContent = fmtTime(device.last_activity);
      grid.appendChild(card);
    });
  }

  function renderConnections(rows) {
    var tbody = $("conn-tbody");
    tbody.textContent = "";
    var filtered = rows.filter(function (row) {
      if (state.filter === "all") return true;
      return row.state === state.filter;
    });
    $("conn-count").textContent =
      filtered.length + " / " + rows.length + " 条已显示";
    filtered.forEach(function (row) {
      var tr = document.createElement("tr");

      tr.appendChild(cellText(clientLabel(row.user)));
      var proto = document.createElement("td");
      proto.textContent = protocolLabel(row.inbound);
      tr.appendChild(proto);

      var idCell = document.createElement("td");
      var idButton = document.createElement("button");
      idButton.type = "button";
      idButton.className = "conn-id";
      idButton.textContent = shortId(row.id);
      idButton.title = "复制完整 ID";
      idButton.addEventListener("click", function () {
        copyText(row.id, "连接 ID 已复制");
      });
      idCell.appendChild(idButton);
      tr.appendChild(idCell);

      tr.appendChild(cellText(row.network || "—"));

      var dest = document.createElement("td");
      dest.className = "dest";
      dest.textContent = row.destination || "—";
      dest.title = row.destination || "";
      tr.appendChild(dest);

      tr.appendChild(cellText(fmtRate(row.uplink_rate), "num"));
      tr.appendChild(cellText(fmtRate(row.downlink_rate), "num"));
      tr.appendChild(cellText(fmtBytes(row.uplink_total), "num"));
      tr.appendChild(cellText(fmtBytes(row.downlink_total), "num"));
      tr.appendChild(cellText(fmtTime(row.created_at)));

      var stateCell = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge " +
        (row.state === "ACTIVE" ? "active" : "recent");
      badge.textContent = stateLabel(row.state);
      stateCell.appendChild(badge);
      tr.appendChild(stateCell);

      tbody.appendChild(tr);
    });
  }

  function cellText(text, extraClass) {
    var td = document.createElement("td");
    if (extraClass) td.className = extraClass;
    td.textContent = text;
    return td;
  }

  function renderMonitorInfo(snap) {
    $("mi-version").textContent = state.session ? state.session.version : "—";
    $("mi-started").textContent = fmtTime(snap.monitor_started_at);
    $("mi-uptime").textContent = fmtUptime(snap.collector_uptime_seconds);
    if (snap.last_error) show($("mi-warning")); else hide($("mi-warning"));
  }

  /* ---------- incidents view (0.6.0, #33 PR-5; review round adds the
     L3 compact timeline, L4 raw tokens, marker-subject evidence and the
     current-history health consumption) ---------- */

  function incMessage(text, isError) {
    var el = $("inc-marker-msg");
    el.textContent = text;
    el.className = "form-msg " + (isError ? "error" : "ok");
    show(el);
  }

  function rearmMessage(text, isError) {
    var el = $("inc-rearm-msg");
    el.textContent = text;
    el.className = "form-msg " + (isError ? "error" : "ok");
    show(el);
  }

  function renderIncRuntime() {
    var chip = $("inc-runtime");
    var rearm = $("inc-rearm-btn");
    var data = state.incidents;
    var runtime = data ? data.runtime : null;
    if (!runtime || !runtime.enabled) {
      setChip(chip, "扫描器", "dark", "unknown");
    } else {
      setChip(chip, "扫描器", runtime.phase,
              runtime.phase === "degraded" ? "bad" : "ok");
    }
    // B5: the list response carries CURRENT diagnostics health -- it is
    // displayed as such, never as incident-time health, and it governs
    // whether an empty list may be called "暂无事件记录。"
    var history = data ? data.history : null;
    var historyChip = $("inc-history");
    if (!history || history.enabled !== true) {
      setChip(historyChip, "历史", "unavailable", "bad");
    } else if (history.degraded === true) {
      setChip(historyChip, "历史", "degraded", "bad");
    } else {
      setChip(historyChip, "历史", "ok", "ok");
    }
    // Server-side precondition mirror (#63 R2 section 10): the re-arm
    // entrance only exists while the scanner reports the rearm phase.
    var rearmable = !!runtime && runtime.enabled === true &&
      runtime.running === true && runtime.phase === "rearm";
    rearm.disabled = !rearmable;
  }

  function loadIncidents() {
    if (!state.session || !state.session.authenticated) return;
    return api("/api/v1/incidents").then(function (data) {
      state.incidents = data;
      renderIncRuntime();
      renderIncidents(data);
    }).catch(function (error) {
      if (error.status === 401) { showLogin("登录已过期，请重新登录。"); return; }
      var body = $("inc-tbody");
      body.textContent = "";
      var row = body.insertRow(-1);
      var cell = row.insertCell(-1);
      cell.colSpan = 7;
      cell.textContent = "事件列表暂不可用。";
    });
  }

  function renderIncidents(data) {
    var tbody = $("inc-tbody");
    tbody.textContent = "";
    var incidents = (data && data.incidents) || [];
    incidents.forEach(function (incident) {
      var tr = document.createElement("tr");
      var stateCell = document.createElement("td");
      var badge = document.createElement("span");
      badge.className = "badge " + (incident.state === "open" ? "active" : "idle");
      badge.textContent = stateLabel(incident.state);
      stateCell.appendChild(badge);
      tr.appendChild(stateCell);
      tr.appendChild(cellText(CATEGORY_LABELS[incident.category] || incident.category));
      tr.appendChild(cellText(fmtEpoch(incident.first_signal_epoch)));
      tr.appendChild(cellText(fmtEpoch(incident.last_signal_epoch)));
      tr.appendChild(cellText(fmtUptime(incident.last_signal_epoch - incident.first_signal_epoch), "num"));
      tr.appendChild(cellText(String(incident.buckets), "num"));
      tr.appendChild(cellText(String(incident.marker_count), "num"));
      tr.addEventListener("click", function () { openIncident(incident.incident_id); });
      tbody.appendChild(tr);
    });
    if (!incidents.length) {
      var row = tbody.insertRow(-1);
      var cell = row.insertCell(-1);
      cell.colSpan = 7;
      // B5: an empty answer from a DEGRADED/unavailable history is
      // uncertainty, never the authoritative empty wording.
      var history = data && data.history;
      var degraded = !history || history.enabled !== true ||
        history.degraded === true;
      cell.textContent = degraded ? INC_EMPTY_DEGRADED : INC_EMPTY_LIST;
    }
  }

  function openIncident(id) {
    if (!state.session || !state.session.authenticated) return;
    return api("/api/v1/incidents/" + id).then(function (detail) {
      state.selectedIncidentId = id;
      state.incSubject = {type: "incident", id: id};
      renderIncidentDetail(detail);
      show($("inc-evidence-card"));
      $("inc-evidence-title").textContent = "事件证据 #" + id;
      hide($("inc-evidence-subject"));
      loadEvidence(state.incSection);
    }).catch(function (error) {
      if (error.status === 401) showLogin("登录已过期，请重新登录。");
    });
  }

  function kvRow(key, value) {
    var div = document.createElement("div");
    div.className = "kv";
    var k = document.createElement("span");
    k.className = "k";
    k.textContent = key;
    var v = document.createElement("span");
    v.className = "v";
    v.textContent = incidentCopy(value);
    div.appendChild(k);
    div.appendChild(v);
    return div;
  }

  function reasonItems(container, pairs) {
    container.textContent = "";
    (pairs || []).forEach(function (pair) {
      var li = document.createElement("li");
      li.textContent = incidentCopy(pair.text);   // textContent only: never the raw token as primary
      container.appendChild(li);
    });
    if (!container.children.length) {
      var li = document.createElement("li");
      li.className = "muted";
      li.textContent = "暂无记录。";
      container.appendChild(li);
    }
  }

  // B2: the L4 token drill-down -- the EXACT raw tokens the server
  // returned, each with a copy affordance, rendered apart from L2 and
  // always through textContent / DOM node APIs.
  function tokenItems(container, pairs) {
    container.textContent = "";
    (pairs || []).forEach(function (pair) {
      var li = document.createElement("li");
      var code = document.createElement("span");
      code.className = "inc-token";
      code.textContent = pair.token;
      li.appendChild(code);
      var copy = document.createElement("button");
      copy.type = "button";
      copy.className = "btn ghost";
      copy.textContent = "复制";
      copy.addEventListener("click", function () {
        copyText(pair.token, "技术标记已复制");
      });
      li.appendChild(copy);
      container.appendChild(li);
    });
    if (!container.children.length) {
      var li = document.createElement("li");
      li.className = "muted";
      li.textContent = "暂无记录。";
      container.appendChild(li);
    }
  }

  function renderIncidentDetail(detail) {
    hide($("inc-list-card"));
    show($("inc-detail"));
    var summary = detail.summary || {};
    $("inc-detail-title").textContent = incidentCopy(summary.headline) || "事件";
    var box = $("inc-summary");
    box.textContent = "";
    var win = summary.window || {};
    if (win.start_epoch !== undefined) {
      box.appendChild(kvRow("信号窗口",
        fmtEpoch(win.start_epoch) + " — " + fmtEpoch(win.end_epoch) +
        " (" + fmtUptime(win.duration_seconds) + ")"));
    }
    ["impact", "protocol_state", "server_state", "affected_scope",
     "assessment"].forEach(function (key) {
      if (summary[key]) box.appendChild(kvRow({impact: "影响", protocol_state: "协议状态", server_state: "服务器状态", affected_scope: "影响范围", assessment: "评估"}[key], summary[key]));
    });
    if (summary.recommended_action) {
      box.appendChild(kvRow("建议操作", summary.recommended_action));
    }
    if (summary.uncertainty) box.appendChild(kvRow("不确定性", summary.uncertainty));
    if (summary.limitations) box.appendChild(kvRow("限制", summary.limitations));
    // The in-window operator markers, joined server-side (#63 R2 §4):
    // closed labels only, never the detail's own free text.
    if ((detail.markers || []).length) {
      box.appendChild(kvRow("人工标记",
        detail.markers.map(function (m) { return incidentCopy(m.label || m.kind); })
                      .join("; ")));
    }
    reasonItems($("inc-evidence-list"), detail.evidence);
    reasonItems($("inc-unknowns-list"), detail.unknowns);
    tokenItems($("inc-evidence-tokens"), detail.evidence);
    tokenItems($("inc-unknown-tokens"), detail.unknowns);
  }

  function closeIncidentDetail() {
    state.selectedIncidentId = null;
    state.incSubject = null;
    hide($("inc-detail"));
    hide($("inc-evidence-card"));
    show($("inc-list-card"));
  }

  // B3: the marker evidence correlation -- the ONLY subject change the
  // UI offers besides an incident. It reuses the same five sections, the
  // same L3/L4 rendering and the same subject-bound route with
  // marker_id=; the +/-900 s window is SERVER-derived and only echoed
  // here. No hash route, no new API route, no incident is created.
  function openMarkerEvidence(id, label) {
    if (!state.session || !state.session.authenticated) return;
    state.incSubject = {type: "marker", id: id, label: label};
    $("inc-evidence-title").textContent = "标记附近的证据";
    var line = $("inc-evidence-subject");
    line.textContent = "标记：" + (label || ("#" + id));
    show(line);
    show($("inc-evidence-card"));
    loadEvidence(state.incSection);
  }

  function loadEvidence(section) {
    state.incSection = section;
    document.querySelectorAll("#inc-sections .seg-item").forEach(function (item) {
      item.classList.toggle("active", item.getAttribute("data-section") === section);
    });
    var subject = state.incSubject;
    if (!subject) return;
    var note = $("inc-rows-note");
    hide(note);
    var url = "/api/v1/evidence?section=" + section;
    if (subject.type === "marker") {
      url += "&marker_id=" + subject.id;
    } else {
      url += "&incident_id=" + subject.id;
    }
    return api(url).then(function (data) {
      renderEvidenceRows(data);
    }).catch(function () {
      // B4: a network/HTTP/read failure is NOT an empty window. No
      // conclusion -- including the neutral retained-evidence text --
      // may be drawn from a view that could not load.
      var head = $("inc-rows-head");
      var body = $("inc-rows-body");
      head.textContent = "";
      body.textContent = "";
      var tr = body.insertRow(-1);
      tr.insertCell(-1).textContent = INC_EVIDENCE_UNAVAILABLE;
      $("inc-l3").textContent = "";
      hide(note);
    });
  }

  function renderEvidenceRows(data) {
    var head = $("inc-rows-head");
    var body = $("inc-rows-body");
    var note = $("inc-rows-note");
    head.textContent = "";
    body.textContent = "";
    $("inc-l3").textContent = "";
    var rows = (data && data.rows) || [];
    var subject = $("inc-evidence-subject");
    if (state.incSubject && state.incSubject.type === "marker" && data &&
        data.window) {
      // B3: the server-derived window, only echoed -- never widened here.
      subject.textContent = "标记：" +
        (state.incSubject.label || ("#" + state.incSubject.id)) +
        " — 服务器给出的时间窗口：" +
        fmtEpoch(data.window.start_epoch) + " — " +
        fmtEpoch(data.window.end_epoch) +
        "（标记前后各 15 分钟）";
      show(subject);
    }
    renderL3(data);
    if (rows.length) {
      var hr = document.createElement("tr");
      Object.keys(rows[0]).forEach(function (key) {
        var th = document.createElement("th");
        th.textContent = key;
        hr.appendChild(th);
      });
      head.appendChild(hr);
    }
    rows.forEach(function (row) {
      var tr = document.createElement("tr");
      Object.keys(rows[0] || {}).forEach(function (key) {
        var value = row[key];
        var td = document.createElement("td");
        td.textContent = (value === null || value === undefined) ? "—" : String(value);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    if (!rows.length) {
      var tr = body.insertRow(-1);
      // B4: this text is ONLY reachable after a successful 200 with an
      // empty row set -- never from a failure path.
      tr.insertCell(-1).textContent = INC_EMPTY_EVIDENCE;
    }
    var notes = [];
    if (data && data.truncated) {
      // the read is ORDER BY epoch ASC LIMIT budget: the response holds
      // the EARLIEST rows -- LATER rows in this section are omitted
      notes.push(INC_TRUNCATED_NOTE);
    }
    if (data && data.window && data.retention_cutoff_epoch !== undefined &&
        data.window.start_epoch < data.retention_cutoff_epoch) {
      notes.push(INC_RETENTION_NOTE);
    }
    if (notes.length) {
      note.textContent = notes.join(" ");
      show(note);
    }
  }

  // ---- B1: the L3 compact timeline --------------------------------------
  // Client-side presentation of the SAME subject-bound rows the raw L4
  // table shows -- no new endpoint, no second fetch, no invented
  // statistics. journal_events aggregate exactly by (cls, proto, dcls,
  // port); audit by (kind, code); samples/probes render their operator
  // columns; device states carry the sparse-context disclaimer.

  function l3Table(headers, rows) {
    var card = document.createElement("div");
    card.className = "table-card";
    var table = document.createElement("table");
    table.className = "table";
    var head = document.createElement("thead");
    var hr = document.createElement("tr");
    headers.forEach(function (h) {
      var th = document.createElement("th");
      th.textContent = h;
      hr.appendChild(th);
    });
    head.appendChild(hr);
    table.appendChild(head);
    var body = document.createElement("tbody");
    rows.forEach(function (cells) {
      var tr = document.createElement("tr");
      cells.forEach(function (value) {
        var td = document.createElement("td");
        td.textContent = (value === null || value === undefined) ? "—" : String(value);
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    table.appendChild(body);
    card.appendChild(table);
    return card;
  }

  function fmtSlot(status, latency, code) {
    if (status === "ok") return "ok " + latency + " ms";
    if (code === "NONE" || !code) return status || "—";
    return status + " (" + code + ")";
  }

  function renderL3(data) {
    var host = $("inc-l3");
    host.textContent = "";
    var rows = (data && data.rows) || [];
    if (!rows.length) return;   // the L4 empty state speaks for both
    if (data.truncated && (data.section === "journal_events"
                           || data.section === "audit")) {
      // a truncated section's totals are NOT full-window totals: say so
      // next to the aggregates instead of labelling them complete
      var partial = document.createElement("p");
      partial.className = "muted";
      partial.textContent = INC_AGGREGATE_PARTIAL;
      host.appendChild(partial);
    }
    if (data.section === "journal_events") {
      // EXACT grouping key: (cls, proto, dcls, port)
      var groups = {};
      rows.forEach(function (row) {
        var key = [row.cls, row.proto, row.dcls, row.port].join("\u0000");
        if (!groups[key]) {
          groups[key] = {cls: row.cls, proto: row.proto, dcls: row.dcls,
                         port: row.port, total: 0, first: row.ts,
                         last: row.ts};
        }
        groups[key].total += row.n;
        groups[key].first = Math.min(groups[key].first, row.ts);
        groups[key].last = Math.max(groups[key].last, row.ts);
      });
      var headers = ["错误类型", "协议", "目标类型",
                     "端口", "总计", "首次", "最近"];
      var table = Object.keys(groups).sort().map(function (key) {
        var g = groups[key];
        return [g.cls, g.proto, g.dcls === "NONE" ? "—" : g.dcls,
                g.port === 0 ? "—" : String(g.port), String(g.total),
                fmtEpoch(g.first), fmtEpoch(g.last)];
      });
      host.appendChild(l3Table(headers, table));
      return;
    }
    if (data.section === "audit") {
      var audits = {};
      rows.forEach(function (row) {
        var key = [row.kind, row.code].join("\u0000");
        if (!audits[key]) {
          audits[key] = {kind: row.kind, code: row.code, total: 0,
                         first: row.epoch, last: row.epoch};
        }
        audits[key].total += 1;
        audits[key].first = Math.min(audits[key].first, row.epoch);
        audits[key].last = Math.max(audits[key].last, row.epoch);
      });
      host.appendChild(l3Table(
        ["类型", "代码", "总计", "首次", "最近"],
        Object.keys(audits).sort().map(function (key) {
          var g = audits[key];
          return [g.kind, g.code, String(g.total),
                  fmtEpoch(g.first), fmtEpoch(g.last)];
        })));
      return;
    }
    if (data.section === "samples") {
      host.appendChild(l3Table(
        ["时间", "Reality 连接", "Hysteria2 连接", "连接总数",
         "API", "采集器"],
        rows.map(function (row) {
          return [fmtEpoch(row.epoch),
                  String(row.reality_active_connections),
                  String(row.hysteria2_active_connections),
                  String(row.total_active_connections),
                  row.api_status || "—",
                  row.collector_stale ? "stale" : "ok"];
        })));
      return;
    }
    if (data.section === "probe_rows") {
      host.appendChild(l3Table(
        ["时间", "DNS", "HTTPS", "UDP", "出站", "公网出口 IP",
         "IP 变化"],
        rows.map(function (row) {
          return [fmtEpoch(row.epoch),
                  fmtSlot(row.dns_status, row.dns_latency_ms, row.dns_error_code),
                  fmtSlot(row.https_status, row.https_latency_ms, row.https_error_code),
                  fmtSlot(row.udp_status, row.udp_latency_ms, row.udp_error_code),
                  fmtSlot(row.egress_status, row.egress_latency_ms, row.egress_error_code),
                  row.egress_ip || "—",
                  row.egress_change || "—"];
        })));
      return;
    }
    if (data.section === "device_states") {
      var note = document.createElement("p");
      note.className = "muted";
      note.textContent = INC_DEVICE_DISCLAIMER;
      host.appendChild(note);
      host.appendChild(l3Table(
        ["时间", "设备", "入站", "活动连接", "状态"],
        rows.map(function (row) {
          return [fmtEpoch(row.epoch), row.device, row.inbound,
                  String(row.active_connections), row.device_status || "—"];
        })));
    }
  }

  function loadMarkers() {
    if (!state.session || !state.session.authenticated) return;
    return api("/api/v1/markers").then(function (data) {
      renderMarkers((data && data.markers) || []);
    }).catch(function () { /* the list stays as it was */ });
  }

  function renderMarkers(markers) {
    var list = $("inc-markers-list");
    list.textContent = "";
    markers.forEach(function (marker) {
      var li = document.createElement("li");
      var label = document.createElement("span");
      label.textContent = incidentCopy(marker.label || marker.kind) +
        " · " + fmtEpoch(marker.epoch);
      li.appendChild(label);
      // B3: non-destructive correlation entry -- selects the marker as
      // the evidence subject on the SAME subject-bound route.
      var view = document.createElement("button");
      view.type = "button";
      view.className = "btn ghost";
      view.textContent = "查看证据";
      view.addEventListener("click", function () {
        openMarkerEvidence(marker.marker_id, incidentCopy(marker.label || marker.kind));
      });
      li.appendChild(view);
      list.appendChild(li);
    });
    if (!(markers || []).length) {
      var li = document.createElement("li");
      li.className = "muted";
      li.style.fontFamily = "inherit";
      li.textContent = "暂无人工标记。";
      list.appendChild(li);
    }
  }

  function addMarker() {
    if (!state.session || !state.session.authenticated) return;
    var kind = $("inc-marker-kind").value;
    var button = $("inc-marker-add-btn");
    button.disabled = true;   // no automatic retry; a double click would
    apiWithStepUp("/api/v1/markers", {   // legitimately record two events
      method: "POST",
      body: { kind: kind }
    }).then(function () {
      button.disabled = false;
      incMessage("人工标记已记录。", false);
      loadMarkers();
    }).catch(function (error) {
      button.disabled = false;
      if (error.status === 401) { showLogin("登录已过期，请重新登录。"); return; }
      if (error.status === 400 && error.code === "invalid_marker_epoch") {
        incMessage("标记时间已超出保留窗口。", true);
        return;
      }
      incMessage("无法记录人工标记。", true);
    });
  }

  function rearmIncidents() {
    if (!state.session || !state.session.authenticated) return;
    var button = $("inc-rearm-btn");
    button.disabled = true;
    apiWithStepUp("/api/v1/incidents/rearm", { method: "POST" })
      .then(function () {
        rearmMessage(INC_REARM_ACCEPTED, false);
        loadIncidents();
      })
      .catch(function (error) {
        if (error.status === 401) { showLogin("登录已过期，请重新登录。"); return; }
        if (error.status === 409) {
          rearmMessage("当前发现状态无需重新启动。", true);
        } else {
          rearmMessage("无法记录重新启动请求，请勿自动重试。", true);
        }
        loadIncidents();
      });
  }

  /* ---------- client availability ---------- */

  function setBadge(el, label, cls) {
    el.textContent = label;
    el.className = "badge " + cls;
  }
  /* ---------- E3 client management (privileged mutations) ---------- */

  function newIdempotencyKey() {
    // 32 hex chars from CSPRNG — matches the helper's key charset.
    var bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    return Array.prototype.map.call(bytes, function (b) {
      return ("0" + b.toString(16)).slice(-2);
    }).join("");
  }

  function e3Message(text, isError) {
    var el = $("e3-msg");
    el.textContent = text;
    el.className = "form-msg " + (isError ? "error" : "ok");
    show(el);
  }

  // B4: ONE writable gate for every E3 mutation control. The view may be
  // stale (still displayed), but the destructive surface only exists while
  // the fresh status explicitly permits changes. Missing fields fail closed.
  function e3Writable() {
    var s = state.e3Status;
    if (!s || s.transport !== "fresh" ||
        Date.now() - (state.e3StatusAt || 0) > 10000) return false;
    var d = s.data;
    return !!(d && d.management_state === "active" && d.helper &&
      d.helper.degraded === false && d.helper.reconcile === "clean" &&
      d.lock && d.lock.acquirable === true && !state.e3PendingRetry);
  }

  /* B3: pending uncertain retry. After a result_unknown the operation is
   * remembered EXACTLY as dispatched ({path, name, idempotencyKey}); the
   * explicit Retry button replays it with the SAME key. A terminal verdict
   * (success or a non-uncertain error) clears it. A lost key can never be
   * "retried" -- only fresh status/list re-checking is offered then. */
  function setPendingRetry(pending) {
    state.e3PendingRetry = pending || null;
    if (pending) {
      // B3-final: while a result_unknown is pending, the ordinary mutation
      // entrances lock (renderE3Controls) and an open delete confirm is
      // closed -- the ONLY retry path is the same-key button below.
      $("e3-retry-name").textContent = pending.name || pending.path;
      show($("e3-retry-row"));
      closeDeleteConfirm();
    } else {
      hide($("e3-retry-row"));
    }
    renderE3Controls();
  }

  function retryPending() {
    var p = state.e3PendingRetry;
    if (!p) return;   // no pending uncertain operation: nothing to retry
    e3Message("正在核验上次修改…", false);
    apiWithStepUp(p.path, {
      method: "POST",
      idempotencyKey: p.idempotencyKey,   // exact same header value
      body: p.body
    }).then(function (data) {
      setPendingRetry(null);
      e3Message(p.name
        ? "重试已结束，操作已达到最终状态。"
        : "重试已结束。", false);
      loadE3Clients();
      loadE3Status();
      loadSession();
    }).catch(function (error) {
      if (error.status === 504 && error.uncertain) {
        // still uncertain: the pending op stays, still the same key
        e3Message(RESULT_UNCONFIRMED, true);
        loadE3Status();
        return;
      }
      // any other terminal verdict clears the pending operation
      setPendingRetry(null);
      e3Message(CLIENT_UNAVAILABLE, true);
      loadE3Clients();
      loadE3Status();
    });
  }

  function loadE3Status(background) {
    if (!state.session || !state.session.authenticated) return;
    // 0.1.4 review (blocker 2): while a convergence owns the view, plain
    // reads are suppressed AT THE ENTRY -- no request, no generation bump
    // and above all no synchronous ``state.e3Status = null`` below, which
    // for a foreground Refresh would flicker Unavailable before any network
    // response exists. That is the exact visible flicker convergence removes.
    if (state.e3Convergence) return Promise.resolve();
    var generation = state.e3StatusGeneration = (state.e3StatusGeneration || 0) + 1;
    // A background poll retains the last fresh verdict for at most 10s;
    // it must not close a delete confirmation while the user is typing.
    if (!background) state.e3Status = null;
    renderE3Controls();
    return api("/api/v1/management/status").then(function (data) {
      // Defence in depth: also retired if a convergence became active while
      // this read was in flight (generation normally catches that first).
      if (generation !== state.e3StatusGeneration || state.e3Convergence) return;
      state.e3Status = data;
      state.e3StatusAt = Date.now();
      renderE3Controls();
    }).catch(function () {
      if (generation !== state.e3StatusGeneration || state.e3Convergence) return;
      state.e3Status = null;
      renderE3Controls();
    });
  }

  function renderE3Controls() {
    // B4 + B3-final: one writable decision drives every destructive control,
    // and a pending uncertain operation locks the ordinary entrances.
    var writable = e3Writable() && !state.e3PendingRetry;
    // 0.1.5 (#36): the local mutation-busy lock is layered on top of server
    // writability, never folded into it -- the Available/Unavailable badge
    // and the read-only Download keep reflecting SERVER truth only.
    var busy = !!state.e3Mutation;
    var adding = busy && state.e3Mutation.kind === "add";
    var deleting = busy && state.e3Mutation.kind === "delete";
    setBadge($("e3-availability"), writable ? "可用" : "不可用",
             writable ? "ok" : "idle");
    if (writable) hide($("e3-unavailable")); else show($("e3-unavailable"));
    $("e3-add-btn").disabled = !writable || busy;
    $("e3-add-btn").textContent = adding ? "正在添加…" : "添加客户端";
    $("e3-add-name").disabled = !writable || busy;
    $("e3-del-btn").disabled = !writable || busy;
    $("e3-del-btn").textContent = deleting ? "正在删除…" : "永久删除";
    // A delete already dispatched (step-up or wire) cannot be "cancelled"
    // by the UI: the transaction is real, so the Cancel control locks with
    // it. Once the POST reaches a terminal verdict the panel is closed or
    // the retry contract owns the view again.
    $("e3-del-cancel").disabled = deleting && state.e3Mutation.inFlight;
    if (!writable) closeDeleteConfirm();
    if (state.e3Clients) renderE3Clients(state.e3Clients);
    if (p6View.name && $("p6-device-panel")) renderP6Devices();
  }

  function loadE3Clients() {
    if (!state.session || !state.session.authenticated) return;
    // 0.1.4 review (blocker 2): suppressed at the entry while a convergence
    // owns the view -- see loadE3Status above.
    if (state.e3Convergence) return Promise.resolve();
    // 0.1.4: the list gets the same generation discipline the status read
    // already had -- a convergence apply (or a newer poll) retires anything
    // still in flight, so an old list response can never overwrite the view.
    var generation = state.e3ClientsGeneration =
        (state.e3ClientsGeneration || 0) + 1;
    return api("/api/v1/clients").then(function (data) {
      if (generation !== state.e3ClientsGeneration || state.e3Convergence) return;
      state.e3Clients = data;
      renderE3Clients(data);
    }).catch(function (error) {
      if (generation !== state.e3ClientsGeneration || state.e3Convergence) return;
      // B4: only error/fixed text here -- never an undefined variable.
      var body = $("e3-clients-body");
      body.innerHTML = "";
      var row = body.insertRow(-1);
      var cell = row.insertCell(-1);
      cell.colSpan = 3;
      cell.textContent = "客户端列表暂不可用。";
    });
  }

  function supersedePlainReads() {
    // Bump both read generations: anything in flight is retired the moment
    // a convergence starts AND again when it lands (a poll issued during
    // the convergence window carries data the server answered BEFORE the
    // freshest truth and must never overwrite the applied pair).
    state.e3StatusGeneration = (state.e3StatusGeneration || 0) + 1;
    state.e3ClientsGeneration = (state.e3ClientsGeneration || 0) + 1;
  }

  function convergeAfterMutation() {
    // 0.1.4 post-mutation convergence: ONE session-gated, read-only server
    // round-trip (GET /api/v1/clients/convergence) that force-refreshes
    // management.status THEN client.list and answers ok ONLY when both are
    // fresh. The frontend applies the pair atomically -- badge, controls
    // and table all move on the same render pass, so the ~2-5s
    // "不可用" window created by the separate TTL-gated reads is gone
    // and no half-fresh state is ever displayed. Convergence outranks the
    // watchdog: generations retire every older in-flight status/list read
    // at start and at apply. Failure fails closed (status cleared ->
    // e3Writable() false -> no controls): never a fake Available, never a
    // sleep, never a retry loop. Like the 0.1.3 helper it never touches
    // #e3-msg, so the success copy survives.
    supersedePlainReads();
    var token = state.e3Convergence = {};   // last call wins
    return api("/api/v1/clients/convergence").then(function (data) {
      if (state.e3Convergence !== token) return;   // superseded
      state.e3Convergence = null;
      var s = data && data.status;
      var c = data && data.clients;
      if (!data || data.ok !== true || !s || !c ||
          s.transport !== "fresh" || c.transport !== "fresh") {
        // Defence in depth: a non-all-fresh body is treated exactly like a
        // failure -- fail closed, do not render a half-truth.
        supersedePlainReads();
        state.e3Status = null;
        renderE3Controls();
        return;
      }
      supersedePlainReads();
      state.e3Status = s;
      state.e3StatusAt = Date.now();
      state.e3Clients = c;
      renderE3Controls();   // one atomic pass: controls + table together
    }).catch(function () {
      if (state.e3Convergence !== token) return;
      state.e3Convergence = null;
      supersedePlainReads();
      state.e3Status = null;   // fail closed; the list stays but unwritable
      renderE3Controls();
    });
  }

  function renderE3Clients(data) {
    var body = $("e3-clients-body");
    body.innerHTML = "";
    var clients = (data.data && data.data.clients) || [];
    var writable = e3Writable() && !state.e3PendingRetry;
    clients.forEach(function (client) {
      var row = body.insertRow(-1);
      row.insertCell(-1).textContent = clientLabel(client.name);
      row.insertCell(-1).textContent = (client.protocols || []).map(protocolLabel).join(", ");
      var actions = row.insertCell(-1);
      // B4: no client-management control at all while the view is not
      // writable. M4: Download is offered for EVERY client, Default
      // included -- exporting the shared account's config was the gap this
      // release closes. Delete keeps its original rules (never Default).
      if (writable) {
        var dl = document.createElement("button");
        dl.className = "btn ghost";
        dl.type = "button";
        dl.textContent = "下载 YAML";
        dl.addEventListener("click", function () {
          downloadConfig(client.name);
        });
        actions.appendChild(dl);
      }
      if (client.name !== "legacy" && client.mutable && writable) {
        var btn = document.createElement("button");
        btn.className = "btn ghost";
        btn.type = "button";
        btn.textContent = "删除";
        // 0.1.5: any in-flight mutation also locks the row entrances
        // (Download above is a read and deliberately keeps its own gate).
        if (state.e3Mutation) btn.disabled = true;
        btn.addEventListener("click", function () {
          beginDeleteClient(client.name);
        });
        actions.appendChild(btn);
      }
      if (writable && client.name !== "legacy") {
        var devices = document.createElement("button");
        devices.className = "btn ghost";
        devices.type = "button";
        devices.textContent = "设备 / 客户端包";
        devices.disabled = !!state.e3Mutation;
        devices.addEventListener("click", function () { openP6Devices(client.name); });
        actions.appendChild(devices);
      }
    });
    if (!clients.length) {
      var row = body.insertRow(-1);
      var cell = row.insertCell(-1);
      cell.colSpan = 3;
      cell.textContent = "暂无客户端。";
    }
  }

  function beginDeleteClient(name) {
    // 0.1.5 (#36): one row Delete click only OPENS a confirmation bound to
    // exactly this client; the deliberate second step is "Delete
    // permanently". No name re-typing -- the wire body still echoes
    // confirm==name, which the server re-validates as a target-binding
    // defence in depth (plus the fresh-list preflight right before
    // dispatch, the reserved/mutable rules and step-up auth).
    if (state.e3Mutation || state.e3PendingRetry) return;
    if (!e3Writable() || name === "legacy") return;
    $("e3-del-name").textContent = name;
    $("e3-del-btn").setAttribute("data-name", name);   // bind BEFORE show/focus
    show($("e3-delete-box"));
    e3Message("", false);
    hide($("e3-msg"));
    // Focus the SAFE control: keyboard Enter/Space must never land on the
    // destructive button by default.
    $("e3-del-cancel").focus();
  }

  function closeDeleteConfirm() {
    // The single exit for the confirmation panel: hides it AND clears the
    // bound target, so a hidden panel can never keep a usable stale
    // data-name for a stray click. Cancel, loss of writability, a pending
    // retry and a successful delete all route through here.
    hide($("e3-delete-box"));
    $("e3-del-btn").removeAttribute("data-name");
    $("e3-del-name").textContent = "";
  }

  function setMutation(kind, name) {
    // 0.1.5 (#36): UI/single-flight lock around add+delete. Rendered
    // synchronously BEFORE dispatch so the busy state is visible for the
    // whole operation. Add no longer performs password step-up.
    state.e3Mutation = {kind: kind, name: name, inFlight: true};
    renderE3Controls();
  }

  function clearMutation() {
    if (!state.e3Mutation) return;
    state.e3Mutation = null;
    renderE3Controls();
  }

  function deleteClient(name, keyOverride) {
    // B3-final fail-safe + 0.1.5 single-flight: neither a pending uncertain
    // operation nor an in-flight local mutation may dispatch a second one.
    if (state.e3PendingRetry || state.e3Mutation) return;
    if (!e3Writable() || name === "legacy") return;
    var key = keyOverride || newIdempotencyKey();
    setMutation("delete", name);
    // B3: an explicit retry replays with the SAME key; a fresh click on the
    // delete button is a NEW operation and gets a NEW key.
    apiWithStepUp("/api/v1/clients/delete", {
      method: "POST",
      idempotencyKey: key,
      body: { name: name, confirm: name }
    }).then(function () {
      setPendingRetry(null);
      closeDeleteConfirm();
      e3Message("客户端已删除。", false);
      loadSession();
      // 0.1.4: the single convergence read applies fresh status+list
      // atomically (the server caches are already invalidated for this
      // confirmed delete). 0.1.5: the mutation lock is held THROUGH the
      // convergence -- clearing it at POST-resolve would let a second
      // mutation race against the fresh read still in flight.
      if (state.e3Mutation) state.e3Mutation.inFlight = false;
      convergeAfterMutation().then(clearMutation);
    }).catch(function (error) {
      if (error.status === 504 && error.uncertain) {
        setPendingRetry({ path: "/api/v1/clients/delete", name: name,
                          idempotencyKey: key,
                          body: { name: name, confirm: name } });
        // Ownership transfers to the pending-retry fail-safe, which keeps
        // the ordinary entrances locked; clear the mutation lock AFTER it.
        clearMutation();
        e3Message(RESULT_UNCONFIRMED, true);
        loadE3Clients();
        loadE3Status();
        return;
      }
      setPendingRetry(null);
      clearMutation();
      if (error.code === "E_RECONCILE_CONFLICT") {
        e3Message("服务器上的客户端已重建或轮换，请刷新并重新核验，本次删除未自动重试。", true);
        loadE3Clients();
        loadE3Status();
        return;
      }
      if (error.code === "E_NOT_FOUND") {
        e3Message("最新列表中没有此客户端，未执行删除。", true);
        loadE3Clients();
        return;
      }
      e3Message(CLIENT_UNAVAILABLE, true);
      loadE3Clients();
      loadE3Status();
    });
  }

  function downloadConfig(name) {
    // M4: export is a READ -- no idempotency key, no ledger, and a pending
    // uncertain MUTATION still blocks it (same view lock). The response is
    // raw file bytes: they go straight into a Blob and a same-click
    // programmatic download, and the object URL is revoked right after.
    // The YAML never touches the DOM, the console, or any storage.
    if (state.e3PendingRetry) return;
    if (!e3Writable()) return;
    e3Message("正在准备下载…", false);
    apiWithStepUp("/api/v1/clients/export", {
      method: "POST",
      body: { name: name },
      raw: true            // no Idempotency-Key header on this request
    }).then(function (response) {
      return response.blob().then(function (blob) {
        var url = URL.createObjectURL(blob);
        var a = document.createElement("a");
        a.href = url;
        a.download = name + "-mihomo.yaml";
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        e3Message("YAML 配置已下载。", false);
      });
    }).catch(function (error) {
      if (error.status === 504 && error.uncertain) {
        // The export may have been answered on the wire; nothing changed
        // server-side, so retrying is simply clicking Download again.
        e3Message("下载结果尚未确认，请刷新状态后手动重试下载。", true);
        loadE3Status();
        return;
      }
      if (error.message === "step-up cancelled") {
        hide($("e3-msg"));
        return;
      }
      e3Message("配置下载失败，服务器配置未被修改。", true);
      loadE3Status();
    });
  }

  function p6Message(text, error) {
    var el = $("p6-msg");
    el.textContent = text;
    el.className = "form-msg " + (error ? "error" : "ok");
    show(el);
  }

  function p6Controls() {
    ["p6-enroll", "p6-refresh", "p6-next", "p6-close"].forEach(function (id) {
      $(id).disabled = p6View.busy || !e3Writable() || !!state.e3Mutation;
    });
    $("p6-enroll").disabled = $("p6-enroll").disabled || !!p6View.retry;
    $("p6-retry").disabled = p6View.busy || !e3Writable();
    if (p6View.retry) show($("p6-retry")); else hide($("p6-retry"));
    if (p6View.next) show($("p6-next")); else hide($("p6-next"));
    ["p6-device-name", "p6-site-label", "p6-path-label"].forEach(function (id) {
      $(id).disabled = p6View.busy || !!p6View.retry || !e3Writable();
    });
  }

  function renderP6Devices() {
    var tbody = $("p6-devices-body");
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    p6View.rows.forEach(function (device) {
      var row = tbody.insertRow(-1);
      row.insertCell(-1).textContent = device.device + " / " + device.probe_id.slice(0, 11);
      var confirmed = device.desired === device.verified;
      row.insertCell(-1).textContent = confirmed
        ? (device.desired === "active" ? "登记已确认" : "撤销已确认")
        : (device.desired === "active" ? "登记待确认" : "撤销待确认");
      var cell = row.insertCell(-1);
      function action(text, call) {
        var button = document.createElement("button");
        button.className = "btn ghost";
        button.type = "button";
        button.textContent = text;
        button.disabled = p6View.busy || !!p6View.retry || !e3Writable() || !!state.e3Mutation;
        button.addEventListener("click", call);
        cell.appendChild(button);
      }
      if (device.desired === "active" && device.verified === "active") {
        action("下载客户端包", function () { downloadP6Bundle(device.device); });
      }
      if (device.desired === "active" && !confirmed) {
        action("重新核验", function () {
          p6Operate("resume", {name: p6View.name, device: device.device});
        });
      }
      if (device.desired === "active" || !confirmed) {
        action(device.desired === "active" ? "撤销上传权限" : "重试撤销", function () {
          if (device.desired === "active" && !window.confirm("是否撤销此设备的 P6 上传权限？代理账号仍会保留。")) return;
          p6Operate("revoke", {name: p6View.name, device: device.device, probe_id: device.probe_id});
        });
      }
    });
    p6Controls();
  }

  function openP6Devices(name) {
    if (p6View.busy || !e3Writable() || state.e3Mutation) return;
    if (p6View.retry && p6View.name !== name) {
      e3Message("请先确认上一次设备操作的结果。", true);
      return;
    }
    p6View.name = name;
    $("p6-client-name").textContent = name;
    show($("p6-device-panel"));
    loadP6Devices();
  }

  function loadP6Devices(cursor) {
    if (p6View.busy || !p6View.name || !e3Writable()) return;
    p6View.busy = true;
    renderP6Devices();
    var payload = {name: p6View.name};
    if (cursor) payload.cursor = cursor;
    api("/api/v1/clients/probes/list", {method: "POST", body: payload}).then(function (result) {
      p6View.rows = result.data.devices;
      p6View.next = result.data.next_cursor;
      var pending = p6View.retry;
      if (pending && p6View.rows.some(function (row) {
        return row.device === pending.body.device && row.verified === row.desired &&
          (pending.op !== "revoke" || row.probe_id === pending.body.probe_id) &&
          row.desired === (pending.op === "revoke" ? "revoked" : "active");
      })) p6View.retry = null;
    }).catch(function () {
      p6View.rows = [];
      p6View.next = null;
      p6Message("设备状态暂不可用，尚未确认任何登记或撤销结果。", true);
    }).then(function () {
      p6View.busy = false;
      renderP6Devices();
    });
  }

  function p6Operate(op, body, key, retry) {
    if (p6View.busy || !e3Writable() || state.e3Mutation || (p6View.retry && !retry)) return;
    p6View.busy = true;
    renderP6Devices();
    var intent = {op: op, body: body, key: key};
    apiWithStepUp("/api/v1/clients/probes/" + op, {
      method: "POST", body: body, idempotencyKey: key
    }).then(function (result) {
      p6View.retry = null;
      if (op === "revoke") p6Message("服务器已确认撤销上传权限。", false);
      else p6Message(result.data.verified === "active"
        ? "设备登记已确认，可以下载该设备的客户端包。"
        : "此登记已撤销。", result.data.verified !== "active");
    }).catch(function (error) {
      if (error.message === "step-up cancelled") return;
      // A failed fetch/JSON read has no HTTP status and may have happened
      // after durable enrollment. Keep the exact intent until an explicit
      // retry or metadata confirmation resolves it; never generate a new key.
      if (error.uncertain || error.retriable || typeof error.status !== "number") p6View.retry = intent;
      p6Message(error.code === "E_P6_DEVICE_EXISTS"
        ? "该设备已有登记，请刷新列表后下载或核验。"
        : "操作结果尚未确认，请刷新设备状态后再重试。", true);
    }).then(function () {
      p6View.busy = false;
      renderP6Devices();
      loadP6Devices();
    });
  }

  function downloadP6Bundle(device) {
    if (p6View.busy || !e3Writable() || state.e3Mutation || p6View.retry) return;
    p6View.busy = true;
    renderP6Devices();
    var name = p6View.name;
    apiWithStepUp("/api/v1/clients/bundle", {
      method: "POST", body: {name: name, device: device}, raw: true
    }).then(function (response) { return response.blob(); }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var link = document.createElement("a");
      try {
        link.href = url;
        link.download = name + "-" + device + "-client-bundle.zip";
        document.body.appendChild(link);
        link.click();
      } finally {
        if (link.parentNode) link.parentNode.removeChild(link);
        URL.revokeObjectURL(url);
      }
      p6Message("客户端包已下载，请妥善保管其中的设备凭据。", false);
    }).catch(function (error) {
      if (error.message === "step-up cancelled") return;
      p6Message(error.code === "E_P6_ARTIFACT"
        ? "客户端包读取失败，请让管理员检查通用 Agent 文件的权限、完整性及版本是否一致。"
        : "客户端包下载失败，请刷新设备状态后手动重试。", true);
    }).then(function () { p6View.busy = false; renderP6Devices(); });
  }

  function addClient(name, keyOverride) {
    // B3-final fail-safe + 0.1.5 single-flight: a pending uncertain
    // operation OR an in-flight mutation locks the ordinary entrance -- no
    // new key is ever generated while one is unresolved.
    if (state.e3PendingRetry || state.e3Mutation) return;
    if (!e3Writable()) return;
    var key = keyOverride || newIdempotencyKey();
    setMutation("add", name);
    api("/api/v1/clients/add", {
      method: "POST",
      idempotencyKey: key,
      body: { name: name }
    }).then(function (data) {
      setPendingRetry(null);
      e3Message("客户端已创建，可在下方下载 YAML 配置。",
                false);
      $("e3-add-name").value = "";
      // 0.1.4: the single convergence read applies fresh status+list
      // atomically (the server caches are already invalidated for this
      // confirmed add). 0.1.5: the lock is held until convergence settles.
      if (state.e3Mutation) state.e3Mutation.inFlight = false;
      convergeAfterMutation().then(clearMutation);
    }).catch(function (error) {
      if (error.status === 504 && error.uncertain) {
        setPendingRetry({ path: "/api/v1/clients/add", name: name,
                          idempotencyKey: key, body: { name: name } });
        clearMutation();   // pending-retry takes over the lock
        e3Message(RESULT_UNCONFIRMED, true);
        loadE3Clients();
        loadE3Status();
        return;
      }
      setPendingRetry(null);
      clearMutation();
      if (error.code === "E_RECONCILE_CONFLICT") {
        e3Message("请求处理期间服务器状态发生变化。" +
                  "请刷新并重新核验，本次请求未自动重试。",
                  true);
        loadE3Clients();
        loadE3Status();
        return;
      }
      e3Message(CLIENT_UNAVAILABLE, true);
      loadE3Clients();
      loadE3Status();
    });
  }

  /* ---------- settings: access control ---------- */

  function loadAccess() {
    api("/api/v1/whitelist").then(function (data) {
      state.whitelist = data;
      renderAccess(data);
    }).catch(function () { /* view not open or not permitted */ });
  }

  function renderWhitelistFromSession() {
    if (state.session && $("wl-current").textContent === "—") {
      $("wl-current").textContent = state.session.current_ip;
    }
  }

  function renderAccess(data) {
    $("wl-current").textContent = data.current_ip;
    var list = $("wl-list");
    list.textContent = "";
    (data.whitelist || []).forEach(function (entry) {
      var li = document.createElement("li");
      var label = document.createElement("span");
      label.textContent = entry;
      li.appendChild(label);
      var remove = document.createElement("button");
      remove.type = "button";
      remove.className = "btn danger";
      remove.textContent = "移除";
      remove.addEventListener("click", function () { removeEntry(entry); });
      li.appendChild(remove);
      list.appendChild(li);
    });
    if (!(data.whitelist || []).length) {
      var empty = document.createElement("li");
      empty.className = "muted";
      empty.style.fontFamily = "inherit";
      empty.textContent = "白名单为空，仅本机或 SSH 隧道可访问监控页面。";
      list.appendChild(empty);
    }
  }

  function wlMessage(text, isError) {
    var el = $("wl-msg");
    el.textContent = text;
    el.className = "form-msg " + (isError ? "error" : "ok");
    show(el);
  }

  function addEntry(entry) {
    api("/api/v1/whitelist", { method: "POST", body: { entry: entry } })
      .then(function () {
        $("wl-add-input").value = "";
        wlMessage("已添加 " + entry, false);
        loadAccess();
      })
      .catch(function (error) { wlMessage(errorText(error), true); });
  }

  function removeEntry(entry, confirmed) {
    // Server-authoritative two-phase flow: the FIRST request never carries
    // confirm -- the server decides whether the entry covers the caller's
    // source address and answers 409 if so. Only after the user confirms
    // the lock-out warning is the confirmed retry sent.
    var body = { entry: entry };
    if (confirmed) { body.confirm = true; }
    api("/api/v1/whitelist/remove", { method: "POST", body: body })
      .then(function () { wlMessage("已移除 " + entry, false); loadAccess(); })
      .catch(function (error) {
        if (error.status === 409 && !confirmed &&
            window.confirm("移除此条目将使当前浏览器失去访问权限。\n" +
                           "之后需要恢复密钥才能访问，是否继续？")) {
          removeEntry(entry, true);
          return;
        }
        wlMessage(errorText(error), true);
      });
  }

  /* ---------- settings: password + recovery ---------- */

  function pwMessage(text, isError) {
    var el = $("pw-msg");
    el.textContent = text;
    el.className = "form-msg " + (isError ? "error" : "ok");
    show(el);
  }

  function changePassword(event) {
    event.preventDefault();
    var current = $("pw-current").value;
    var next = $("pw-new").value;
    var repeat = $("pw-repeat").value;
    if (next.length < 8) { pwMessage("新密码至少需要 8 个字符。", true); return; }
    if (next !== repeat) { pwMessage("两次输入的新密码不一致。", true); return; }
    api("/api/v1/password", {
      method: "POST",
      body: { current_password: current, new_password: next }
    }).then(function () {
      $("pw-form").reset();
      pwMessage("密码已修改。", false);
    }).catch(function (error) { pwMessage(errorText(error), true); });
  }

  function rotateRecovery() {
    var current = window.prompt("请输入当前管理员密码，以重新生成恢复密钥：");
    if (current === null) return;
    api("/api/v1/recovery/rotate", {
      method: "POST", body: { current_password: current }
    }).then(function (data) {
      var el = $("rec-result");
      el.textContent = "新恢复密钥（仅显示一次，请立即保存）：" +
        data.recovery_key;
      show(el);
      loadSession();
    }).catch(function (error) {
      var el = $("rec-result");
      el.textContent = "失败：" + errorText(error);
      show(el);
    });
  }

  /* ---------- session / login / recovery ---------- */

  function loadSession() {
    return api("/api/v1/session").then(function (data) {
      state.session = data;
      $("rec-status").textContent =
        data.recovery_configured ? "已配置 ✓" : "未配置";
      renderWhitelistFromSession();
      return data;
    });
  }

  function showLogin(message) {
    hide($("app"));
    hide($("recovery-view"));
    show($("login-overlay"));
    var error = $("login-error");
    if (message) { error.textContent = message; show(error); }
    else hide(error);
    $("login-password").focus();
  }

  function login(event) {
    event.preventDefault();
    var password = $("login-password").value;
    api("/api/v1/login", { method: "POST", body: { password: password } })
      .then(function () {
        $("login-password").value = "";
        startDashboard();
      })
      .catch(function (error) {
        var message = error.status === 429
          ? "失败次数过多，已暂时锁定，请稍后重试。"
          : "密码无效。";
        showLogin(message);
      });
  }

  function logout() {
    api("/api/v1/logout", { method: "POST" }).then(reload, reload);
  }

  function reload() { window.location.reload(); }

  function submitRecovery(event) {
    event.preventDefault();
    var key = $("recovery-key").value;
    var message = $("recovery-msg");
    api("/api/v1/recovery", { method: "POST", body: { key: key } })
      .then(function (data) {
        message.textContent = "已恢复访问，当前 IP（" + data.ip + "）已加入白名单，请正常登录。";
        message.className = "form-msg ok";
        show(message);
        $("recovery-key").value = "";
      })
      .catch(function (error) {
        message.textContent = error.status === 429
          ? "尝试次数过多，已暂时锁定，请稍后重试。"
          : errorText(error);
        message.className = "form-msg error";
        show(message);
      });
  }

  /* ---------- live updates ---------- */

  function startStream() {
    if (state.es) { state.es.close(); }
    var generation = ++state.esGeneration;
    var source = new EventSource("/api/v1/stream");
    state.es = source;
    source.addEventListener("snapshot", function (event) {
      if (generation !== state.esGeneration) return;
      try {
        state.snapshot = JSON.parse(event.data);
        state.lastSnapshotAt = Date.now();
        render();
      } catch (err) { /* malformed frame: ignore, next tick arrives */ }
    });
    source.onopen = function () {
      setChip($("chip-monitor"), "监控", "connecting", "unknown");
    };
    source.onerror = function () {
      // EventSource retries automatically (server hints retry: 3000).
      // Detect an expired session instead of retrying forever.
      if (generation !== state.esGeneration) return;
      api("/api/v1/session").then(function (data) {
        if (!data.authenticated) {
          state.esGeneration++;
          source.close();
          showLogin("登录已过期，请重新登录。");
        }
      }).catch(function () { /* transient; EventSource keeps retrying */ });
    };
  }

  function startWatchdog() {
    setInterval(function () {
      if (!state.session || !state.session.authenticated) return;
      if (state.view === "settings") loadE3Status(true);
      // Fallback poll if the SSE stream is not delivering. Freshness only
      // advances when the snapshot VERSION truly moves: a frozen publisher
      // answering HTTP 200 with the same payload must never keep the
      // watchdog healthy by itself.
      if (Date.now() - state.lastSnapshotAt > 10000) {
        api("/api/v1/snapshot").then(function (snap) {
          if ((snap.snapshot_version || 0) > state.lastVersion) {
            state.lastSnapshotAt = Date.now();
          }
          state.snapshot = snap;
          render();
        }).catch(function () { /* ignored; stream may recover */ });
      }
      if (state.es && state.es.readyState === 2) { startStream(); }
    }, 5000);
  }

  function startDashboard() {
    hide($("login-overlay"));
    hide($("recovery-view"));
    show($("app"));
    loadSession().then(function (session) {
      state.session = session;
      if (!session.authenticated) { showLogin(); return null; }
      setView("overview");
      return api("/api/v1/snapshot").then(function (snap) {
        state.snapshot = snap;
        state.lastSnapshotAt = Date.now();
        render();
        startStream();
        startWatchdog();
      });
    }).catch(function (error) {
      showLogin(error.status === 403
        ? "当前地址不在白名单中，请使用恢复密钥。"
        : "无法连接监控 API。");
    });
  }

  /* ---------- wiring ---------- */

  function bind() {
    if ($("p6-enroll-form")) {
      $("p6-enroll-form").addEventListener("submit", function (event) {
        event.preventDefault();
        p6Operate("enroll", {name: p6View.name, device: $("p6-device-name").value.trim(),
          site_label: $("p6-site-label").value.trim(), path_label: $("p6-path-label").value.trim()}, newIdempotencyKey());
      });
      $("p6-refresh").addEventListener("click", function () { loadP6Devices(); });
      $("p6-next").addEventListener("click", function () { loadP6Devices(p6View.next); });
      $("p6-close").addEventListener("click", function () { if (!p6View.busy) hide($("p6-device-panel")); });
      $("p6-retry").addEventListener("click", function () {
        var pending = p6View.retry;
        if (pending) p6Operate(pending.op, pending.body, pending.key, true);
      });
    }
    document.querySelectorAll(".nav-item").forEach(function (item) {
      item.addEventListener("click", function () {
        setView(item.getAttribute("data-view"));
      });
    });
    $("logout-btn").addEventListener("click", logout);
    $("login-form").addEventListener("submit", login);
    $("recovery-form").addEventListener("submit", submitRecovery);
    $("pw-form").addEventListener("submit", changePassword);
    $("rec-rotate-btn").addEventListener("click", rotateRecovery);
    $("e3-refresh").addEventListener("click", function () {
      loadE3Status();
      loadE3Clients();
    });
    $("e3-add-btn").addEventListener("click", function () {
      var name = $("e3-add-name").value.trim();
      if (name) addClient(name);
    });
    $("e3-add-name").addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        var name = $("e3-add-name").value.trim();
        if (name) addClient(name);
      }
    });
    $("e3-del-btn").addEventListener("click", function () {
      // 0.1.5 (#36): no name re-typing gate. The confirmation was opened
      // with a bound data-name (set before the panel shows); this deliberate
      // second click IS the guard. deleteClient re-checks writability,
      // pending-retry and the single-flight lock, and the server re-checks
      // confirm==name plus the fresh-list preflight.
      var name = $("e3-del-btn").getAttribute("data-name");
      if (!name) return;   // unbound / already-closed panel dispatches nothing
      deleteClient(name);
    });
    $("e3-del-cancel").addEventListener("click", function () {
      closeDeleteConfirm();
    });
    $("e3-retry-btn").addEventListener("click", retryPending);
    $("wl-add-btn").addEventListener("click", function () {
      var value = $("wl-add-input").value.trim();
      if (value) addEntry(value);
    });
    $("wl-add-input").addEventListener("keydown", function (event) {
      if (event.key === "Enter") {
        event.preventDefault();
        var value = $("wl-add-input").value.trim();
        if (value) addEntry(value);
      }
    });
    $("wl-add-current").addEventListener("click", function () {
      if (state.session && state.session.current_ip) {
        addEntry(state.session.current_ip);
      }
    });
    // Scoped to the connections filter: the evidence drill-down has its
    // own .seg-item group (#inc-sections) with its own handler below.
    document.querySelectorAll("#conn-filter .seg-item").forEach(function (item) {
      item.addEventListener("click", function () {
        state.filter = item.getAttribute("data-filter");
        document.querySelectorAll("#conn-filter .seg-item").forEach(function (other) {
          other.classList.toggle("active", other === item);
        });
        if (state.snapshot) renderConnections(state.snapshot.connections || []);
      });
    });
    $("inc-refresh-btn").addEventListener("click", function () {
      loadIncidents();
      loadMarkers();
    });
    $("inc-back-btn").addEventListener("click", closeIncidentDetail);
    $("inc-evidence-close").addEventListener("click", function () {
      state.incSubject = null;
      hide($("inc-evidence-card"));
    });
    $("inc-marker-add-btn").addEventListener("click", addMarker);
    $("inc-rearm-btn").addEventListener("click", rearmIncidents);
    document.querySelectorAll("#inc-sections .seg-item").forEach(function (item) {
      item.addEventListener("click", function () {
        loadEvidence(item.getAttribute("data-section"));
      });
    });
  }

  function boot() {
    bind();
    if (window.location.pathname === "/recovery") {
      hide($("app"));
      show($("recovery-view"));
      $("recovery-key").focus();
      return;
    }
    startDashboard();
  }

  document.addEventListener("DOMContentLoaded", boot);
})();
