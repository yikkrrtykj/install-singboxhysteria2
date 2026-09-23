/* sing-box Monitor — Phase E2 dashboard logic (vanilla JS, no dependencies).
 *
 * Data source: the E1 snapshot ONLY (GET /api/v1/snapshot + SSE stream).
 * Stale semantics are inherited verbatim: when snapshot.stale is true the
 * last state keeps being rendered and an explicit banner says so — the
 * dashboard never fakes zeros, never clears devices, never invents CLOSED.
 */
(function () {
  "use strict";

  var PROTOCOL_LABELS = { "vless-in": "Reality", "hy2-in": "Hysteria2",
                          reality: "Reality", hy2: "Hysteria2", hysteria2: "Hysteria2" };
  function clientLabel(name) { return name === "legacy" ? "Default" : name; }
  function protocolLabel(tag) { return PROTOCOL_LABELS[tag] || "Other"; }
  var CLIENT_UNAVAILABLE = "Client management is temporarily unavailable. Check the server before making changes.";
  var RESULT_UNCONFIRMED = "The result is not confirmed yet. Refresh the client list before retrying. Do not start another change until the current state is confirmed.";

  var state = {
    snapshot: null,
    session: null,
    whitelist: null,
    filter: "all",
    view: "overview",
    es: null,
    esGeneration: 0,
    lastSnapshotAt: 0,
    lastVersion: 0
  };

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
    function done() { toast(label || "Copied"); }
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
        if (!password) { fail("Password required."); return; }
        api("/api/v1/step-up", { method: "POST", body: { password: password } })
          .then(function () {
            close();
            loadSession().catch(function () { /* status refresh is best effort */ });
            resolve();
          })
          .catch(function (error) {
            if (error.status === 429) {
              fail("Too many failed attempts — try again later.");
            } else if (error.status === 401) {
              fail("Incorrect password.");
            } else {
              fail(error.message);
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

  var VIEW_TITLES = { overview: "Overview", devices: "Devices",
                      connections: "Connections", settings: "Settings" };

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
  }

  /* ---------- rendering ---------- */

  function setChip(el, label, status, stateName) {
    el.textContent = label + " · " + status;
    el.setAttribute("data-state", stateName);
  }

  function render() {
    var snap = state.snapshot;
    if (!snap) return;

    if (snap.snapshot_version && snap.snapshot_version > state.lastVersion) {
      state.lastVersion = snap.snapshot_version;
    }

    setChip($("chip-monitor"), "Monitor",
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
      banner.textContent = "Data stale — Last successful API event: " +
        fmtTime(snap.last_success_at);
      show($("stale-banner"));
    } else if (snap.web_status !== "HEALTHY") {
      banner.textContent = "Monitor data frozen — last publish: " +
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
      empty.textContent = "No devices observed yet.";
      grid.appendChild(empty);
      return;
    }
    var cardTemplate = $("device-card-template");
    var rowTemplate = $("protocol-row-template");
    devices.forEach(function (device) {
      var card = cardTemplate.content.cloneNode(true);
      card.querySelector(".device-name").textContent = clientLabel(device.name);
      var badge = card.querySelector(".device-status");
      badge.textContent = device.status;
      badge.className = "badge device-status " +
        (device.status === "ACTIVE" ? "active"
         : device.status === "RECENT ACTIVITY" ? "recent" : "idle");
      var container = card.querySelector(".device-protocols");
      var tags = Object.keys(device.protocols || {});
      if (!tags.length) {
        var none = document.createElement("div");
        none.className = "empty";
        none.textContent = "No traffic observed yet.";
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
      filtered.length + " of " + rows.length + " shown";
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
      idButton.title = "Copy full ID";
      idButton.addEventListener("click", function () {
        copyText(row.id, "Connection ID copied");
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
      badge.textContent = row.state;
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
    e3Message("Checking the previous change…", false);
    var dispatch = p.path === "/api/v1/clients/add" ? api : apiWithStepUp;
    dispatch(p.path, {
      method: "POST",
      idempotencyKey: p.idempotencyKey,   // exact same header value
      body: p.body
    }).then(function (data) {
      setPendingRetry(null);
      e3Message(p.name
        ? "Retry finished: the operation reached a terminal state."
        : "Retry finished.", false);
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
    setBadge($("e3-availability"), writable ? "Available" : "Unavailable",
             writable ? "ok" : "idle");
    if (writable) hide($("e3-unavailable")); else show($("e3-unavailable"));
    $("e3-add-btn").disabled = !writable || busy;
    $("e3-add-btn").textContent = adding ? "Adding…" : "Add client";
    $("e3-add-name").disabled = !writable || busy;
    $("e3-del-btn").disabled = !writable || busy;
    $("e3-del-btn").textContent = deleting ? "Deleting…" : "Delete permanently";
    // A delete already dispatched (step-up or wire) cannot be "cancelled"
    // by the UI: the transaction is real, so the Cancel control locks with
    // it. Once the POST reaches a terminal verdict the panel is closed or
    // the retry contract owns the view again.
    $("e3-del-cancel").disabled = deleting && state.e3Mutation.inFlight;
    if (!writable) closeDeleteConfirm();
    if (state.e3Clients) renderE3Clients(state.e3Clients);
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
      cell.textContent = "Client list unavailable.";
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
    // "Unavailable" window created by the separate TTL-gated reads is gone
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
        dl.textContent = "Download";
        dl.addEventListener("click", function () {
          downloadConfig(client.name);
        });
        actions.appendChild(dl);
      }
      if (client.name !== "legacy" && client.mutable && writable) {
        var btn = document.createElement("button");
        btn.className = "btn ghost";
        btn.type = "button";
        btn.textContent = "Delete";
        // 0.1.5: any in-flight mutation also locks the row entrances
        // (Download above is a read and deliberately keeps its own gate).
        if (state.e3Mutation) btn.disabled = true;
        btn.addEventListener("click", function () {
          beginDeleteClient(client.name);
        });
        actions.appendChild(btn);
      }
    });
    if (!clients.length) {
      var row = body.insertRow(-1);
      var cell = row.insertCell(-1);
      cell.colSpan = 3;
      cell.textContent = "No clients found.";
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
    // synchronously BEFORE network dispatch so the busy state is visible for
    // the whole operation. Delete may include step-up; Add deliberately does
    // not require a second password after login.
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
      e3Message("Client deleted.", false);
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
        e3Message("Server state changed: the client was rebuilt or rotated " +
                  "in the meantime. Refresh and re-check — the delete was " +
                  "not retried.", true);
        loadE3Clients();
        loadE3Status();
        return;
      }
      if (error.code === "E_NOT_FOUND") {
        e3Message("The client is not in the fresh server list; nothing was " +
                  "deleted.", true);
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
    e3Message("Preparing the download…", false);
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
        e3Message("Configuration downloaded.", false);
      });
    }).catch(function (error) {
      if (error.status === 504 && error.uncertain) {
        // The export may have been answered on the wire; nothing changed
        // server-side, so retrying is simply clicking Download again.
        e3Message("The export result is unknown. Refresh the status and try " +
                  "the download again.", true);
        loadE3Status();
        return;
      }
      if (error.message === "step-up cancelled") {
        hide($("e3-msg"));
        return;
      }
      e3Message("The configuration could not be downloaded. Nothing was " +
                "changed on the server.", true);
      loadE3Status();
    });
  }

  function addClient(name, keyOverride) {
    // B3-final fail-safe + 0.1.5 single-flight: a pending uncertain
    // operation OR an in-flight mutation locks the ordinary entrance -- no
    // new key is ever generated while one is unresolved.
    if (state.e3PendingRetry || state.e3Mutation) return;
    if (!e3Writable()) return;
    var key = keyOverride || newIdempotencyKey();
    setMutation("add", name);
    // UX contract: the authenticated admin session + CSRF token is enough
    // for client.add. Do NOT route Add through apiWithStepUp: logging in once
    // must not immediately ask for the same administrator password again.
    api("/api/v1/clients/add", {
      method: "POST",
      idempotencyKey: key,
      body: { name: name }
    }).then(function (data) {
      setPendingRetry(null);
      e3Message("Client created. Download its configuration below.",
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
        e3Message("Server state changed while the request was in flight. " +
                  "Refresh and re-check — this request was not retried.",
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
      remove.textContent = "Remove";
      remove.addEventListener("click", function () { removeEntry(entry); });
      li.appendChild(remove);
      list.appendChild(li);
    });
    if (!(data.whitelist || []).length) {
      var empty = document.createElement("li");
      empty.className = "muted";
      empty.style.fontFamily = "inherit";
      empty.textContent = "Whitelist is empty — only loopback can reach the dashboard.";
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
        wlMessage("Added " + entry, false);
        loadAccess();
      })
      .catch(function (error) { wlMessage(error.message, true); });
  }

  function removeEntry(entry, confirmed) {
    // Server-authoritative two-phase flow: the FIRST request never carries
    // confirm -- the server decides whether the entry covers the caller's
    // source address and answers 409 if so. Only after the user confirms
    // the lock-out warning is the confirmed retry sent.
    var body = { entry: entry };
    if (confirmed) { body.confirm = true; }
    api("/api/v1/whitelist/remove", { method: "POST", body: body })
      .then(function () { wlMessage("Removed " + entry, false); loadAccess(); })
      .catch(function (error) {
        if (error.status === 409 && !confirmed &&
            window.confirm("Removing this entry will lock this browser out.\n" +
                           "Recovery key will be required. Continue?")) {
          removeEntry(entry, true);
          return;
        }
        wlMessage(error.message, true);
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
    if (next.length < 8) { pwMessage("New password must be at least 8 characters.", true); return; }
    if (next !== repeat) { pwMessage("New passwords do not match.", true); return; }
    api("/api/v1/password", {
      method: "POST",
      body: { current_password: current, new_password: next }
    }).then(function () {
      $("pw-form").reset();
      pwMessage("Password changed.", false);
    }).catch(function (error) { pwMessage(error.message, true); });
  }

  function rotateRecovery() {
    var current = window.prompt("Confirm your current admin password to regenerate the recovery key:");
    if (current === null) return;
    api("/api/v1/recovery/rotate", {
      method: "POST", body: { current_password: current }
    }).then(function (data) {
      var el = $("rec-result");
      el.textContent = "New recovery key (shown ONLY once — store it now): " +
        data.recovery_key;
      show(el);
      loadSession();
    }).catch(function (error) {
      var el = $("rec-result");
      el.textContent = "Failed: " + error.message;
      show(el);
    });
  }

  /* ---------- session / login / recovery ---------- */

  function loadSession() {
    return api("/api/v1/session").then(function (data) {
      state.session = data;
      $("rec-status").textContent =
        data.recovery_configured ? "configured ✓" : "not configured";
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
          ? "Too many failed attempts — locked, try again later."
          : "Invalid password.";
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
        message.textContent = data.message +
          " Your IP (" + data.ip + ") was added. Please login normally.";
        message.className = "form-msg ok";
        show(message);
        $("recovery-key").value = "";
      })
      .catch(function (error) {
        message.textContent = error.status === 429
          ? "Too many attempts — locked, try again later."
          : error.message;
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
      setChip($("chip-monitor"), "Monitor", "connecting", "unknown");
    };
    source.onerror = function () {
      // EventSource retries automatically (server hints retry: 3000).
      // Detect an expired session instead of retrying forever.
      if (generation !== state.esGeneration) return;
      api("/api/v1/session").then(function (data) {
        if (!data.authenticated) {
          state.esGeneration++;
          source.close();
          showLogin("Session expired — please log in again.");
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
        ? "Your address is not whitelisted. Use the recovery key."
        : "Failed to reach the dashboard API.");
    });
  }

  /* ---------- wiring ---------- */

  function bind() {
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
    document.querySelectorAll(".seg-item").forEach(function (item) {
      item.addEventListener("click", function () {
        state.filter = item.getAttribute("data-filter");
        document.querySelectorAll(".seg-item").forEach(function (other) {
          other.classList.toggle("active", other === item);
        });
        if (state.snapshot) renderConnections(state.snapshot.connections || []);
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
