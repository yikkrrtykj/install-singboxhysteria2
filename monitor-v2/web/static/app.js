/* sing-box Monitor — Phase E2 dashboard logic (vanilla JS, no dependencies).
 *
 * Data source: the E1 snapshot ONLY (GET /api/v1/snapshot + SSE stream).
 * Stale semantics are inherited verbatim: when snapshot.stale is true the
 * last state keeps being rendered and an explicit banner says so — the
 * dashboard never fakes zeros, never clears devices, never invents CLOSED.
 */
(function () {
  "use strict";

  var PROTOCOL_LABELS = { "vless-in": "Reality", "hy2-in": "HY2" };

  var state = {
    snapshot: null,
    session: null,
    whitelist: null,
    filter: "all",
    view: "overview",
    es: null,
    esGeneration: 0,
    lastSnapshotAt: 0
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
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
      if (!CSRF_EXEMPT_PATHS.test(path) && state.session &&
          state.session.csrf_token) {
        init.headers["X-CSRF-Token"] = state.session.csrf_token;
      }
    }
    return fetch(path, init).then(function (response) {
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok) {
          var error = new Error(data.error || ("HTTP " + response.status));
          error.status = response.status;
          throw error;
        }
        return data;
      });
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
    if (name === "settings") loadAccess();
  }

  /* ---------- rendering ---------- */

  function setChip(el, label, status, stateName) {
    el.textContent = label + " · " + status;
    el.setAttribute("data-state", stateName);
  }

  function render() {
    var snap = state.snapshot;
    if (!snap) return;

    setChip($("chip-monitor"), "Monitor",
            snap.web_status || "—",
            snap.web_status === "HEALTHY" ? "ok" : "bad");
    setChip($("chip-api"), "sing-box API",
            snap.api_status || "—",
            snap.api_status === "CONNECTED" ? "ok" : "bad");

    if (snap.stale) {
      $("stale-time").textContent = fmtTime(snap.last_success_at);
      show($("stale-banner"));
    } else {
      hide($("stale-banner"));
    }

    $("st-uptime").textContent = fmtUptime(snap.collector_uptime_seconds);
    $("st-last-event").textContent = fmtTime(snap.last_success_at);
    $("st-generated").textContent = fmtTime(snap.snapshot_generated_at);

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
      card.querySelector(".device-name").textContent = device.name;
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
          PROTOCOL_LABELS[tag] || tag;
        row.querySelector(".proto-tag").textContent = tag;
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

      tr.appendChild(cellText(row.user));
      var proto = document.createElement("td");
      proto.textContent = (PROTOCOL_LABELS[row.inbound] || row.inbound) +
        " (" + row.inbound + ")";
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
    $("mi-batches").textContent = String(snap.batch_count ?? "—");
    $("mi-skipped").textContent = String(snap.skipped_events ?? "—");
    $("mi-conflicts").textContent = String(snap.identity_conflicts ?? "—");
    $("mi-abandoned").textContent = String(snap.abandoned_on_reset ?? "—");
    $("mi-error").textContent = snap.last_error ? String(snap.last_error) : "none";
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
      // Fallback poll if the SSE stream is not delivering.
      if (Date.now() - state.lastSnapshotAt > 10000) {
        api("/api/v1/snapshot").then(function (snap) {
          state.snapshot = snap;
          state.lastSnapshotAt = Date.now();
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
