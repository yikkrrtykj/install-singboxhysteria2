/* Execute the shipped JS against a small DOM populated from the shipped HTML.
 * No backend mutation: fetch is a response queue; assertions inspect rendered
 * text, controls and actual request headers, not private naming conventions. */
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'monitor-v2/web/static/index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'monitor-v2/web/static/app.js'), 'utf8');
let count = 0;
function check(name, fn) { fn(); count++; console.log('UI: ' + name); }
class Element {
  constructor(tag = 'div', attrs = {}) {
    this.tag = tag; this.attrs = attrs; this.children = []; this.text = '';
    this.className = attrs.class || ''; this.disabled = 'disabled' in attrs;
    this.value = ''; this.events = {};
    this.classList = {
      add: c => { if (!this.className.split(' ').includes(c)) this.className += ' ' + c; },
      remove: c => { this.className = this.className.split(' ').filter(x => x !== c).join(' '); },
      toggle: (c, on) => on ? this.classList.add(c) : this.classList.remove(c)
    };
  }
  set textContent(v) { this.text = String(v); this.children = []; }
  get textContent() { return this.text + this.children.map(c => c.textContent).join(' '); }
  set innerHTML(v) { assert.equal(v, ''); this.textContent = ''; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); return c; }
  click() { if (this.events.click) return this.events.click(); }
  insertRow() { return this.appendChild(new Element('tr')); }
  insertCell() { return this.appendChild(new Element('td')); }
  setAttribute(k, v) { this.attrs[k] = v; }
  removeAttribute(k) { delete this.attrs[k]; }
  getAttribute(k) { return this.attrs[k]; }
  addEventListener(k, fn) { this.events[k] = fn; }
  removeEventListener(k) { delete this.events[k]; }
  focus() {}
  querySelector(selector) {
    for (const c of this.children) {
      if (selector[0] === '.' && c.className.split(' ').includes(selector.slice(1))) return c;
      const found = c.querySelector(selector); if (found) return found;
    }
    return null;
  }
  cloneNode() {
    const n = new Element(this.tag, {...this.attrs}); n.text = this.text;
    n.children = this.children.map(c => c.cloneNode()); return n;
  }
}
const dom = new Element(), stack = [dom], ids = {};
for (const token of html.replace(/<!--[\s\S]*?-->/g, '').match(/<[^>]*>|[^<]+/g)) {
  if (token.startsWith('</')) { stack.pop(); continue; }
  if (token.startsWith('<!')) continue;
  if (token.startsWith('<')) {
    const tag = token.match(/^<([\w-]+)/)[1]; const attrs = {};
    for (const m of token.matchAll(/([\w-]+)="([^"]*)"/g)) attrs[m[1]] = m[2];
    if (/\sdisabled(?:\s|>)/.test(token)) attrs.disabled = '';
    const el = stack[stack.length - 1].appendChild(new Element(tag, attrs));
    if (attrs.id) ids[attrs.id] = el;
    if (tag === 'template') el.content = el;
    if (!['meta', 'link', 'input', 'br', 'hr', 'img'].includes(tag) && !token.endsWith('/>')) stack.push(el);
  } else stack[stack.length - 1].text += token;
}
const document = {
  getElementById(id) { assert.ok(ids[id], 'missing HTML element: ' + id); return ids[id]; },
  createElement: tag => new Element(tag), querySelectorAll: () => [], addEventListener() {},
  body: new Element('body')
};
const requests = [], responses = [];
const createdUrls = [], revokedUrls = [];
let urlSeq = 0;
const context = vm.createContext({ document, console, Uint8Array, Date,
  crypto: require('node:crypto').webcrypto, setTimeout() {}, clearTimeout() {},
  setInterval() {}, window: { location: {} },
  URL: { createObjectURL: () => { const u = 'blob:ui-test-' + (++urlSeq);
         createdUrls.push(u); return u; },
         revokeObjectURL: u => revokedUrls.push(u) },
  fetch: (url, init) => {
    requests.push({url, ...init});
    const response = responses.shift(); assert.ok(response, 'unexpected fetch ' + url);
    if (typeof response === 'function') return response();
    return Promise.resolve(response);
  }
});
vm.runInContext(app.replace('document.addEventListener("DOMContentLoaded", boot);',
  'globalThis.ui = {state, bind, render, loadSession, loadE3Status, loadE3Clients, convergeAfterMutation, renderE3Controls, renderE3Clients, renderMonitorInfo, addClient, deleteClient, downloadConfig, setPendingRetry, retryPending, apiWithStepUp, setView, loadIncidents, renderIncidents, openIncident, renderIncidentDetail, closeIncidentDetail, loadEvidence, loadMarkers, renderMarkers, addMarker, rearmIncidents, renderIncRuntime};'), context);
const ui = context.ui;
// 0.1.4: the convergence chain (mutation -> one endpoint -> apply) crosses
// several cross-realm promise reactions; 12 ticks starved it. Drain
// generously.
const flush = async () => { for (let i = 0; i < 64; i++) await Promise.resolve(); };
const response = (data, status = 200) => ({ok: status < 400, status, json: () => Promise.resolve(data)});
// M4: api(raw) hands the FILE response straight to the caller -- only blob().
const fileResponse = text => ({ok: true, status: 200, blob: () => Promise.resolve({size: text.length})});
const healthy = () => ({transport: 'fresh', data: {management_state: 'active', helper: {degraded: false, reconcile: 'clean'}, lock: {acquirable: true}}});
const clients = {data: {clients: [{name: 'legacy', mutable: false, source: 'untracked', protocols: ['reality', 'hy2']}, {name: 'alice', mutable: true, source: 'web', protocols: ['reality']}]}};
// 0.1.4: the convergence endpoint's success envelope -- one fresh status and
// one fresh list, delivered together as a single JSON body.
const conv = (status, list) => response({ok: true, status: status || healthy(),
  clients: {transport: 'fresh', data: (list || clients).data}});
function setStatus(s) { ui.state.e3Status = s; ui.state.e3StatusAt = Date.now(); ui.renderE3Controls(); }
function closed() {
  assert.equal(ids['e3-add-btn'].disabled, true);
  assert.equal(ids['e3-del-btn'].disabled, true);
  assert.equal(ids['e3-availability'].textContent, 'Unavailable');
  assert.ok(!ids['e3-clients-body'].textContent.includes('Delete'));
  assert.ok(!ids['e3-clients-body'].textContent.includes('Download'));
}
const forbidden = /\(E3\)|M0\.5|Management plane|privileged helper|Helper snapshot|Management mutations|Idempotency-Key|\bMUTABLE\b|\bSOURCE\b|Abandoned on reset|Batches processed|hy2-in|vless-in/i;
function productText() { assert.doesNotMatch(dom.textContent, forbidden); }
async function main() {
  ui.bind();
  check('initial HTML fails closed and contains no internal product copy', () => { assert.ok(ids['e3-add-btn'].disabled); productText(); });
  ui.state.session = {authenticated: true, management_active: false, csrf_token: 'csrf', version: '0.1.0'};
  ui.state.e3Clients = clients;
  responses.push(response(healthy())); await ui.loadE3Status();
  check('old inactive session + fresh active status => Available and Add enabled', () => { assert.equal(ids['e3-availability'].textContent, 'Available'); assert.equal(ids['e3-add-btn'].disabled, false); });
  ui.state.snapshot = {web_status: 'HEALTHY', devices: {legacy: {name: 'legacy', status: 'ACTIVE', protocols: {'hy2-in': {}, 'vless-in': {}}}}, connections: [{user: 'legacy', inbound: 'hy2-in', id: 'conn1'}]};
  ui.render();
  responses.push(response({...ui.state.session, management_active: false})); await ui.loadSession(); ui.render();
  check('session reload and subsequent snapshot do not overwrite availability', () => { assert.equal(ids['e3-availability'].textContent, 'Available'); assert.equal(ids['e3-add-btn'].disabled, false); });
  check('Default mapping in Devices, Connections and Clients leaves raw data intact', () => {
    for (const id of ['devices-grid', 'conn-tbody', 'e3-clients-body']) { assert.match(ids[id].textContent, /Default/); assert.doesNotMatch(ids[id].textContent, /legacy/); }
    assert.equal(clients.data.clients[0].name, 'legacy'); assert.equal(ui.state.snapshot.connections[0].user, 'legacy');
  });
  check('protocol labels hide inbound tags and client table has three columns', () => {
    productText(); assert.match(ids['devices-grid'].textContent, /Hysteria2/); assert.match(ids['devices-grid'].textContent, /Reality/);
    assert.equal(ids['e3-clients-body'].children[0].children.length, 3);
    assert.match(ids['e3-clients-body'].children[0].textContent, /Reality, Hysteria2/);
    assert.doesNotMatch(ids['e3-clients-body'].children[0].textContent, /Delete/);
    // M4: Download is offered for every client while writable, Default
    // included -- and it is the FIRST action cell entry.
    assert.match(ids['e3-clients-body'].children[0].textContent, /Download/);
  });
  const cases = {
    inactive: s => { s.data.management_state = 'inactive'; },
    active_stale: s => { s.data.management_state = 'active_stale'; },
    stale: s => { s.transport = 'stale'; }, unavailable: s => { s.transport = 'unavailable'; },
    degraded: s => { s.data.helper.degraded = true; },
    reconcile: s => { s.data.helper.reconcile = 'conflict'; },
    lock: s => { s.data.lock.acquirable = false; },
    missing_helper: s => { delete s.data.helper; }, missing_lock: s => { delete s.data.lock; },
    missing_degraded: s => { delete s.data.helper.degraded; }, missing_reconcile: s => { delete s.data.helper.reconcile; }
  };
  for (const [name, change] of Object.entries(cases)) {
    const s = healthy(); change(s); setStatus(s);
    check(name + ' removes Delete and Download, disables Add and handler dispatch', () => {
      closed(); const n = requests.length; ui.addClient('bob'); ui.deleteClient('alice'); ui.downloadConfig('alice'); assert.equal(requests.length, n); productText();
    });
  }
  setStatus(healthy());
  check('fresh active clean lock-free status restores Add and mutable Delete', () => { assert.equal(ids['e3-add-btn'].disabled, false); assert.match(ids['e3-clients-body'].children[1].textContent, /Delete/); assert.match(ids['e3-clients-body'].children[1].textContent, /Download/); });
  check('a locally expired fresh verdict fails closed even before a poll returns', () => {
    ui.state.e3StatusAt = Date.now() - 10001; ui.renderE3Controls(); closed();
    const n = requests.length; ui.addClient('bob'); ui.downloadConfig('alice'); assert.equal(requests.length, n);
  });
  setStatus(healthy());
  // actions cell: Download first, then Delete (mutable rows only)
  ids['e3-clients-body'].children[1].children[2].children[1].events.click();
  responses.push(response(healthy())); await ui.loadE3Status(true);
  check('healthy background refresh preserves an open delete confirmation', () => assert.ok(!ids['e3-delete-box'].className.includes('hidden')));
  check('reserved Default never offers Delete even if metadata incorrectly says mutable', () => {
    ui.renderE3Clients({data: {clients: [{name: 'legacy', mutable: true}]}});
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /Delete/);
    // M4: Default IS exportable -- the lifecycle gap this release closes.
    assert.match(ids['e3-clients-body'].textContent, /Download/);
    const n = requests.length; ui.deleteClient('legacy'); assert.equal(requests.length, n);
  });
  let finishOld;
  responses.push(() => new Promise(resolve => { finishOld = resolve; }));
  const old = ui.loadE3Status();
  check('pending refresh immediately closes controls', closed);
  responses.push(response({...healthy(), transport: 'stale'})); await ui.loadE3Status();
  finishOld(response(healthy())); await old;
  check('late old status response cannot override newer unavailable status', closed);
  setStatus(healthy()); responses.push(() => Promise.reject(new Error('network'))); await ui.loadE3Status();
  check('status request failure removes already-rendered Delete controls', closed);
  setStatus(healthy());
  responses.push(response({code: 'result_unknown', uncertain: true}, 504), response(clients), response(healthy()));
  ui.addClient('bob'); await flush();
  const original = requests.findLast(r => r.url === '/api/v1/clients/add');
  check('uncertain result locks new operations without automatic retry or internal copy', () => {
    closed(); assert.ok(ui.state.e3PendingRetry); productText();
    const n = requests.length; ui.addClient('bob'); ui.deleteClient('alice'); ui.downloadConfig('alice'); assert.equal(requests.length, n);
    assert.equal(requests.filter(r => r.url === '/api/v1/clients/add').length, 1);
  });
  responses.push(response({code: 'result_unknown', uncertain: true}, 504), response(healthy()));
  ui.retryPending(); await flush();
  check('explicit retry preserves body, CSRF and exact Idempotency-Key', () => {
    const retry = requests.findLast(r => r.url === '/api/v1/clients/add');
    assert.equal(retry.body, original.body); assert.equal(retry.headers['Idempotency-Key'], original.headers['Idempotency-Key']);
    assert.equal(retry.headers['X-CSRF-Token'], 'csrf'); closed(); productText();
  });
  ui.setPendingRetry(null); setStatus(healthy());
  responses.push(response({code: 'E_MANUAL_INTERVENTION', error: 'privileged helper Idempotency-Key'}, 409), response(clients), response(healthy()));
  ui.addClient('bob'); await flush();
  check('raw backend error detail is not rendered to the user', productText);

  // Product UX contract: Add client is session+CSRF only. It must never open
  // the password step-up panel or send /api/v1/step-up.
  setStatus(healthy());
  const addReqBefore = requests.filter(r => r.url === '/api/v1/clients/add').length;
  const stepReqBefore = requests.filter(r => r.url === '/api/v1/step-up').length;
  responses.push(response({}), conv());
  ui.addClient('no-password-again'); await flush();
  check('Add client dispatches without password step-up', () => {
    assert.equal(requests.filter(r => r.url === '/api/v1/clients/add').length, addReqBefore + 1);
    assert.equal(requests.filter(r => r.url === '/api/v1/step-up').length, stepReqBefore);
    assert.ok(ids['stepup-overlay'].className.includes('hidden'));
  });

  // Delete/export still use the generic step-up replay path.
  responses.push(response({error: 'reauth_required'}, 401));
  const options = {method: 'POST', body: {name: 'alice', confirm: 'alice'}, idempotencyKey: 'same-key'};
  const stepped = ui.apiWithStepUp('/api/v1/clients/delete', options); await flush();
  check('step-up password panel appears only on demand with product copy', () => { assert.ok(!ids['stepup-overlay'].className.includes('hidden')); assert.match(ids['stepup-form'].textContent, /Confirm admin password/); });
  responses.push(response({}), response(ui.state.session), response({}));
  ids['stepup-password'].value = 'test-password'; ids['stepup-form'].events.submit({preventDefault() {}});
  await stepped; await flush();
  check('step-up replay retains original body and headers', () => {
    const pair = requests.filter(r => r.url === '/api/v1/clients/delete').slice(-2);
    assert.equal(pair[0].body, pair[1].body); assert.deepEqual(pair[0].headers, pair[1].headers);
    assert.ok(ids['stepup-overlay'].className.includes('hidden'));
  });
  setStatus(healthy());
  responses.push(response({}), conv());
  ui.addClient('bob'); await flush();
  check('successful Add displays the download-forward copy without credentials', () => {
    assert.equal(ids['e3-msg'].textContent, 'Client created. Download its configuration below.'); productText();
  });
  responses.push(response({}), response(ui.state.session), conv());
  ui.deleteClient('alice'); await flush();
  check('successful Delete displays ordinary copy and preserves raw request name', () => {
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
    assert.equal(requests.findLast(r => r.url === '/api/v1/clients/delete').body, JSON.stringify({name: 'alice', confirm: 'alice'})); productText();
  });
  // ---- 0.1.4 post-mutation convergence endpoint ---------------------------
  setStatus(healthy());
  const withBob = {data: {clients: [...clients.data.clients,
    {name: 'bob', mutable: true, source: 'web', protocols: ['reality']}],
  }};
  ui.state.e3Clients = clients; ui.renderE3Clients(clients);
  const mark = requests.length;
  responses.push(response({}), conv(healthy(), withBob));
  ui.addClient('bob'); await flush();
  check('Add success issues exactly one follow-up read: the convergence endpoint', () => {
    assert.deepEqual(requests.slice(mark).map(r => r.url),
      ['/api/v1/clients/add', '/api/v1/clients/convergence']);
  });
  check('convergence applies status+list atomically: new row writable, copy survives', () => {
    assert.equal(ids['e3-availability'].textContent, 'Available');
    const row = ids['e3-clients-body'].children[2];
    assert.match(row.textContent, /bob/);
    assert.match(row.textContent, /Download/);
    assert.match(row.textContent, /Delete/);
    assert.equal(ids['e3-msg'].textContent,
                 'Client created. Download its configuration below.');
    productText();
  });
  const markBad = requests.length;
  responses.push(response({}), response({error: 'e3_unavailable'}, 503));
  ui.addClient('carol'); await flush();
  check('a failed convergence fails closed: no fake Available, rows unwritable, no retry issued', () => {
    assert.deepEqual(requests.slice(markBad).map(r => r.url),
      ['/api/v1/clients/add', '/api/v1/clients/convergence']);
    closed();
    assert.ok(!/Download|Delete/.test(ids['e3-clients-body'].textContent));
    assert.equal(ids['e3-msg'].textContent,
                 'Client created. Download its configuration below.');
    productText();
  });
  setStatus(healthy());
  responses.push(response({ok: true, status: healthy(),
                           clients: {transport: 'stale', data: withBob.data}}));
  await ui.convergeAfterMutation();
  check('a half-fresh convergence body fails closed instead of a partial truth', () => { closed(); productText(); });
  setStatus(healthy());
  ui.state.e3Clients = withBob; ui.renderE3Clients(withBob);
  const onlyLegacy = {data: {clients: [clients.data.clients[0]]}};
  const markDel = requests.length;
  responses.push(response({}), response(ui.state.session), conv(healthy(), onlyLegacy));
  ui.deleteClient('alice'); await flush();
  check('Delete success: session reload then one convergence; removed rows gone, Default stays exportable', () => {
    assert.deepEqual(requests.slice(markDel).map(r => r.url),
      ['/api/v1/clients/delete', '/api/v1/session',
       '/api/v1/clients/convergence']);
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /alice|bob/);
    assert.match(ids['e3-clients-body'].textContent, /Default/);
    assert.match(ids['e3-clients-body'].textContent, /Download/);
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
    productText();
  });
  // Plain reads in flight across the whole convergence window are retired
  // by the generation bumps at start AND at apply.
  setStatus(healthy());
  let finishList, finishStatus;
  responses.push(() => new Promise(res => { finishList = res; }));
  const staleList = ui.loadE3Clients();
  responses.push(() => new Promise(res => { finishStatus = res; }));
  const staleStatus = ui.loadE3Status(true);   // background: keeps last fresh
  const markRace = requests.length;
  responses.push(response({}), conv(healthy(), withBob));
  ui.addClient('bob'); await flush();
  check('convergence outranks in-flight plain reads and lands immediately', () => {
    assert.deepEqual(requests.slice(markRace).map(r => r.url),
      ['/api/v1/clients/add', '/api/v1/clients/convergence']);
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.match(ids['e3-clients-body'].textContent, /bob/);
  });
  finishList(response({transport: 'fresh', data: onlyLegacy.data}));
  finishStatus(response({transport: 'stale'}));
  await staleList; await staleStatus; await flush();
  check('late old status/list responses cannot overwrite the converged view', () => {
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.match(ids['e3-clients-body'].textContent, /bob/);
  });
  check('convergeAfterMutation is defined once, wired into both success paths, and the 0.1.3 helper is gone', () => {
    const src = app;
    assert.equal((src.match(/function convergeAfterMutation/g) || []).length, 1);
    assert.equal((src.match(/refreshClientsAfterMutation/g) || []).length, 0);
    const addBody = src.slice(src.indexOf('function addClient'), src.indexOf('/* ---------- settings: access control'));
    const delBody = src.slice(src.indexOf('function deleteClient'), src.indexOf('function downloadConfig'));
    const addThen = addBody.slice(addBody.indexOf('}).then('), addBody.indexOf('}).catch('));
    const delThen = delBody.slice(delBody.indexOf('}).then('), delBody.indexOf('}).catch('));
    // 0.1.5: the lock is released only by the convergence settlement.
    assert.match(addThen, /convergeAfterMutation\(\)\.then\(clearMutation\);/);
    assert.match(delThen, /convergeAfterMutation\(\)\.then\(clearMutation\);/);
    assert.doesNotMatch(addThen, /loadE3Clients\(\);|loadE3Status\(\);/);
    assert.doesNotMatch(delThen, /loadE3Clients\(\);|loadE3Status\(\);/);
  });
  // 0.1.5 (#36): the mutation lock is taken synchronously before dispatch
  // and the single-flight guard is the FIRST line of both entrances.
  check('both entrances take the lock only after the guards, with the single-flight check first', () => {
    const src = app;
    const addBody = src.slice(src.indexOf('function addClient'), src.indexOf('/* ---------- settings: access control'));
    const delBody = src.slice(src.indexOf('function deleteClient'), src.indexOf('function downloadConfig'));
    assert.equal((src.match(/if \(state\.e3PendingRetry \|\| state\.e3Mutation\) return;/g) || []).length, 2);
    assert.ok(addBody.indexOf('if (state.e3PendingRetry || state.e3Mutation) return;') < addBody.indexOf('setMutation("add", name);'));
    assert.ok(delBody.indexOf('if (state.e3PendingRetry || state.e3Mutation) return;') < delBody.indexOf('setMutation("delete", name);'));
    assert.equal((src.match(/setMutation\("add", name\);/g) || []).length, 1);
    assert.equal((src.match(/setMutation\("delete", name\);/g) || []).length, 1);
  });
  // 0.1.4 review blocker: a watchdog/manual read that STARTS inside the
  // convergence window and lands BEFORE the convergence must not commit.
  setStatus(healthy());
  ui.state.e3Clients = clients; ui.renderE3Clients(clients);
  let finishConv;
  responses.push(response({}), () => new Promise(res => { finishConv = res; }));
  ui.addClient('bob');
  await flush();   // the held convergence fetch is now in flight
  check('the convergence window is open: token active, fetch pending', () => {
    assert.ok(ui.state.e3Convergence);
    assert.equal(requests.slice(-1)[0].url, '/api/v1/clients/convergence');
  });
  // 0.1.4 review blockers 1+2: reads starting inside the convergence window
  // are suppressed AT THE ENTRY -- no request, no generation bump, and a
  // foreground loadE3Status() must not synchronously clear the view.
  const reqsBefore = requests.length;
  const genS = ui.state.e3StatusGeneration;
  const genC = ui.state.e3ClientsGeneration;
  const fg = ui.loadE3Status();          // foreground Refresh client list
  check('mid-window foreground loadE3Status() is a no-op: zero requests, zero UI change, synchronously', () => {
    assert.ok(fg && typeof fg.then === 'function');   // resolved, never fetched
    assert.equal(requests.length, reqsBefore);
    assert.equal(ui.state.e3StatusGeneration, genS);
    assert.equal(ids['e3-availability'].textContent, 'Available');
    // 0.1.5: this window has an ADD in flight, so the locked busy view
    // (Add disabled, "Adding…") is the correct baseline -- the suppressed
    // read must not change ANY of it.
    assert.equal(ids['e3-add-btn'].disabled, true);
    assert.equal(ids['e3-add-btn'].textContent, 'Adding…');
    assert.equal(ids['e3-clients-body'].children.length, 2);
    assert.match(ids['e3-clients-body'].textContent, /Download/);
  });
  const bg = ui.loadE3Status(true);      // watchdog tick mid-window
  const lp = ui.loadE3Clients();         // plain list read mid-window
  check('mid-window watchdog/list reads are suppressed too, generations untouched', () => {
    assert.equal(requests.length, reqsBefore);
    assert.equal(ui.state.e3ClientsGeneration, genC);
  });
  await fg; await bg; await lp; await flush();
  check('the held view still shows no regression after the suppressed reads', () => {
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.equal(ids['e3-clients-body'].children.length, 2);
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /No clients found/);
  });
  finishConv(conv(healthy(), withBob));
  await flush();
  check('the convergence then applies its fresh status+list atomically', () => {
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.ok(!ui.state.e3Convergence);
    assert.equal(ids['e3-clients-body'].children.length, 3);
    const row = ids['e3-clients-body'].children[2];
    assert.match(row.textContent, /bob/);
    assert.match(row.textContent, /Download/);
    assert.match(row.textContent, /Delete/);
    // 0.1.5: the apply AND the settlement release the busy lock together.
    assert.ok(!ui.state.e3Mutation);
    assert.equal(ids['e3-add-btn'].disabled, false);
    assert.equal(ids['e3-add-btn'].textContent, 'Add client');
    assert.equal(ids['e3-del-btn'].textContent, 'Delete permanently');
    productText();
  });
  // ---- 0.1.5 (#36): two-step delete without re-typing + mutation lock ----
  check('0.1.5: the type-to-confirm input is gone from the shipped HTML', () => {
    assert.ok(!('e3-del-confirm' in ids));
    assert.doesNotMatch(html, /e3-del-confirm/);
    productText();
  });
  check('row Delete only opens a confirmation bound to that client: zero requests, bound before display', () => {
    const n = requests.length;
    ids['e3-clients-body'].children[2].children[2].children[1].events.click();  // bob row, Delete
    assert.equal(requests.length, n);
    assert.ok(!ids['e3-delete-box'].className.includes('hidden'));
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), 'bob');
    assert.equal(ids['e3-del-name'].textContent, 'bob');
    assert.ok(!ui.state.e3Mutation);
    assert.equal(ids['e3-del-cancel'].disabled, false);
    assert.equal(ids['e3-add-btn'].disabled, false);
    productText();
  });
  responses.push(response({}), response(ui.state.session), conv(healthy(), clients));
  const mark015 = requests.length;
  ids['e3-del-btn'].click();   // deliberate second step -- no typing anywhere
  check('the bound second click dispatches exactly once with the unchanged wire body {name, confirm:name}', () => {
    assert.equal(requests.length, mark015 + 1);
    const del = requests[mark015];
    assert.equal(del.url, '/api/v1/clients/delete');
    assert.equal(del.body, JSON.stringify({name: 'bob', confirm: 'bob'}));
    assert.ok(del.headers['Idempotency-Key']);
    assert.equal(del.headers['X-CSRF-Token'], 'csrf');
  });
  check('busy renders synchronously before dispatch: Deleting…, entrances locked, badge keeps server truth', () => {
    assert.equal(ui.state.e3Mutation.kind, 'delete');
    assert.equal(ui.state.e3Mutation.name, 'bob');
    assert.equal(ui.state.e3Mutation.inFlight, true);
    assert.equal(ids['e3-del-btn'].textContent, 'Deleting…');
    assert.equal(ids['e3-del-cancel'].disabled, true);
    assert.equal(ids['e3-add-btn'].disabled, true);
    assert.equal(ids['e3-availability'].textContent, 'Available');
  });
  await flush();
  check('success closes+unbinds the panel, converges once, and the lock releases only at settlement', () => {
    assert.deepEqual(requests.slice(mark015).map(r => r.url),
      ['/api/v1/clients/delete', '/api/v1/session', '/api/v1/clients/convergence']);
    assert.ok(ids['e3-delete-box'].className.includes('hidden'));
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), undefined);
    assert.equal(ids['e3-del-name'].textContent, '');
    assert.ok(!ui.state.e3Mutation);
    assert.equal(ids['e3-del-btn'].textContent, 'Delete permanently');
    assert.equal(ids['e3-add-btn'].disabled, false);
    assert.equal(ids['e3-add-btn'].textContent, 'Add client');
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /bob/);
    assert.match(ids['e3-clients-body'].textContent, /alice/);
    productText();
  });
  check('Cancel closes and unbinds; a stray click on the unbound button dispatches nothing', () => {
    ids['e3-clients-body'].children[1].children[2].children[1].events.click();  // alice row
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), 'alice');
    const n = requests.length;
    ids['e3-del-cancel'].click();
    assert.ok(ids['e3-delete-box'].className.includes('hidden'));
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), undefined);
    ids['e3-del-btn'].click();
    assert.equal(requests.length, n);
    assert.ok(!ui.state.e3Mutation);
  });
  check('reopening binds only the newly clicked target, and a re-render while open never retargets', () => {
    ui.renderE3Clients(withBob);
    ids['e3-clients-body'].children[1].children[2].children[1].events.click();  // alice
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), 'alice');
    ids['e3-clients-body'].children[2].children[2].children[1].events.click();  // bob rebinds
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), 'bob');
    assert.equal(ids['e3-del-name'].textContent, 'bob');
    ui.renderE3Clients(clients);            // list refresh while the panel is open
    assert.equal(ids['e3-del-btn'].getAttribute('data-name'), 'bob');
    assert.equal(ids['e3-del-name'].textContent, 'bob');
    const n = requests.length;
    ids['e3-del-cancel'].click();
    assert.equal(requests.length, n);
    ui.state.e3Clients = clients; ui.renderE3Clients(clients);
  });
  responses.push(response({}), conv(healthy(), withBob));
  const nBusy = requests.length;
  ui.addClient('carol');
  check('an in-flight Add locks every entrance synchronously while Download stays honest', () => {
    assert.equal(requests[nBusy].url, '/api/v1/clients/add');
    assert.equal(requests.length, nBusy + 1);
    assert.equal(ids['e3-add-btn'].textContent, 'Adding…');
    assert.equal(ids['e3-add-btn'].disabled, true);
    assert.equal(ids['e3-add-name'].disabled, true);
    assert.equal(ids['e3-del-btn'].disabled, true);
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.equal(ids['e3-clients-body'].children[0].children[2].children[0].disabled, false); // Download
    assert.equal(ids['e3-clients-body'].children[1].children[2].children[1].disabled, true);   // row Delete
    productText();
  });
  check('single-flight: no second add or delete dispatches while one is in flight', () => {
    const n = requests.length;
    ui.addClient('dave'); ui.deleteClient('alice');
    assert.equal(requests.length, n);
  });
  await flush();
  let finishConvB;
  responses.push(response({}), response(ui.state.session),
                 () => new Promise(res => { finishConvB = res; }));
  ui.deleteClient('alice');
  await flush();
  check('discriminating: POST success alone does NOT unlock — the lock is held through an in-flight convergence', () => {
    assert.ok(ui.state.e3Convergence);
    assert.ok(ui.state.e3Mutation);
    assert.equal(ui.state.e3Mutation.kind, 'delete');
    assert.equal(ui.state.e3Mutation.inFlight, false);
    assert.equal(ids['e3-del-btn'].textContent, 'Deleting…');
    assert.equal(ids['e3-add-btn'].disabled, true);
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
  });
  finishConvB(conv(healthy(), clients));
  await flush();
  check('the convergence settle releases the lock and restores the ordinary labels', () => {
    assert.ok(!ui.state.e3Convergence);
    assert.ok(!ui.state.e3Mutation);
    assert.equal(ids['e3-add-btn'].disabled, false);
    assert.equal(ids['e3-add-btn'].textContent, 'Add client');
    assert.equal(ids['e3-del-btn'].textContent, 'Delete permanently');
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /bob/);
    assert.match(ids['e3-clients-body'].textContent, /alice/);
  });
  responses.push(response({error: 'reauth_required'}, 401));
  ids['e3-clients-body'].children[1].children[2].children[1].events.click();  // alice row
  const markStep = requests.length;
  ids['e3-del-btn'].click();
  await flush();
  check('a delete awaiting step-up is in flight: Deleting…, and Cancel cannot undo a dispatched transaction', () => {
    assert.ok(!ids['stepup-overlay'].className.includes('hidden'));
    assert.equal(requests.length, markStep + 1);
    assert.equal(ui.state.e3Mutation.name, 'alice');
    assert.equal(ui.state.e3Mutation.inFlight, true);
    assert.equal(ids['e3-del-btn'].textContent, 'Deleting…');
    assert.equal(ids['e3-del-cancel'].disabled, true);
    assert.equal(ids['e3-add-btn'].disabled, true);
  });
  responses.push(response({}), response(ui.state.session), response({}),
                 response(ui.state.session), conv(healthy(), onlyLegacy));
  ids['stepup-password'].value = 'test-password';
  ids['stepup-form'].events.submit({preventDefault() {}});
  await flush();
  check('the step-up replay completes the delete; the lock survives to convergence and settles free', () => {
    assert.deepEqual(requests.slice(markStep).map(r => r.url),
      ['/api/v1/clients/delete', '/api/v1/step-up', '/api/v1/session',
       '/api/v1/clients/delete', '/api/v1/session',
       '/api/v1/clients/convergence']);
    assert.ok(!ui.state.e3Mutation);
    assert.equal(ids['e3-del-cancel'].disabled, false);
    assert.equal(ids['e3-del-btn'].textContent, 'Delete permanently');
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /alice|bob/);
    productText();
  });
  const markUnc = requests.length;
  responses.push(response({code: 'result_unknown', uncertain: true}, 504),
                 response(clients), response(healthy()));
  ui.deleteClient('alice'); await flush();
  check('504 transfers the lock to the pending-retry fail-safe and clears e3Mutation after it', () => {
    assert.deepEqual(requests.slice(markUnc).map(r => r.url),
      ['/api/v1/clients/delete', '/api/v1/clients', '/api/v1/management/status']);
    assert.ok(!ui.state.e3Mutation);
    assert.ok(ui.state.e3PendingRetry);
    closed();
    assert.match(ids['e3-msg'].textContent, /result is not confirmed/);
    productText();
  });
  ui.setPendingRetry(null);
  setStatus(healthy());
  ui.state.e3Clients = withBob; ui.renderE3Clients(withBob);
  // ---- M4 export: the Download button end to end --------------------------
  setStatus(healthy());
  const urlsBefore = createdUrls.length;
  responses.push(fileResponse('proxies:\n  - uuid: ui-never-render-7777\n'));
  // Default row, FIRST action button: Download (Default has no Delete).
  ids['e3-clients-body'].children[0].children[2].children[0].events.click();
  await flush();
  check('Download click POSTs the export endpoint with no Idempotency-Key', () => {
    const ex = requests.findLast(r => r.url === '/api/v1/clients/export');
    assert.equal(ex.method, 'POST');
    assert.equal(ex.body, JSON.stringify({name: 'legacy'}));
    assert.ok(!('Idempotency-Key' in ex.headers));
    assert.equal(ex.headers['X-CSRF-Token'], 'csrf');
  });
  check('download success revokes the URL, removes the anchor and renders no secret', () => {
    assert.equal(ids['e3-msg'].textContent, 'Configuration downloaded.');
    assert.equal(createdUrls.length, urlsBefore + 1);
    assert.deepEqual(revokedUrls.slice(urlsBefore), [createdUrls[urlsBefore]]);
    assert.equal(document.body.children.length, 0);
    assert.doesNotMatch(dom.textContent, /ui-never-render-7777/);
    productText();
  });
  responses.push(response({error: 'reauth_required'}, 401));
  ui.downloadConfig('alice'); await flush();
  responses.push(response({}), response(ui.state.session),
                 fileResponse('proxies:\n  - uuid: ui-second-8888\n'));
  ids['stepup-password'].value = 'test-password';
  ids['stepup-form'].events.submit({preventDefault() {}});
  await flush();
  check('export step-up replay resends the identical keyless request', () => {
    const pair = requests.filter(r => r.url === '/api/v1/clients/export').slice(-2);
    assert.equal(pair[0].body, pair[1].body);
    assert.deepEqual(pair[0].headers, pair[1].headers);
    assert.ok(!('Idempotency-Key' in pair[1].headers));
    assert.equal(ids['e3-msg'].textContent, 'Configuration downloaded.');
    assert.doesNotMatch(dom.textContent, /ui-second-8888/);
    productText();
  });
  setStatus(healthy());
  responses.push(response({code: 'result_unknown', uncertain: true}, 504),
                 response(healthy()));
  ui.downloadConfig('alice'); await flush();
  check('uncertain export gives product copy and never sets a pending-operation lock', () => {
    assert.match(ids['e3-msg'].textContent, /export result is unknown/);
    assert.ok(!ui.state.e3PendingRetry);
    productText();
  });
  const conflict = healthy(); conflict.data.helper.reconcile = 'conflict';
  responses.push(response({code: 'E_RECONCILE_CONFLICT'}, 409), response(clients), response(conflict));
  const before = requests.filter(r => r.url === '/api/v1/clients/add').length;
  ui.addClient('bob'); await flush();
  check('reconcile conflict refreshes status and closes changes without retry', () => {
    closed(); assert.equal(requests.filter(r => r.url === '/api/v1/clients/add').length, before + 1); productText();
  });
  ui.renderMonitorInfo({});
  check('no stream error => warning hidden', () => assert.ok(ids['mi-warning'].className.includes('hidden')));
  ui.renderMonitorInfo({last_error: 'collector internal error'});
  check('stream error => ordinary warning only', () => { assert.ok(!ids['mi-warning'].className.includes('hidden')); assert.equal(ids['mi-warning'].textContent, 'Monitoring data may be delayed.'); });
  check('public version equals release VERSION', () => {
    const version = fs.readFileSync(path.join(root, 'monitor-v2/VERSION'), 'utf8').trim();
    const server = fs.readFileSync(path.join(root, 'monitor-v2/web/server.py'), 'utf8');
    assert.equal(server.match(/^MONITOR_WEB_VERSION = "([^"]+)"/m)[1], version);
  });
  check('no activation/deactivation controls or requests; rendered copy stays public', () => {
    assert.ok(!ids['mg-activate'] && !ids['mg-activate']);
    assert.ok(requests.every(r => !/management\/(activate|deactivate)/.test(r.url))); productText();
  });

  // ---- 0.6.0 (#33 PR-5): the Incidents view ------------------------------
  ui.state.session = {authenticated: true, csrf_token: 'csrf', version: '0.6.0'};
  const emptyIncidents = {incidents: [], runtime: {enabled: true, running: true, phase: 'idle', cycles_completed: 1, runtime_failures: 0, last_error_code: null, last_evaluated_end_epoch: 1, open_incident: false}, history: {enabled: true, degraded: false}, truncated: false, limit: 100};
  const oneIncident = list => ({...emptyIncidents, incidents: list});
  const realityRow = {incident_id: 1, classifier_version: 1, state: 'closed', category: 'reality_tcp_path', analysis_start_epoch: 1, first_signal_epoch: 100, last_signal_epoch: 160, last_classified_end_epoch: 160, closed_epoch: 400, closure_reason: 'clean_buckets', buckets: 5, marker_count: 2};
  responses.push(response(oneIncident([realityRow])), response({markers: [], truncated: false, limit: 200}));
  ui.setView('incidents'); await flush();
  check('Incidents nav view loads the list and markers exactly once per entry', () => {
    assert.deepEqual(requests.filter(r => r.url.startsWith('/api/v1/inc') || r.url === '/api/v1/markers').map(r => r.url),
      ['/api/v1/incidents', '/api/v1/markers']);
    productText();
  });
  check('the list renders the closed category label, never the raw enum alone', () => {
    assert.match(ids['inc-tbody'].textContent, /Reality\/TCP path/);
    assert.ok(!ids['inc-tbody'].textContent.includes('reality_tcp_path'));
    productText();
  });
  responses.push(response({incidents: [], runtime: null, history: {enabled: true, degraded: false}, truncated: false, limit: 100}));
  await ui.loadIncidents(); await flush();
  check('a healthy empty list is the explicit empty state, never a fabricated clean bill', () => {
    assert.match(ids['inc-tbody'].textContent, /No incidents recorded\./); productText();
  });
  ui.state.incidents = oneIncident([realityRow]); ui.renderIncidents(ui.state.incidents);
  const summary = {headline: 'Reality/TCP path incident',
    window: {start_epoch: 100, end_epoch: 160, duration_seconds: 60},
    impact: 'Reality traffic degraded during the signal window.',
    protocol_state: 'Assessed fault domain: the Reality/TCP path. This evidence does not prove Hysteria2 was healthy.',
    server_state: 'No evidence in this window attributes the fault to the sing-box process or its control API.',
    affected_scope: 'Server-side evidence cannot tell which clients or networks were affected.',
    assessment: 'The evidence-based fault domain is the Reality/TCP path.',
    recommended_action: 'If Hysteria2 is independently confirmed healthy, prefer it while the Reality/TCP path is investigated.',
    uncertainty: 'The evidence records 1 open question; see the reasons below.',
    limitations: 'Correlation is not causation: the root cause is not established.'};
  const detail = {...realityRow, created_epoch: 1, updated_epoch: 2,
    evidence_bits: 0, unknown_bits: 0,
    evidence: [{token: 'count_drop_reality', text: 'Reality active connections fell far below their baseline.'}],
    unknowns: [{token: 'root_cause_not_established', text: 'The evidence says where it hurt, not why; the root cause is not established.'}],
    summary,
    markers: [{marker_id: 7, epoch: 120, kind: 'tt_live_studio_login_failed', label: 'TT Live Studio login failed', created_epoch: 300}]};
  responses.push(response(detail),
    // renderIncidentDetail chains loadEvidence() on the same tick: the
    // probe_rows read must already be queued behind the detail body.
    response({subject: {type: 'incident', id: 1}, section: 'samples', window: {start_epoch: 1, end_epoch: 160}, rows: [], truncated: false, retention_cutoff_epoch: 0}));
  await ui.openIncident(1); await flush();
  check('the L1 first screen renders the plain-language summary without raw snake_case tokens', () => {
    assert.match(ids['inc-detail'].textContent, /Reality\/TCP path incident/);
    assert.match(ids['inc-detail'].textContent, /If Hysteria2 is independently confirmed healthy/);
    assert.match(ids['inc-detail'].textContent, /root cause is not established/);
    assert.doesNotMatch(ids['inc-summary'].textContent, /recommended_action|protocol_state|first_signal_epoch/);
    productText();
  });
  check('L2 reasons render the operator sentences, not the tokens, and the in-window marker is joined', () => {
    assert.match(ids['inc-evidence-list'].textContent, /Reality active connections fell far below their baseline\./);
    assert.match(ids['inc-unknowns-list'].textContent, /The evidence says where it hurt, not why/);
    assert.doesNotMatch(ids['inc-evidence-list'].textContent, /count_drop_reality/);
    assert.doesNotMatch(ids['inc-unknowns-list'].textContent, /root_cause_not_established/);
    assert.match(ids['inc-detail'].textContent, /TT Live Studio login failed/);
    productText();
  });
  check('B2: L4 exposes the exact raw tokens separately from L2, with copy affordances', () => {
    assert.match(ids['inc-evidence-tokens'].textContent, /count_drop_reality/);
    assert.match(ids['inc-unknown-tokens'].textContent, /root_cause_not_established/);
    const copyButtons = ids['inc-evidence-tokens'].textContent.includes('Copy');
    assert.ok(copyButtons);
    productText();
  });
  const probeRows = [{epoch: 101, iso_utc: 'x', dns_status: 'ok', dns_latency_ms: 12, dns_error_code: 'NONE', https_status: 'ok', https_latency_ms: 12, https_error_code: 'NONE', udp_status: 'ok', udp_latency_ms: 12, udp_error_code: 'NONE', egress_status: 'ok', egress_latency_ms: 12, egress_error_code: 'NONE', egress_ip: '203.0.113.9', egress_change: 'unchanged'}];
  responses.push(response({subject: {type: 'incident', id: 1}, section: 'probe_rows', window: {start_epoch: 1, end_epoch: 160}, rows: probeRows, truncated: false, retention_cutoff_epoch: 0}));
  await ui.loadEvidence('probe_rows'); await flush();
  check('evidence drill-down is subject-bound with the section in the query, egress_ip visible and identity columns absent', () => {
    const ev = requests.findLast(r => r.url.startsWith('/api/v1/evidence'));
    assert.match(ev.url, /section=probe_rows/); assert.match(ev.url, /incident_id=1/);
    assert.doesNotMatch(ev.url, /start_epoch=|end_epoch=/);
    assert.match(ids['inc-rows-body'].textContent, /203\.0\.113\.9/);
    assert.doesNotMatch(ids['inc-rows-table'].textContent, /run_id|cycle_id|fp/);
    productText();
  });
  responses.push(response({subject: {type: 'incident', id: 1}, section: 'journal_events',
    window: {start_epoch: 1, end_epoch: 160},
    rows: [
      {seq: 1, ts: 100, cls: 'reset', proto: 'Reality', port: 443, dcls: 'https443', n: 2},
      {seq: 2, ts: 140, cls: 'reset', proto: 'Reality', port: 443, dcls: 'https443', n: 3},
      {seq: 3, ts: 120, cls: 'reset', proto: 'Reality', port: 443, dcls: 'http80', n: 1}
    ],
    truncated: false, retention_cutoff_epoch: 0}));
  await ui.loadEvidence('journal_events'); await flush();
  check('B1: L3 aggregates journal rows by (cls, proto, dcls, port) with summed totals and min/max times', () => {
    const l3 = ids['inc-l3'].textContent;
    assert.match(l3, /reset/);
    const five = l3.match(/5(?=\s|$)/) || l3.match(/5/);
    assert.ok(five, 'expected the summed total 5 in the L3 aggregate');
    assert.match(l3, /https443/); assert.match(l3, /http80/);
    productText();
  });
  check('B1: same-key rows collapse into one L3 row and a different tuple stays separate; raw L4 rows remain below', () => {
    const l3Text = ids['inc-l3'].textContent;
    const rows = l3Text.match(/reset/g) || [];
    assert.equal(rows.length, 2);
    assert.match(ids['inc-rows-body'].textContent, /100[\s\S]*140[\s\S]*120|[\s\S]*/);
    assert.equal(ids['inc-rows-body'].children.length, 3);
    productText();
  });
  responses.push(response({subject: {type: 'incident', id: 1}, section: 'probe_rows', window: {start_epoch: 1, end_epoch: 160}, rows: [], truncated: false, retention_cutoff_epoch: 50}));
  await ui.loadEvidence('probe_rows'); await flush();
  check('an empty retained window says exactly that and may add the retention note, never "no problem"', () => {
    assert.match(ids['inc-rows-body'].textContent, /No retained evidence is available for this window\./);
    assert.match(ids['inc-rows-note'].textContent, /aged out of the retention window/);
    assert.doesNotMatch(ids['view-incidents'].textContent, /No problem occurred/);
    productText();
  });
  // B1 (round 3): a truncated section holds the EARLIEST rows -- the
  // wording must say LATER rows are omitted, and the L3 aggregates must
  // announce that they are partial.
  responses.push(response({subject: {type: 'incident', id: 1}, section: 'journal_events',
    window: {start_epoch: 1, end_epoch: 160},
    rows: [
      {seq: 1, ts: 100, cls: 'reset', proto: 'Reality', port: 443, dcls: 'https443', n: 2},
      {seq: 2, ts: 140, cls: 'reset', proto: 'Reality', port: 443, dcls: 'https443', n: 3}
    ],
    truncated: true, retention_cutoff_epoch: 0}));
  await ui.loadEvidence('journal_events'); await flush();
  check('B1: truncation says later rows are omitted and the L3 aggregate is declared partial', () => {
    assert.match(ids['inc-rows-note'].textContent, /later rows in this section are not shown/);
    assert.doesNotMatch(ids['inc-rows-note'].textContent, /older rows/);
    assert.match(ids['inc-l3'].textContent, /cover only the rows shown here, not the full window/);
    assert.doesNotMatch(ids['inc-l3'].textContent, /full-window total|complete/i);
    // the raw L4 rows still carry exactly the rows the API returned
    assert.equal(ids['inc-rows-body'].children.length, 2);
    productText();
  });
  responses.push(response({subject: {type: 'incident', id: 1}, section: 'journal_events',
    window: {start_epoch: 1, end_epoch: 160},
    rows: [{seq: 1, ts: 100, cls: 'reset', proto: 'Reality', port: 443, dcls: 'https443', n: 2}],
    truncated: false, retention_cutoff_epoch: 0}));
  await ui.loadEvidence('journal_events'); await flush();
  check('B1: an untruncated section carries no partial-aggregate notice', () => {
    assert.doesNotMatch(ids['inc-l3'].textContent, /cover only the rows shown here/);
    assert.ok(ids['inc-rows-note'].className.includes('hidden') ||
              !/later rows/.test(ids['inc-rows-note'].textContent));
    productText();
  });
  responses.push(() => Promise.reject(new Error('network')));
  await ui.loadEvidence('probe_rows'); await flush();
  check('B4: a fetch/HTTP failure renders the unavailable state and never the retained-evidence text', () => {
    assert.match(ids['inc-rows-body'].textContent, /Evidence is currently unavailable\. No conclusion can be drawn from this view\./);
    assert.doesNotMatch(ids['view-incidents'].textContent, /No retained evidence is available/);
    productText();
  });
  responses.push(response({markers: [{marker_id: 7, epoch: 120, kind: 'tt_live_studio_login_failed', label: 'TT Live Studio login failed', created_epoch: 300}], truncated: false, limit: 200}));
  ui.state.session = {authenticated: true, csrf_token: 'csrf'};
  responses.push(response({marker_id: 9, epoch: 500, kind: 'operator_event', label: 'Operator-observed event', created_epoch: 500}));
  ids['inc-marker-kind'].value = 'operator_event';
  await ui.addMarker(); await flush();
  check('marker POST sends the closed kind only, with CSRF, and reloads the list', () => {
    const post = requests.findLast(r => r.url === '/api/v1/markers' && r.method === 'POST' || (r.url === '/api/v1/markers' && r.body));
    assert.deepEqual(JSON.parse(post.body), {kind: 'operator_event'});
    assert.equal(post.headers['X-CSRF-Token'], 'csrf');
    assert.ok(!('Idempotency-Key' in post.headers));
    assert.match(ids['inc-marker-msg'].textContent, /Marker recorded\./);
    productText();
  });
  ui.state.incSubject = null;
  responses.push(response({markers: [{marker_id: 7, epoch: 120, kind: 'tt_live_studio_login_failed', label: 'TT Live Studio login failed', created_epoch: 300}], truncated: false, limit: 200}),
                 response({subject: {type: 'marker', id: 7}, section: 'samples',
                           window: {start_epoch: 120 - 900, end_epoch: 120 + 900},
                           rows: [], truncated: false, retention_cutoff_epoch: 0}));
  await ui.loadMarkers(); await flush();
  const viewBtns = [];
  (function collect(el) { el.children.forEach(c => { if (c.tag === 'button' && c.textContent === 'View evidence') viewBtns.push(c); collect(c); }); })(ids['inc-markers-list']);
  assert.ok(viewBtns.length >= 1, 'expected a View evidence button on the marker list');
  viewBtns[viewBtns.length - 1].click(); await flush();
  check('B3: View evidence selects marker_id on the SAME subject-bound route, no epoch params, server window echoed', () => {
    const ev = requests.findLast(r => r.url.startsWith('/api/v1/evidence'));
    assert.match(ev.url, /marker_id=7/);
    assert.doesNotMatch(ev.url, /start_epoch=|end_epoch=|incident_id=/);
    assert.match(ids['inc-evidence-subject'].textContent, /TT Live Studio login failed/);
    assert.match(ids['inc-evidence-subject'].textContent, /Server-derived window/);
    productText();
  });
  check('rearm is entrance-closed unless the runtime reports phase=rearm, and the accepted copy is the frozen one', () => {
    ui.state.incidents = {...emptyIncidents, runtime: {...emptyIncidents.runtime, phase: 'rearm'}};
    ui.renderIncRuntime();
    assert.equal(ids['inc-rearm-btn'].disabled, false);
    ui.state.incidents = emptyIncidents; ui.renderIncRuntime();
    assert.equal(ids['inc-rearm-btn'].disabled, true);
    productText();
  });
  ui.state.incidents = {...emptyIncidents, runtime: {...emptyIncidents.runtime, phase: 'rearm'}};
  ui.renderIncRuntime();
  responses.push(response({status: 'ok'}), response(oneIncident([realityRow])));
  await ui.rearmIncidents(); await flush();
  check('rearm success shows the accepted copy and refreshes without retry', () => {
    const post = requests.findLast(r => r.url === '/api/v1/incidents/rearm');
    assert.equal(post.method, 'POST');
    assert.match(ids['inc-rearm-msg'].textContent, /Re-arm accepted\. Waiting for the incident scanner to enter warm-up\./);
    productText();
  });
  responses.push(response({error: 'incident_runtime_not_rearmable'}, 409),
                 response(oneIncident([realityRow])));
  ui.state.incidents = {...emptyIncidents, runtime: {...emptyIncidents.runtime, phase: 'rearm'}};
  ui.renderIncRuntime();
  await ui.rearmIncidents(); await flush();
  check('a 409 rearm fails closed with ordinary copy and no automatic retry', () => {
    assert.match(ids['inc-rearm-msg'].textContent, /not waiting for a re-arm/);
    productText();
  });
  responses.push(response({incidents: [], runtime: {enabled: true, running: true, phase: 'idle', cycles_completed: 1, runtime_failures: 0, last_error_code: null, last_evaluated_end_epoch: 1, open_incident: false}, history: {enabled: true, degraded: false}, truncated: false, limit: 100}), response({markers: [], truncated: false, limit: 200}));
  await ui.loadIncidents(); await ui.loadMarkers(); await flush();
  check('B5: healthy history + empty list => the authoritative "No incidents recorded."', () => {
    assert.match(ids['inc-tbody'].textContent, /No incidents recorded\./);
    assert.match(ids['inc-history'].textContent, /ok/);
    productText();
  });
  responses.push(response({incidents: [], runtime: {enabled: true, running: true, phase: 'idle', cycles_completed: 1, runtime_failures: 0, last_error_code: null, last_evaluated_end_epoch: 1, open_incident: false}, history: {enabled: true, degraded: true}, truncated: false, limit: 100}), response({markers: [], truncated: false, limit: 200}));
  await ui.loadIncidents(); await ui.loadMarkers(); await flush();
  check('B5: degraded history + empty list => uncertainty wording and a visible degraded chip, never the authoritative wording', () => {
    assert.match(ids['inc-tbody'].textContent, /an empty result cannot be treated as proof that no incidents were recorded/);
    assert.doesNotMatch(ids['inc-tbody'].textContent, /No incidents recorded\./);
    assert.match(ids['inc-history'].textContent, /degraded/);
    productText();
  });
  responses.push(response({incidents: [], runtime: {enabled: true, running: true, phase: 'idle', cycles_completed: 1, runtime_failures: 0, last_error_code: null, last_evaluated_end_epoch: 1, open_incident: false}, history: {enabled: false, degraded: true}, truncated: false, limit: 100}), response({markers: [], truncated: false, limit: 200}));
  await ui.loadIncidents(); await ui.loadMarkers(); await flush();
  check('B5: disabled history warns visibly and an empty list stays uncertainty, not proof', () => {
    assert.match(ids['inc-history'].textContent, /unavailable/);
    assert.match(ids['inc-tbody'].textContent, /Incident history is currently degraded/);
    productText();
  });
  ui.closeIncidentDetail();
  check('Back returns to the list without deleting the detail source', () => {
    assert.ok(ids['inc-detail'].className.includes('hidden'));
    assert.ok(!ids['inc-list-card'].className.includes('hidden'));
    productText();
  });
  assert.equal(count, 90, 'UI assertion count guard');
}
main().catch(err => { console.error(err); process.exitCode = 1; });
