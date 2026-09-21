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
  'globalThis.ui = {state, bind, render, loadSession, loadE3Status, renderE3Controls, renderE3Clients, renderMonitorInfo, addClient, deleteClient, downloadConfig, setPendingRetry, retryPending, apiWithStepUp};'), context);
const ui = context.ui;
// 0.1.3: the post-mutation convergence chains status -> list across several
// cross-realm promise reactions; 12 ticks starved it. Drain generously.
const flush = async () => { for (let i = 0; i < 64; i++) await Promise.resolve(); };
const response = (data, status = 200) => ({ok: status < 400, status, json: () => Promise.resolve(data)});
// M4: api(raw) hands the FILE response straight to the caller -- only blob().
const fileResponse = text => ({ok: true, status: 200, blob: () => Promise.resolve({size: text.length})});
const healthy = () => ({transport: 'fresh', data: {management_state: 'active', helper: {degraded: false, reconcile: 'clean'}, lock: {acquirable: true}}});
const clients = {data: {clients: [{name: 'legacy', mutable: false, source: 'untracked', protocols: ['reality', 'hy2']}, {name: 'alice', mutable: true, source: 'web', protocols: ['reality']}]}};
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
  responses.push(response({error: 'reauth_required'}, 401));
  const options = {method: 'POST', body: {name: 'bob'}, idempotencyKey: 'same-key'};
  const stepped = ui.apiWithStepUp('/api/v1/clients/add', options); await flush();
  check('step-up password panel appears only on demand with product copy', () => { assert.ok(!ids['stepup-overlay'].className.includes('hidden')); assert.match(ids['stepup-form'].textContent, /Confirm admin password/); });
  responses.push(response({}), response(ui.state.session), response({}));
  ids['stepup-password'].value = 'test-password'; ids['stepup-form'].events.submit({preventDefault() {}});
  await stepped; await flush();
  check('step-up replay retains original body and headers', () => {
    const pair = requests.filter(r => r.url === '/api/v1/clients/add').slice(-2);
    assert.equal(pair[0].body, pair[1].body); assert.deepEqual(pair[0].headers, pair[1].headers);
    assert.ok(ids['stepup-overlay'].className.includes('hidden'));
  });
  setStatus(healthy());
  responses.push(response({}), response(healthy()), response(clients));
  ui.addClient('bob'); await flush();
  check('successful Add displays the download-forward copy without credentials', () => {
    assert.equal(ids['e3-msg'].textContent, 'Client created. Download its configuration below.'); productText();
  });
  responses.push(response({}), response(ui.state.session), response(healthy()), response(clients));
  ui.deleteClient('alice'); await flush();
  check('successful Delete displays ordinary copy and preserves raw request name', () => {
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
    assert.equal(requests.findLast(r => r.url === '/api/v1/clients/delete').body, JSON.stringify({name: 'alice', confirm: 'alice'})); productText();
  });
  // ---- 0.1.3 post-mutation immediate convergence --------------------------
  setStatus(healthy());
  const withBob = {data: {clients: [...clients.data.clients,
    {name: 'bob', mutable: true, source: 'web', protocols: ['reality']}],
  }};
  let finishStatus;
  const mark = requests.length;
  responses.push(response({}),
                 () => new Promise(res => { finishStatus = res; }),
                 response(withBob));
  ui.addClient('bob'); await flush();
  check('Add success refreshes status THEN list in order, keeping the last good view while in flight', () => {
    assert.deepEqual(requests.slice(mark).map(r => r.url),
      ['/api/v1/clients/add', '/api/v1/management/status']);
    // the in-flight status read did NOT erase the fresh writable state
    assert.equal(ids['e3-availability'].textContent, 'Available');
    assert.equal(ids['e3-add-btn'].disabled, false);
    // the list refresh has NOT been issued yet -- strict ordering
    assert.equal(requests.slice(mark).length, 2);
  });
  finishStatus(response(healthy())); await flush();
  check('post-Add convergence renders the new client with Download/Delete without any watchdog', () => {
    assert.equal(requests[mark + 2].url, '/api/v1/clients');
    assert.equal(ids['e3-availability'].textContent, 'Available');
    const row = ids['e3-clients-body'].children[2];
    assert.match(row.textContent, /bob/);
    assert.match(row.textContent, /Download/);
    assert.match(row.textContent, /Delete/);
    assert.equal(ids['e3-msg'].textContent,
                 'Client created. Download its configuration below.');
    productText();
  });
  setStatus(healthy());
  const markBad = requests.length;
  responses.push(response({}), response({error: 'status down'}, 503),
                 response(withBob));
  ui.addClient('dan'); await flush();
  check('failed fresh-status after a successful Add fails closed and keeps no stale controls', () => {
    assert.equal(requests[markBad + 1].url, '/api/v1/management/status');
    closed();                       // Unavailable, zero action buttons
    assert.ok(!/Download|Delete/.test(ids['e3-clients-body'].textContent));
    assert.equal(ids['e3-msg'].textContent,
                 'Client created. Download its configuration below.');
    productText();
  });
  setStatus(healthy());
  ui.state.e3Clients = clients; ui.renderE3Clients(clients);
  const onlyLegacy = {data: {clients: [clients.data.clients[0]]}};
  const markDel = requests.length;
  responses.push(response({}), response(ui.state.session),
                 response(healthy()), response(onlyLegacy));
  ui.deleteClient('alice'); await flush();
  check('Delete success converges immediately: status then list, removed row gone, copy survives', () => {
    assert.deepEqual(requests.slice(markDel).map(r => r.url),
      ['/api/v1/clients/delete', '/api/v1/session',
       '/api/v1/management/status', '/api/v1/clients']);
    assert.doesNotMatch(ids['e3-clients-body'].textContent, /alice/);
    assert.match(ids['e3-clients-body'].textContent, /Default/);
    assert.match(ids['e3-clients-body'].textContent, /Download/);
    assert.equal(ids['e3-msg'].textContent, 'Client deleted.');
    productText();
  });
  check('the convergence helper is wired into both success paths and defined once', () => {
    const src = app;
    assert.equal((src.match(/function refreshClientsAfterMutation/g) || []).length, 1);
    const addBody = src.slice(src.indexOf('function addClient'), src.indexOf('/* ---------- settings: access control'));
    const delBody = src.slice(src.indexOf('function deleteClient'), src.indexOf('function downloadConfig'));
    assert.match(addBody.slice(addBody.indexOf('}).then('), addBody.indexOf('}).catch(')), /refreshClientsAfterMutation\(\);/);
    assert.match(delBody.slice(delBody.indexOf('}).then('), delBody.indexOf('}).catch(')), /refreshClientsAfterMutation\(\);/);
    assert.doesNotMatch(addBody.slice(addBody.indexOf('}).then('), addBody.indexOf('}).catch(')), /loadE3Clients\(\);/);
    assert.doesNotMatch(delBody.slice(delBody.indexOf('}).then('), delBody.indexOf('}).catch(')), /loadE3Clients\(\);/);
  });
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
    assert.ok(!ids['mg-activate'] && !ids['mg-deactivate']);
    assert.ok(requests.every(r => !/management\/(activate|deactivate)/.test(r.url))); productText();
  });
  assert.equal(count, 44, 'UI assertion count guard');
}
main().catch(err => { console.error(err); process.exitCode = 1; });
