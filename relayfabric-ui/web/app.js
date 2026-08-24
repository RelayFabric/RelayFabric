// RelayFabric admin UI — a Preact + htm port of the design mockup, wired to
// the switchyardd admin API (proxied by relayfabric-ui). When the API is
// unreachable the UI drops into an offline demo with sample data so it stays
// fully browsable; against a live daemon every screen shows real data.
import { html, render, Component } from './vendor/preact-htm.js';

// ---- helpers ---------------------------------------------------------------

// ---- passkey auth (v0.4 cycle E) -------------------------------------------

const b64u = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
  dec: (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)),
};

async function passkeyLogin() {
  const opts = await api('/auth/login/options', { method: 'POST' });
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: b64u.dec(opts.challenge),
      rpId: opts.rp_id,
      userVerification: 'preferred',
    },
  });
  return api('/auth/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge_token: opts.challenge_token,
      id: cred.id,
      client_data_json: b64u.enc(cred.response.clientDataJSON),
      authenticator_data: b64u.enc(cred.response.authenticatorData),
      signature: b64u.enc(cred.response.signature),
    }),
  });
}

async function passkeyRegister(setupToken, role, label) {
  const headers = setupToken ? { 'x-setup-token': setupToken } : {};
  const opts = await api('/auth/register/options', { method: 'POST', headers });
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge: b64u.dec(opts.challenge),
      rp: { id: opts.rp_id, name: 'RelayFabric' },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: label || 'relayfabric-admin',
        displayName: label || 'RelayFabric admin',
      },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      attestation: 'none',
    },
  });
  return api('/auth/register', {
    method: 'POST',
    headers: { ...headers, 'content-type': 'application/json' },
    body: JSON.stringify({
      challenge_token: opts.challenge_token,
      client_data_json: b64u.enc(cred.response.clientDataJSON),
      attestation_object: b64u.enc(cred.response.attestationObject),
      role, label,
    }),
  });
}



async function api(path, opts) {
  const r = await fetch(path, opts);
  const ct = r.headers.get('content-type') || '';
  if (!r.ok) {
    const body = await r.text().catch(() => '');
    const e = new Error('HTTP ' + r.status + (body ? ': ' + body.slice(0, 200) : ''));
    e.status = r.status;
    throw e;
  }
  return ct.includes('application/json') ? r.json() : r.text();
}

const shortId = (s) => (s && s.length > 13 ? s.slice(0, 13) + '…' : s || '');
const shortNode = (s) => (s && s.length > 16 ? s.slice(0, 10) + '…' + s.slice(-2) : s || '');

function ago(iso) {
  if (!iso) return '—';
  const ms = Date.now() - new Date(iso).getTime();
  if (isNaN(ms)) return String(iso);
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return s + 's';
  if (s < 3600) return Math.round(s / 60) + 'm';
  if (s < 86400) return Math.round(s / 3600) + 'h';
  return Math.round(s / 86400) + 'd';
}
const clock = (off) => new Date(Date.now() - (off || 0)).toTimeString().slice(0, 8);

function tagFor(state) {
  const s = String(state);
  if (['connected', 'delivered', 'pending', 'verified', 'true', 'up'].includes(s)) return 'tag tag-accent';
  if (['retry', 'dead_letter', 'failed', 'expired', 'false', 'disconnected', 'down'].includes(s)) return 'tag tag-outline';
  return 'tag tag-neutral';
}
const evTag = (t) => ({
  ingress: 'tag tag-neutral', delivery: 'tag tag-accent', plugin: 'tag tag-outline',
  advert: 'tag tag-neutral', federation: 'tag tag-accent-2', config_applied: 'tag tag-outline',
  link_verified: 'tag tag-accent-2',
}[t] || 'tag tag-neutral');

const NAV = [
  ['overview', 'Overview', 'ph ph-gauge'],
  ['queue', 'Queue', 'ph ph-tray'],
  ['config', 'Config', 'ph ph-sliders-horizontal'],
  ['identities', 'Identities', 'ph ph-identification-badge'],
  ['federation', 'Federation', 'ph ph-globe-hemisphere-west'],
  ['routes', 'Routes & plugins', 'ph ph-tree-structure'],
  ['events', 'Live events', 'ph ph-pulse'],
  ['limits', 'Limits & metrics', 'ph ph-chart-bar'],
];

// ---- offline demo sample data (used only when the API is unreachable) ------

const DEMO = {
  status: { node: 'switchyard-01', node_id: 'rf:7fd2c4a9…b3', public: false, queue: { pending: 412, retry: 2, dead_letter: 2, delivered: 8871 } },
  plugins: {
    matrix: { connected: true, capabilities: { text: true, direct_messages: true, groups: true, reactions: true }, gauges: { queue_depth: 3 } },
    smtp: { connected: true, capabilities: { text: true, attachments: true }, gauges: { inbox_lag: 0.4 } },
    webhook: { connected: true, capabilities: { text: true }, gauges: {} },
    xmpp: { connected: false, capabilities: { text: true, direct_messages: true, presence: true }, gauges: {} },
  },
  routes: [
    { name: 'inbound-mail', sources: ['smtp:inbox'], destinations: ['matrix:#ops:fen.example'], identity_mode: 'pseudonymous', render: { tag: 'alias', max_chars: 0 }, policies: [] },
    { name: 'xmpp-mirror', sources: ['matrix:#ops:fen.example'], destinations: ['xmpp:ops@hub.oakmesh.net'], identity_mode: 'aliased', render: { tag: 'alias', max_chars: 120 }, policies: ['no-media-to-xmpp'] },
    { name: 'alerts-fanout', sources: ['webhook:ingest'], destinations: ['webhook:alerts'], identity_mode: 'pseudonymous', render: { tag: 'alias', max_chars: 0 }, policies: [] },
  ],
  deliveries: [
    { id: 101, message_id: '01991f2a-8c41-7b02-b3d1-4e0a92c7715f', route: 'inbound-mail', destination: 'matrix:#ops:fen.example', state: 'pending', reason: '—', attempts: 0, updated_at: new Date(Date.now() - 4000).toISOString() },
    { id: 102, message_id: '01991f2a-11d9-7e88-a0c2-90b1f4d6632a', route: 'alerts-fanout', destination: 'webhook:alerts', state: 'retry', reason: 'UPSTREAM_5XX', attempts: 3, updated_at: new Date(Date.now() - 120000).toISOString() },
    { id: 103, message_id: '01991f28-a410-7f33-b527-08d1e9c66740', route: 'alerts-fanout', destination: 'webhook:alerts', state: 'dead_letter', reason: 'MAX_ATTEMPTS', attempts: 8, updated_at: new Date(Date.now() - 2280000).toISOString() },
  ],
  federation: { peers: [
    { name: 'fen-relay', node_id: 'rf:7fd2…a1', trust: 'pinned', connected: true, last_seen: new Date(Date.now() - 8000).toISOString() },
    { name: 'oakmesh-hub', node_id: 'rf:a41f…c8', trust: 'pinned', connected: true, last_seen: new Date(Date.now() - 21000).toISOString() },
  ] },
  discovery: { mode: 'passive', our_advert: { name: 'switchyard-01', services: ['relay', 'store'], expires_in: '52m' }, peers: [
    { name: 'hub.oakmesh', services: ['relay', 'store'], seen: new Date(Date.now() - 21000).toISOString() },
    { name: 'fen-relay', services: ['relay'], seen: new Date(Date.now() - 8000).toISOString() },
  ] },
  pub: { public: true, services: [
    { name: 'lxmf-relay', type: 'lxmf', ingress: true, egress: true },
    { name: 'mesh-egress', type: 'meshtastic', ingress: false, egress: true },
  ] },
  identities: { links: [
    { id: 1, display_name: 'Dana', a: 'matrix:@d****mple', b: 'smtp:op****.net', verified_at: '2026-07-02' },
    { id: 2, display_name: 'Ops pager', a: 'matrix:@r****mple', b: 'xmpp:pa****.net', verified_at: '2026-07-15' },
  ] },
  challenges: [{ id: 7, target: 'xmpp:pa****.net', expires: 'in 9m' }],
  limits: { global: { queue_max: 50000, cas_bytes_used: 268435456, cas_max_bytes: 1073741824 }, per_route: { queue_max: 5000 }, per_sender: { messages_per_minute: 10, bytes_per_hour: 52428800 }, transport_budgets: { xmpp: 30, smtp: 60, webhook: 120 } },
};

const bytes = (n) => {
  if (!n) return '0';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v % 1 === 0 ? v : v.toFixed(1)) + ' ' + u[i];
};

// ---- component -------------------------------------------------------------

const SCREENS = NAV.map(([id]) => id);
const validScreen = (x) => (SCREENS.includes(x) ? x : null);

class App extends Component {
  state = {
    screen: validScreen(location.hash.slice(1)) || 'overview',
    theme: localStorage.getItem('rf-theme') || 'dark',
    live: false, ready: false,
    status: null, plugins: {}, routes: [], federation: { peers: [] },
    discovery: { mode: 'disabled', our_advert: null, peers: [] },
    pub: { public: false, services: [] },
    identities: { links: [] }, challenges: [], limits: null, metricsText: '',
    filter: 'pending', deliveries: [], sel: null,
    events: [], paused: false, demoPlay: false,
    cfgText: '', cfgMsg: null, restartList: [], prevList: [], prevAvailable: false, viewingPrev: null,
    showRollback: false, showLink: false,
    linkRequester: '', linkTarget: '', linkName: '',
    toast: null,
  };

  async componentDidMount() {
    try {
      const sess = await api('/auth/session');
      if (!sess.authenticated) {
        this.setState({ ready: true, authRequired: true, setupRequired: sess.setup_required });
        return;
      }
      this.setState({ authRole: sess.role || null });
    } catch (_e) { /* /auth unreachable: fall through to the API probe */ }
    try {
      const status = await api('/v1/status');
      this.setState({ live: true, status, ready: true });
      this.loadCommon();
      // setState is async in Preact — this.state.live isn't committed yet, so
      // pass live explicitly or loadScreen's guard skips the initial load
      // (blank editor / "no previous revision" on a reload while deep-linked).
      this.loadScreen(this.state.screen, true);
      this.openEvents();
      this.poll = setInterval(() => { this.refreshLight(); }, 4000);
    } catch (_e) {
      // offline: demo mode with sample data
      this.setState({
        live: false, ready: true,
        status: DEMO.status, plugins: DEMO.plugins, routes: DEMO.routes,
        federation: DEMO.federation, discovery: DEMO.discovery, pub: DEMO.pub,
        identities: DEMO.identities, challenges: DEMO.challenges, limits: DEMO.limits,
        deliveries: DEMO.deliveries,
        cfgText: DEMO_CONFIG,
      });
      this.startDemo();
    }
  }
  componentWillUnmount() {
    clearInterval(this.poll); clearInterval(this.demoTimer);
    if (this.es) this.es.close();
    if (this.toastT) clearTimeout(this.toastT);
  }

  // --- live data loading ---
  async loadCommon() {
    try { this.setState({ plugins: await api('/v1/plugins') }); } catch (_) {}
    try { this.setState({ routes: (await api('/v1/routes')).routes || [] }); } catch (_) {}
    try { this.setState({ federation: await api('/v1/federation') }); } catch (_) {}
    try { this.setState({ discovery: await api('/v1/discovery') }); } catch (_) {}
    try { this.setState({ pub: await api('/v1/public') }); } catch (_) {}
  }
  async refreshLight() {
    if (!this.state.live) return;
    try { this.setState({ status: await api('/v1/status') }); } catch (_) {}
    // Keep the plugin roster fresh (connect/disconnect, gauges) — the Overview
    // and Routes screens both read it, so a plugin (re)connecting shows up
    // without a manual reload.
    try { this.setState({ plugins: await api('/v1/plugins') }); } catch (_) {}
    if (this.state.screen === 'queue') this.loadQueue(this.state.filter);
  }
  loadScreen(screen, live = this.state.live) {
    if (!live) return;
    if (screen === 'queue') this.loadQueue(this.state.filter);
    if (screen === 'config') this.loadConfig();
    if (screen === 'identities') this.loadIdentities();
    if (screen === 'limits') this.loadLimits();
    if (screen === 'routes') this.loadCommon();
    if (screen === 'federation') this.loadCommon();
  }
  async loadQueue(state) {
    try { this.setState({ deliveries: (await api('/v1/queue?state=' + state)).deliveries || [] }); }
    catch (_) { this.setState({ deliveries: [] }); }
  }
  requeueDelivery = (id) => async () => {
    if (!this.state.live) { this.toastMsg('POST /v1/queue/' + id + '/requeue → 204 (demo)'); return; }
    try {
      await api('/v1/queue/' + id + '/requeue', { method: 'POST' });
      this.toastMsg('requeued delivery ' + id + ' → pending');
      this.setState({ sel: null });
      this.loadQueue(this.state.filter);
    } catch (e) { this.toastMsg('requeue → ' + (e.status || 'error')); }
  };
  purgeDeadLetters = async () => {
    if (!this.state.live) { this.toastMsg('POST /v1/queue/purge → 200 (demo)'); return; }
    try {
      const r = await api('/v1/queue/purge', { method: 'POST' });
      this.toastMsg('purged ' + (r.purged || 0) + ' dead-lettered deliveries');
      this.setState({ sel: null });
      this.loadQueue(this.state.filter);
    } catch (e) { this.toastMsg('purge → ' + (e.status || 'error')); }
  };
  async loadConfig() {
    try { this.setState({ cfgText: await api('/v1/config'), cfgMsg: null, viewingPrev: null }); } catch (_) {}
    await this.loadPrev();
  }
  // Probe the retained revisions (daemon keeps up to 5: .prev, .prev.2 …).
  // Stop at the first empty slot — they're contiguous newest-first.
  async loadPrev() {
    const list = [];
    for (let n = 1; n <= 5; n++) {
      try { list.push({ n, text: await api('/v1/config/prev?n=' + n) }); }
      catch (_) { break; }
    }
    this.setState({ prevList: list, prevAvailable: list.length > 0 });
  }
  async loadIdentities() {
    try { this.setState({ identities: await api('/v1/identities') }); } catch (_) {}
    try { this.setState({ challenges: (await api('/v1/identities/challenges')).challenges || [] }); } catch (_) {}
  }
  async loadLimits() {
    try { this.setState({ limits: await api('/v1/limits') }); } catch (_) {}
    try { this.setState({ metricsText: await api('/metrics') }); } catch (_) {}
  }

  openEvents() {
    try {
      const es = new EventSource('/v1/events');
      this.es = es;
      const TYPES = ['ingress', 'delivery', 'plugin', 'link_verified', 'config_applied', 'federation', 'advert'];
      const push = (type) => (ev) => {
        let msg = ev.data;
        try { msg = JSON.stringify(JSON.parse(ev.data)); } catch (_) {}
        this.setState((s) => (s.paused ? null : { events: [{ type, msg, t: clock() }, ...s.events].slice(0, 60) }));
      };
      TYPES.forEach((t) => es.addEventListener(t, push(t)));
      es.onmessage = push('event');
    } catch (_) {}
  }

  // --- demo mode events ---
  tickDemoEvents(seed) {
    const pool = [
      ['ingress', `{id: 01991${hex(3)}…${hex(4)}, protocol: smtp, routes: [inbound-mail]}`],
      ['delivery', `{id: 01991${hex(3)}…${hex(4)}, route: inbound-mail, state: delivered}`],
      ['delivery', `{id: 01991${hex(3)}…${hex(4)}, route: alerts-fanout, state: retry, reason: UPSTREAM_5XX}`],
      ['plugin', `{name: xmpp, up: ${Math.random() > 0.5}}`],
      ['federation', `{peer: fen-relay, up: true}`],
    ];
    const mk = (off) => { const [type, msg] = pool[Math.floor(Math.random() * pool.length)]; return { type, msg, t: clock(off) }; };
    if (seed) {
      const s = []; for (let i = 9; i >= 0; i--) s.push(mk(i * 4200)); this.setState({ events: s });
    } else {
      this.setState((st) => (st.paused ? null : { events: [mk(), ...st.events].slice(0, 60) }));
    }
  }

  // Synthetic event playback — lets an operator see the live views populate
  // (Overview + Live events) without waiting on real traffic. Auto-runs in
  // offline mode; a toggle drives it in live mode.
  startDemo() {
    if (this.demoTimer) return;
    this.tickDemoEvents(true);
    this.demoTimer = setInterval(() => this.tickDemoEvents(), 2500);
    this.setState({ demoPlay: true });
  }
  stopDemo() {
    clearInterval(this.demoTimer);
    this.demoTimer = null;
    this.setState({ demoPlay: false });
  }
  toggleDemo = () => { if (this.demoTimer) this.stopDemo(); else this.startDemo(); };

  // --- actions ---
  go = (id) => () => { location.hash = id; this.setState({ screen: id, sel: null }); this.loadScreen(id); };
  toggleTheme = () => { const t = this.state.theme === 'dark' ? 'light' : 'dark'; localStorage.setItem('rf-theme', t); this.setState({ theme: t }); };
  toastMsg(m) { this.setState({ toast: m }); clearTimeout(this.toastT); this.toastT = setTimeout(() => this.setState({ toast: null }), 3200); }

  validateCfg = async () => {
    this.setState({ cfgMsg: 'validating…' });
    if (!this.state.live) { setTimeout(() => this.setState({ cfgMsg: 'valid · 200 (demo)' }), 500); return; }
    try {
      await api('/v1/config/validate', { method: 'POST', headers: { 'content-type': 'application/x-yaml' }, body: this.state.cfgText });
      this.setState({ cfgMsg: 'valid · 200' });
    } catch (e) { this.setState({ cfgMsg: 'invalid · ' + (e.status || 'err') }); }
  };
  applyCfg = async () => {
    if (!this.state.live) { this.setState({ restartList: [{ n: 'smtp' }] }); this.toastMsg('PUT /v1/config → 200 (demo)'); return; }
    try {
      const res = await api('/v1/config', { method: 'PUT', headers: { 'content-type': 'application/x-yaml' }, body: this.state.cfgText });
      const rr = (res && res.restart_required) || [];
      this.setState({ cfgMsg: 'applied · 200', restartList: rr.map((n) => ({ n })) });
      this.toastMsg('PUT /v1/config → 200' + (rr.length ? ' · restart_required: [' + rr.join(', ') + ']' : ''));
      // Apply rotated the history — refresh the retained-revision list.
      await this.loadPrev();
    } catch (e) { this.setState({ cfgMsg: 'error · ' + (e.status || 'err') }); this.toastMsg('PUT /v1/config → ' + (e.status || 'error')); }
  };
  confirmRollback = async () => {
    this.setState({ showRollback: false });
    if (!this.state.live) { this.setState({ restartList: [] }); this.toastMsg('POST /v1/config/rollback → 200 (demo)'); return; }
    try {
      await api('/v1/config/rollback', { method: 'POST' });
      await this.loadConfig();
      this.setState({ restartList: [] });
      this.toastMsg('POST /v1/config/rollback → 200 · swapped with .prev');
    } catch (e) {
      const c = e.status;
      this.toastMsg('POST /v1/config/rollback → ' +
        (c === 404 ? '404 · no previous revision' : c === 409 ? '409 · env drift, no change' : (c || 'error')));
    }
  };
  viewPrev = (n) => () => {
    if (this.state.viewingPrev === n) { this.loadConfig(); return; }
    const rev = (this.state.prevList || []).find((r) => r.n === n);
    if (!rev) return;
    const label = n === 1 ? '.prev' : '.prev.' + n;
    this.setState({ cfgText: rev.text, viewingPrev: n, cfgMsg: 'viewing ' + label + ' — Apply to restore it' + (n === 1 ? ', or Roll back to swap' : '') });
  };
  unlink = (id) => async () => {
    if (this.state.live) { try { await api('/v1/identities/link/' + id, { method: 'DELETE' }); } catch (_) {} }
    this.setState((s) => ({ identities: { links: (s.identities.links || []).filter((x) => x.id !== id) } }));
    this.toastMsg('DELETE /v1/identities/link/' + id + ' → 204');
  };
  confirmLink = async () => {
    const target = this.state.linkTarget || 'smtp:dana@oakmesh.net';
    this.setState({ showLink: false });
    let cid = Math.floor(Math.random() * 900 + 100);
    if (this.state.live) {
      try {
        const res = await api('/v1/identities/link', {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ requester: this.state.linkRequester, target, display_name: this.state.linkName }),
        });
        cid = (res && res.challenge_id) || cid;
        this.loadIdentities();
      } catch (e) { this.toastMsg('POST /v1/identities/link → ' + (e.status || 'error')); return; }
    } else {
      const masked = target.replace(/^(\w+:.{2}).+(.{4})$/, '$1****$2');
      this.setState((s) => ({ challenges: [...s.challenges, { id: cid, target: masked, expires: 'in 10m' }] }));
    }
    this.toastMsg('POST /v1/identities/link → 202 · challenge_id ' + cid);
  };

  // ---- render ----
  doLogin = async () => {
    try {
      const r = await passkeyLogin();
      this.setState({ authRequired: false, authRole: r.role });
      this.componentDidMount();
    } catch (e) { this.setState({ authError: String(e.message || e) }); }
  };

  doSetup = async () => {
    try {
      await passkeyRegister(this.state.setupToken, 'administrator', 'first-admin');
      await this.doLogin();
    } catch (e) { this.setState({ authError: String(e.message || e) }); }
  };

  doLogout = async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch (_) {}
    this.setState({ authRequired: true, authRole: null });
  };

  renderAuth() {
    const s = this.state;
    return html`<div class="rf-root" style="display:flex;align-items:center;justify-content:center;min-height:100vh">
      <div class="card elev-md" style="max-width:380px;padding:28px;gap:14px">
        <div class="card-kicker">RelayFabric</div>
        <div class="card-title">${s.setupRequired ? 'First-run setup' : 'Sign in'}</div>
        ${s.setupRequired ? html`
          <p style="font-size:13px;opacity:.8">No passkeys are registered. Paste the one-time
          setup token printed on the relayfabric-ui console, then register this device's
          passkey — it becomes the administrator credential.</p>
          <input class="input" placeholder="setup token" value=${s.setupToken || ''}
                 onInput=${(e) => this.setState({ setupToken: e.target.value })} />
          <button class="btn btn-primary" onClick=${this.doSetup}>Register passkey</button>
        ` : html`
          <p style="font-size:13px;opacity:.8">Authenticate with a registered passkey.</p>
          <button class="btn btn-primary" onClick=${this.doLogin}>Sign in with passkey</button>
        `}
        ${s.authError && html`<div style="color:var(--color-danger,#d66);font-size:12px">${s.authError}</div>`}
      </div>
    </div>`;
  }

  render() {
    if (this.state.authRequired) return this.renderAuth();
    const s = this.state;
    if (!s.ready) return html`<div style="display:grid;place-items:center;height:100vh;color:var(--color-text)">Connecting…</div>`;
    const rootClass = 'rf-root' + (s.theme === 'light' ? ' rf-light' : '');
    const q = (s.status && s.status.queue) || {};
    return html`
    <div class=${rootClass} style="display:flex;min-height:100vh;background:var(--color-bg);color:var(--color-text);font-family:var(--font-body)">
      ${this.sidebar(s, q)}
      <main style="flex:1;min-width:0;padding:26px 32px 40px;overflow:auto">
        ${!s.live && html`<div class="card elev-sm" style="flex-direction:row;align-items:center;gap:10px;margin-bottom:16px;font-size:12.5px"><i class="ph ph-plugs" style="font-size:16px;color:var(--color-accent)"></i><span>Offline — the admin socket isn't reachable. Showing sample data.</span></div>`}
        ${s.screen === 'overview' && this.overview(s, q)}
        ${s.screen === 'queue' && this.queue(s)}
        ${s.screen === 'config' && this.config(s)}
        ${s.screen === 'identities' && this.identitiesScreen(s)}
        ${s.screen === 'federation' && this.federationScreen(s)}
        ${s.screen === 'routes' && this.routesScreen(s)}
        ${s.screen === 'events' && this.eventsScreen(s)}
        ${s.screen === 'limits' && this.limitsScreen(s)}
      </main>
      ${s.showRollback && this.rollbackDialog()}
      ${s.showLink && this.linkDialog(s)}
      ${s.toast && html`<div class="card elev-lg" style="position:fixed;right:22px;bottom:22px;flex-direction:row;align-items:center;gap:10px;padding:12px 16px;font-size:13px;z-index:50"><i class="ph ph-check-circle" style="font-size:17px;color:var(--color-accent)"></i>${s.toast}</div>`}
    </div>`;
  }

  sidebar(s, q) {
    const nodeId = (s.status && s.status.node_id) || 'rf:…';
    return html`
    <aside style="width:216px;flex:none;display:flex;flex-direction:column;gap:4px;padding:18px 12px 14px;border-right:1px solid var(--color-divider);background:color-mix(in srgb,var(--color-surface) 45%,transparent);position:sticky;top:0;height:100vh">
      <div style="display:flex;align-items:center;gap:10px;padding:0 10px 14px">
        <img src="logo.png" alt="RelayFabric" style="width:44px;height:44px;flex:none;border-radius:8px"/>
        <div>
          <div style="font-family:var(--font-heading);font-weight:500;font-size:17px;letter-spacing:-0.01em">RelayFabric</div>
          <div class="text-muted" style="font-size:11px;margin-top:2px">switchyardd · admin</div>
        </div>
      </div>
      <nav style="display:flex;flex-direction:column;gap:2px">
        ${NAV.map(([id, label, icon]) => html`
          <button onClick=${this.go(id)} style="display:flex;align-items:center;gap:9px;width:100%;padding:7px 10px;border:none;border-radius:var(--radius-md);background:${s.screen === id ? 'color-mix(in srgb,var(--color-accent) 14%,transparent)' : 'transparent'};color:${s.screen === id ? 'var(--color-accent)' : 'inherit'};font:inherit;font-size:13.5px;text-align:left;cursor:pointer">
            <i class=${icon} style="font-size:16px"></i>${label}
          </button>`)}
      </nav>
      <div style="flex:1"></div>
      <div style="display:flex;flex-direction:column;gap:8px;padding:12px 10px 0;border-top:1px solid var(--color-divider)">
        <div class="text-muted" style="font-size:10.5px;font-family:ui-monospace,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">admin.sock ${s.live ? '· connected' : '· offline'}${s.authRole ? ' · ' + s.authRole : ''}</div>
          ${s.authRole && html`<button class="btn btn-ghost" style="font-size:11px;padding:2px 6px" onClick=${this.doLogout}>Sign out</button>`}
        <div class="text-muted" style="font-size:10.5px;font-family:ui-monospace,Menlo,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${shortNode(nodeId)}</div>
        <div style="display:flex;gap:10px;font-size:11px">
          <a href="/docs" target="_blank" style="text-decoration:none">/docs</a>
          <a href="/v1/openapi.json" target="_blank" style="text-decoration:none">/v1/openapi.json</a>
        </div>
        <button class="btn btn-secondary" onClick=${this.toggleTheme} style="justify-content:flex-start;font-size:12.5px"><i class=${s.theme === 'dark' ? 'ph ph-sun' : 'ph ph-moon'} style="font-size:15px"></i>${s.theme === 'dark' ? 'Light theme' : 'Dark theme'}</button>
        <div class="text-muted" style="margin-top:4px;font-size:10px;line-height:1.6">
          Sponsored by <a href="https://tarnover.com" target="_blank" rel="noopener" style="text-decoration:none">Tarnover</a><br/>
          © Jascha Wanger / Tarnover, LLC · <a href="https://github.com/RelayFabric/RelayFabric/blob/main/LICENSE" target="_blank" rel="noopener" style="text-decoration:none">Apache-2.0</a>
        </div>
      </div>
    </aside>`;
  }

  header(title, sub, right) {
    return html`<div style="display:flex;align-items:center;gap:14px;margin-bottom:16px;flex-wrap:wrap">
      <div><h4 style="margin:0">${title}</h4><span class="text-muted" style="font-size:12.5px">${sub}</span></div>
      ${right ? html`<span style="flex:1"></span>${right}` : ''}
    </div>`;
  }

  overview(s, q) {
    const pl = Object.entries(s.plugins || {});
    const up = pl.filter(([, p]) => p.connected).length;
    const peers = (s.federation.peers || []);
    const fedUp = peers.filter((p) => p.connected).length;
    const adverts = (s.discovery.peers || []);
    const spark = [3, 5, 4, 7, 9, 6, 8, 11, 7, 9];
    return html`
      ${this.header('Overview', 'GET /v1/status · refreshed live')}
      <div style="display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin-bottom:16px">
        <div class="card elev-sm">
          <span class="card-kicker">Node</span>
          <div style="display:flex;align-items:center;gap:8px">
            <span style="width:8px;height:8px;border-radius:50%;background:var(--color-accent);animation:rf-pulse 2.4s ease-in-out infinite"></span>
            <span style="font-family:var(--font-heading);font-weight:500;font-size:clamp(15px,1.6vw,22px);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${(s.status && s.status.node) || '—'}</span>
          </div>
          <div class="card-meta" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${shortNode((s.status && s.status.node_id) || '')} · public: ${String((s.status && s.status.public) || false)}</div>
        </div>
        <div class="card elev-sm">
          <span class="card-kicker">Queue · pending</span>
          <div style="display:flex;align-items:flex-end;justify-content:space-between;gap:10px;min-width:0">
            <span style="font-family:var(--font-heading);font-weight:500;font-size:24px">${q.pending || 0}</span>
            <div style="display:flex;align-items:flex-end;gap:3px;height:26px">
              ${spark.map((v) => html`<div style="width:5px;height:${Math.round(4 + v * 2.1)}px;border-radius:2px;background:var(--color-accent-700)"></div>`)}
            </div>
          </div>
          <div class="card-meta">${q.retry || 0} retry · ${q.dead_letter || 0} dead_letter</div>
        </div>
        <div class="card elev-sm">
          <span class="card-kicker">Plugins</span>
          <span style="font-family:var(--font-heading);font-weight:500;font-size:24px">${up}<span style="font-size:13px;opacity:.6"> / ${pl.length} connected</span></span>
          <div class="card-meta" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${pl.filter(([, p]) => !p.connected).map(([n]) => n).join(', ') || 'all up'}</div>
        </div>
        <div class="card elev-sm">
          <span class="card-kicker">Federation</span>
          <span style="font-family:var(--font-heading);font-weight:500;font-size:24px">${fedUp}<span style="font-size:13px;opacity:.6"> / ${peers.length} peers up</span></span>
          <div class="card-meta" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">discovery: ${s.discovery.mode || 'disabled'} · ${adverts.length} adverts</div>
        </div>
      </div>
      <div style="display:grid;grid-template-columns:1.45fr 1fr;gap:14px">
        <div class="card elev-sm" style="gap:var(--space-3)">
          <div style="display:flex;align-items:baseline;justify-content:space-between">
            <span class="card-title" style="font-size:15px">Live events</span>
            <button class="btn btn-ghost" onClick=${this.go('events')} style="font-size:12px">open feed</button>
          </div>
          <div style="display:flex;flex-direction:column;gap:7px">
            ${s.events.slice(0, 6).map((e) => html`
              <div style="display:grid;grid-template-columns:64px 118px 1fr;gap:10px;align-items:center;font-size:12.5px">
                <span class="text-muted" style="font-family:ui-monospace,Menlo,monospace;font-size:11px">${e.t}</span>
                <span class=${evTag(e.type)} style="justify-content:center">${e.type}</span>
                <span style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:ui-monospace,Menlo,monospace;font-size:11.5px">${e.msg}</span>
              </div>`)}
            ${s.events.length === 0 && html`<span class="text-muted" style="font-size:12.5px">Waiting for events…</span>`}
          </div>
        </div>
        <div class="card elev-sm" style="gap:var(--space-3)">
          <div style="display:flex;align-items:baseline;justify-content:space-between">
            <span class="card-title" style="font-size:15px">Plugins</span>
            <button class="btn btn-ghost" onClick=${this.go('routes')} style="font-size:12px">routes & plugins</button>
          </div>
          <div style="display:flex;flex-direction:column;gap:8px">
            ${pl.map(([name, p]) => html`
              <div style="display:flex;align-items:center;gap:10px;font-size:13px">
                <span style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${name}</span>
                <span class="text-muted" style="font-size:11px">${gaugeNote(p.gauges)}</span>
                <span style="flex:1"></span>
                <span class=${tagFor(p.connected ? 'connected' : 'disconnected')}>${p.connected ? 'connected' : 'disconnected'}</span>
              </div>`)}
          </div>
        </div>
      </div>`;
  }

  queue(s) {
    const counts = { pending: 0, retry: 0, dead_letter: 0, expired: 0 };
    const q = (s.status && s.status.queue) || {};
    Object.assign(counts, q);
    return html`
      ${this.header('Queue', 'GET /v1/queue?state=' + s.filter + ' · newest first · refs masked, bodies never included', html`
        <div style="display:flex;gap:4px">
          ${['pending', 'retry', 'dead_letter', 'expired'].map((f) => html`
            <button onClick=${() => { this.setState({ filter: f, sel: null }); this.loadQueue(f); }} style="border:1px solid ${s.filter === f ? 'var(--color-accent)' : 'var(--color-divider)'};background:transparent;color:${s.filter === f ? 'var(--color-accent)' : 'inherit'};font:inherit;font-size:12px;padding:5px 12px;border-radius:var(--radius-md);cursor:pointer;font-family:ui-monospace,Menlo,monospace">${f} (${counts[f] || 0})</button>`)}
          ${s.filter === 'dead_letter' && (counts.dead_letter || (s.deliveries || []).length) ? html`
            <button onClick=${this.purgeDeadLetters} title="Delete all dead-lettered deliveries" style="border:1px solid var(--color-divider);background:transparent;color:inherit;font:inherit;font-size:12px;padding:5px 12px;border-radius:var(--radius-md);cursor:pointer;margin-left:6px"><i class="ph ph-trash" style="font-size:12px"></i> purge</button>` : ''}
        </div>`)}
      <div style="display:flex;gap:18px;align-items:flex-start">
        <div style="flex:1;min-width:0;overflow-x:auto">
          <table class="table" style="table-layout:fixed;width:100%;min-width:620px">
            <thead><tr><th style="width:19%">message_id</th><th style="width:15%">Route</th><th style="width:24%">Destination</th><th>State</th><th style="width:15%">Reason</th><th style="width:6%">Att.</th><th style="width:9%">Updated</th></tr></thead>
            <tbody>
              ${(s.deliveries || []).map((m) => html`
                <tr onClick=${() => this.setState({ sel: m })} style="cursor:pointer">
                  <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px;color:${s.sel && s.sel.message_id === m.message_id ? 'var(--color-accent)' : 'inherit'};overflow:hidden;text-overflow:ellipsis">${shortId(m.message_id)}</td>
                  <td style="overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,Menlo,monospace;font-size:12px">${m.route}</td>
                  <td class="text-muted" style="font-family:ui-monospace,Menlo,monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis">${m.destination}</td>
                  <td><span class=${tagFor(m.state)}>${m.state}</span></td>
                  <td class="text-muted" style="font-size:12px;overflow:hidden;text-overflow:ellipsis;font-family:ui-monospace,Menlo,monospace">${m.reason || '—'}</td>
                  <td>${m.attempts}</td>
                  <td class="text-muted">${ago(m.updated_at)}</td>
                </tr>`)}
              ${(s.deliveries || []).length === 0 && html`<tr><td colspan="7" class="text-muted" style="padding:16px 6px">No ${s.filter} deliveries.</td></tr>`}
            </tbody>
          </table>
        </div>
        ${s.sel && html`
          <div class="card elev-md" style="width:340px;flex:none;gap:var(--space-3);position:sticky;top:26px">
            <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:8px">
              <div style="min-width:0">
                <div class="card-kicker">GET /v1/messages/{id}</div>
                <div style="font-family:ui-monospace,Menlo,monospace;font-size:12px;margin-top:3px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${s.sel.message_id}</div>
              </div>
              <button class="btn btn-icon btn-secondary" onClick=${() => this.setState({ sel: null })} style="width:28px;height:28px"><i class="ph ph-x" style="font-size:14px"></i></button>
            </div>
            <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12px">
              <span class="text-muted">route</span><span style="font-family:ui-monospace,Menlo,monospace">${s.sel.route}</span>
              <span class="text-muted">destination</span><span style="font-family:ui-monospace,Menlo,monospace">${s.sel.destination}</span>
              <span class="text-muted">state</span><span><span class=${tagFor(s.sel.state)}>${s.sel.state}</span></span>
              <span class="text-muted">attempts</span><span>${s.sel.attempts}${s.sel.reason && s.sel.reason !== '—' ? ' · ' + s.sel.reason : ''}</span>
              <span class="text-muted">created</span><span>${s.sel.created_at ? new Date(s.sel.created_at).toLocaleString() : '—'}</span>
              <span class="text-muted">updated</span><span>${s.sel.updated_at ? new Date(s.sel.updated_at).toLocaleString() : '—'}</span>
            </div>
            ${['dead_letter', 'failed', 'expired'].includes(s.sel.state) && s.sel.id != null ? html`
              <button class="btn btn-secondary" onClick=${this.requeueDelivery(s.sel.id)} style="justify-content:center">
                <i class="ph ph-arrow-counter-clockwise" style="font-size:14px"></i> Requeue for another attempt
              </button>` : ''}
            <div class="card-meta">Bodies are never included in any admin response.</div>
          </div>`}
      </div>`;
  }

  config(s) {
    return html`
      ${this.header('Config', 'GET /v1/config · byte-verbatim YAML · secret refs never resolved', html`
        ${s.cfgMsg ? html`<span class="tag tag-accent">${s.cfgMsg}</span>` : ''}
        <button class="btn btn-secondary" onClick=${this.validateCfg}>Validate</button>
        <button class="btn btn-primary" onClick=${this.applyCfg}>Apply</button>`)}
      <div style="display:grid;grid-template-columns:1fr 300px;gap:16px;align-items:start">
        <textarea class="input" value=${s.cfgText} onInput=${(e) => this.setState({ cfgText: e.target.value, cfgMsg: null })} spellcheck="false" style="min-height:470px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;line-height:1.6;padding:14px"></textarea>
        <div style="display:flex;flex-direction:column;gap:12px">
          <div class="card elev-sm" style="gap:var(--space-2)">
            <span class="card-kicker">Previous revisions · up to 5 kept</span>
            ${s.prevAvailable ? html`
              <div style="display:flex;flex-direction:column;gap:5px">
                ${s.prevList.map((r) => html`
                  <div style="display:flex;align-items:center;gap:8px;font-size:12px">
                    <span style="font-family:ui-monospace,Menlo,monospace">${r.n === 1 ? '.prev' : '.prev.' + r.n}</span>
                    <span class="text-muted">${r.text.length} B</span>
                    <span style="flex:1"></span>
                    <button class="btn btn-ghost" onClick=${this.viewPrev(r.n)} style="font-size:11px">${s.viewingPrev === r.n ? 'view current' : 'view'}</button>
                  </div>`)}
              </div>
              <div style="display:flex;align-items:center;gap:8px;margin-top:2px">
                <span style="flex:1"></span>
                <button class="btn btn-ghost" onClick=${() => this.setState({ showRollback: true })} style="font-size:11.5px">roll back</button>
              </div>
              <div class="card-meta">Newest first (.prev). Each Apply rotates the history one slot; the oldest of 5 drops off. View any, then Apply to restore it. Roll back re-validates .prev and swaps it in (env drift → 409).</div>
            ` : html`<div class="text-muted" style="font-size:12.5px">No previous revision yet — Apply saves one.</div>`}
          </div>
          ${s.restartList.length > 0 && html`
            <div class="card elev-sm" style="gap:var(--space-2)">
              <span class="card-kicker">restart_required</span>
              <div style="display:flex;gap:6px;flex-wrap:wrap">${s.restartList.map((r) => html`<span class="tag tag-outline" style="font-family:ui-monospace,Menlo,monospace">${r.n}</span>`)}</div>
              <div class="card-meta">Applied, but these plugins need a process restart to take full effect.</div>
            </div>`}
          <div class="card elev-sm" style="gap:var(--space-2)">
            <span class="card-kicker">Endpoints</span>
            <div style="font-family:ui-monospace,Menlo,monospace;font-size:11.5px;line-height:1.9;opacity:.85">
              <div>GET · /v1/config</div>
              <div>GET · /v1/config/prev</div>
              <div>PUT · /v1/config</div>
              <div>POST · /v1/config/validate</div>
              <div>POST · /v1/config/rollback</div>
            </div>
          </div>
        </div>
      </div>`;
  }

  identitiesScreen(s) {
    const links = (s.identities.links || []);
    return html`
      ${this.header('Identities', 'GET /v1/identities · refs masked, full refs never leave the daemon', html`
        <button class="btn btn-primary" onClick=${() => this.setState({ showLink: true, linkRequester: '', linkTarget: '', linkName: '' })}><i class="ph ph-link" style="font-size:15px"></i>Link identity</button>`)}
      <table class="table" style="margin-bottom:22px">
        <thead><tr><th>id</th><th>Display name</th><th>Side A</th><th>Side B</th><th>Verified</th><th></th></tr></thead>
        <tbody>
          ${links.map((i) => html`
            <tr>
              <td class="text-muted" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${i.id}</td>
              <td>${i.display_name || i.displayName || '—'}</td>
              <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${i.a}</td>
              <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${i.b}</td>
              <td class="text-muted">${i.verified_at || i.verified || '—'}</td>
              <td style="text-align:right"><button class="btn btn-ghost" onClick=${this.unlink(i.id)} style="font-size:12px">unlink</button></td>
            </tr>`)}
          ${links.length === 0 && html`<tr><td colspan="6" class="text-muted" style="padding:16px 6px">No verified identity links.</td></tr>`}
        </tbody>
      </table>
      <div class="card elev-sm" style="max-width:600px;gap:var(--space-3)">
        <span class="card-kicker">Pending challenges · pending_count: ${s.challenges.length}</span>
        ${s.challenges.length > 0 ? html`<div style="display:flex;flex-direction:column;gap:8px">
          ${s.challenges.map((c) => html`<div style="display:flex;align-items:center;gap:12px;font-size:13px">
            <span class="tag tag-outline" style="font-family:ui-monospace,Menlo,monospace">#${c.id}</span>
            <span style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${c.target}</span>
            <span style="flex:1"></span>
            <span class="text-muted" style="font-size:12px">expires ${c.expires}</span>
          </div>`)}
        </div>` : html`<span class="text-muted" style="font-size:13px">No pending challenges.</span>`}
        <div class="card-meta">Verification codes are delivered to the target over its plugin and never appear in any API response.</div>
      </div>`;
  }

  federationScreen(s) {
    const peers = (s.federation.peers || []);
    const adverts = (s.discovery.peers || []);
    const our = s.discovery.our_advert;
    const pub = s.pub || { public: false, services: [] };
    const svcs = pub.services || [];
    return html`
      ${this.header('Federation & discovery', 'GET /v1/federation · GET /v1/discovery · GET /v1/public · dial addresses deliberately omitted')}
      <div class="card elev-sm" style="gap:var(--space-3);margin-bottom:22px;max-width:900px">
        <span class="card-kicker">Public node · <span class=${tagFor(String(pub.public))}>${pub.public ? 'public' : 'private'}</span></span>
        ${pub.public ? html`
          <table class="table">
            <thead><tr><th>Service</th><th>Protocol</th><th>Ingress</th><th>Egress</th></tr></thead>
            <tbody>
              ${svcs.map((sv) => html`<tr>
                <td>${sv.name || '—'}</td>
                <td><span class="tag tag-neutral">${sv.type || '—'}</span></td>
                <td><span class=${tagFor(String(!!sv.ingress))}>${String(!!sv.ingress)}</span></td>
                <td><span class=${tagFor(String(!!sv.egress))}>${String(!!sv.egress)}</span></td>
              </tr>`)}
              ${svcs.length === 0 && html`<tr><td colspan="4" class="text-muted" style="padding:16px 6px">Public, but no public_services declared — every federated route's protocols must be covered by an ingress/egress entry (SPEC §112.8), so this node accepts no federated traffic yet.</td></tr>`}
            </tbody>
          </table>` : html`<span class="text-muted" style="font-size:12.5px">This node is private: it does not advertise services or accept federated ingress. Set <code>node.public: true</code> and declare <code>public_services</code> to expose it.</span>`}
      </div>
      <table class="table" style="margin-bottom:22px">
        <thead><tr><th>Peer</th><th>node_id</th><th>Trust</th><th>Connected</th><th>Last seen</th></tr></thead>
        <tbody>
          ${peers.map((p) => html`<tr>
            <td style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${p.name || '—'}</td>
            <td class="text-muted" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${shortNode(p.node_id || '')}</td>
            <td><span class="tag tag-neutral">${p.trust || '—'}</span></td>
            <td><span class=${tagFor(String(p.connected))}>${String(p.connected)}</span></td>
            <td class="text-muted">${ago(p.last_seen)}</td>
          </tr>`)}
          ${peers.length === 0 && html`<tr><td colspan="5" class="text-muted" style="padding:16px 6px">No federation peers configured.</td></tr>`}
        </tbody>
      </table>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;max-width:900px">
        <div class="card elev-sm" style="gap:var(--space-3)">
          <span class="card-kicker">Our advert · mode: ${s.discovery.mode || 'disabled'}</span>
          ${our ? html`<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12.5px">
            <span class="text-muted">name</span><span>${our.name}</span>
            <span class="text-muted">services</span><span style="display:flex;gap:5px">${(our.services || []).map((c) => html`<span class="tag tag-accent">${c}</span>`)}</span>
            <span class="text-muted">expires</span><span class="text-muted">${our.expires_in || 're-signed on each request'}</span>
          </div>` : html`<span class="text-muted" style="font-size:12.5px">This node publishes no advert (discovery ${s.discovery.mode || 'disabled'}).</span>`}
        </div>
        <div class="card elev-sm" style="gap:var(--space-3)">
          <span class="card-kicker">Peer adverts · re-verified on serve</span>
          <div style="display:flex;flex-direction:column;gap:9px">
            ${adverts.map((a) => html`<div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:12.5px">
              <span style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${a.name}</span>
              ${(a.services || a.caps || []).map((c) => html`<span class="tag tag-neutral">${typeof c === 'string' ? c : c.n}</span>`)}
              <span style="flex:1"></span>
              <span class="text-muted" style="font-size:11.5px">rx ${ago(a.seen)}</span>
            </div>`)}
            ${adverts.length === 0 && html`<span class="text-muted" style="font-size:12.5px">No peer adverts held.</span>`}
          </div>
        </div>
      </div>`;
  }

  routesScreen(s) {
    const pl = Object.entries(s.plugins || {});
    return html`
      ${this.header('Routes & plugins', 'GET /v1/routes · GET /v1/plugins')}
      <h6 style="margin-bottom:6px">Plugins</h6>
      <table class="table" style="margin-bottom:24px">
        <thead><tr><th>Name</th><th>Connected</th><th>Capabilities</th><th>Gauges</th></tr></thead>
        <tbody>
          ${pl.map(([name, p]) => html`<tr>
            <td style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${name}</td>
            <td><span class=${tagFor(p.connected ? 'connected' : 'disconnected')}>${p.connected ? 'connected' : 'disconnected'}</span></td>
            <td><div style="display:flex;gap:5px;flex-wrap:wrap">${capList(p.capabilities).map((c) => html`<span class="tag tag-neutral">${c}</span>`)}</div></td>
            <td class="text-muted" style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${gaugeNote(p.gauges)}</td>
          </tr>`)}
        </tbody>
      </table>
      <h6 style="margin-bottom:6px">Routes</h6>
      <table class="table">
        <thead><tr><th>Route</th><th>Sources</th><th>Destinations</th><th>identity_mode</th><th>Render</th><th>Policies</th></tr></thead>
        <tbody>
          ${(s.routes || []).map((r) => html`<tr>
            <td style="font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${r.name}</td>
            <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${(r.sources || []).join(', ')}</td>
            <td style="font-family:ui-monospace,Menlo,monospace;font-size:12px">${(r.destinations || []).join(', ')}</td>
            <td><span class="tag tag-neutral">${r.identity_mode || '—'}</span></td>
            <td class="text-muted" style="font-size:12px">${r.render ? (r.render.tag || 'alias') + ' · ttl ' + (r.render.max_chars || 0) : '—'}</td>
            <td class="text-muted" style="font-size:12px">${(r.policies || []).join(', ') || '—'}</td>
          </tr>`)}
          ${(s.routes || []).length === 0 && html`<tr><td colspan="6" class="text-muted" style="padding:16px 6px">No routes configured.</td></tr>`}
        </tbody>
      </table>`;
  }

  eventsScreen(s) {
    return html`
      ${this.header('Live events', 'GET /v1/events · text/event-stream · advisory, REST is source of truth', html`
        <button class=${'btn ' + (s.demoPlay ? 'btn-primary' : 'btn-secondary')} onClick=${this.toggleDemo}><i class=${s.demoPlay ? 'ph ph-stop' : 'ph ph-flask'} style="font-size:15px"></i>${s.demoPlay ? 'Stop sample events' : 'Play sample events'}</button>
        <button class="btn btn-secondary" onClick=${() => this.setState({ paused: !s.paused })}><i class=${s.paused ? 'ph ph-play' : 'ph ph-pause'} style="font-size:15px"></i>${s.paused ? 'Resume' : 'Pause'}</button>`)}
      <div style="display:flex;flex-direction:column">
        ${s.events.slice(0, 40).map((e) => html`
          <div style="display:grid;grid-template-columns:76px 128px 1fr;gap:12px;align-items:center;padding:7px 2px;font-size:13px;border-bottom:1px solid color-mix(in srgb,var(--color-text) 6%,transparent)">
            <span class="text-muted" style="font-family:ui-monospace,Menlo,monospace;font-size:11.5px">${e.t}</span>
            <span class=${evTag(e.type)} style="justify-content:center">${e.type}</span>
            <span style="font-family:ui-monospace,Menlo,monospace;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${e.msg}</span>
          </div>`)}
        ${s.events.length === 0 && html`<span class="text-muted" style="font-size:13px;padding:10px 2px">Waiting for events…</span>`}
      </div>`;
  }

  limitsScreen(s) {
    const l = s.limits || DEMO.limits;
    const tb = Object.entries(l.transport_budgets || {});
    return html`
      ${this.header('Limits & metrics', 'GET /v1/limits · configured caps + live CAS disk use · GET /metrics')}
      <div style="display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;max-width:900px;margin-bottom:14px">
        <div class="card elev-sm" style="gap:var(--space-2)">
          <span class="card-kicker">global</span>
          <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12.5px;font-family:ui-monospace,Menlo,monospace">
            <span class="text-muted">queue_max</span><span style="text-align:right">${(l.global.queue_max || 0).toLocaleString()}</span>
            <span class="text-muted">cas used</span><span style="text-align:right">${bytes(l.global.cas_bytes_used || 0)}${l.global.cas_max_bytes ? ' / ' + bytes(l.global.cas_max_bytes) : ' (unlimited)'}</span>
          </div>
        </div>
        <div class="card elev-sm" style="gap:var(--space-2)">
          <span class="card-kicker">per_route</span>
          <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12.5px;font-family:ui-monospace,Menlo,monospace">
            <span class="text-muted">queue_max</span><span style="text-align:right">${(l.per_route.queue_max || 0).toLocaleString()}</span>
          </div>
        </div>
        <div class="card elev-sm" style="gap:var(--space-2)">
          <span class="card-kicker">per_sender</span>
          <div style="display:grid;grid-template-columns:auto 1fr;gap:4px 12px;font-size:12.5px;font-family:ui-monospace,Menlo,monospace">
            <span class="text-muted">messages_per_minute</span><span style="text-align:right">${l.per_sender.messages_per_minute || 0}</span>
            <span class="text-muted">bytes_per_hour</span><span style="text-align:right">${bytes(l.per_sender.bytes_per_hour)}</span>
          </div>
        </div>
      </div>
      ${tb.length > 0 && html`<div class="card elev-sm" style="max-width:900px;gap:var(--space-2);margin-bottom:14px">
        <span class="card-kicker">transport_budgets · egress msgs/min per protocol</span>
        <div style="display:flex;gap:16px;flex-wrap:wrap;font-family:ui-monospace,Menlo,monospace;font-size:12.5px">${tb.map(([k, v]) => html`<span>${k} <span class="text-muted">${v}</span></span>`)}</div>
      </div>`}
      <div class="card elev-sm" style="max-width:900px;gap:var(--space-2)">
        <span class="card-kicker">Prometheus exposition · GET /metrics</span>
        <pre style="margin:0;font-family:ui-monospace,Menlo,monospace;font-size:12px;line-height:1.7;opacity:.85;white-space:pre-wrap;max-height:320px;overflow:auto">${s.metricsText || '# GET /metrics — load this screen against a live daemon to see counters'}</pre>
      </div>`;
  }

  rollbackDialog() {
    return html`<div class="dialog-backdrop"><div class="dialog">
      <div class="dialog-title">Roll back to .prev?</div>
      <div class="dialog-body">POST /v1/config/rollback re-validates the .prev file before touching anything — if a secret reference no longer resolves (env drift) it returns 409 and no file changes. On success, current and .prev swap.</div>
      <div class="dialog-actions">
        <button class="btn btn-secondary" onClick=${() => this.setState({ showRollback: false })}>Cancel</button>
        <button class="btn btn-primary" onClick=${this.confirmRollback}>Roll back</button>
      </div>
    </div></div>`;
  }

  linkDialog(s) {
    return html`<div class="dialog-backdrop"><div class="dialog">
      <div class="dialog-title">Link identity</div>
      <div class="dialog-body" style="margin-bottom:2px">POST /v1/identities/link → 202 with a challenge_id. A verification code goes to the target over its plugin; it never appears here.</div>
      <div class="field"><label>Requester · protocol:ref</label><input class="input" value=${s.linkRequester} onInput=${(e) => this.setState({ linkRequester: e.target.value })} placeholder="matrix:@dana:fen.example"/></div>
      <div class="field"><label>Target · protocol:ref</label><input class="input" value=${s.linkTarget} onInput=${(e) => this.setState({ linkTarget: e.target.value })} placeholder="smtp:dana@oakmesh.net"/></div>
      <div class="field"><label>Display name</label><input class="input" value=${s.linkName} onInput=${(e) => this.setState({ linkName: e.target.value })} placeholder="Dana"/></div>
      <div class="dialog-actions">
        <button class="btn btn-secondary" onClick=${() => this.setState({ showLink: false })}>Cancel</button>
        <button class="btn btn-primary" onClick=${this.confirmLink}>Send challenge</button>
      </div>
    </div></div>`;
  }
}

function hex(n) { return Array.from({ length: n }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join(''); }
function capList(caps) { return caps ? Object.entries(caps).filter(([, v]) => v === true).map(([k]) => k) : []; }
function gaugeNote(g) {
  if (!g) return '';
  const ent = Object.entries(g);
  if (ent.length === 0) return '';
  return ent.slice(0, 2).map(([k, v]) => k + ' ' + v).join(' · ');
}

const DEMO_CONFIG = `# relayfabric.yaml (offline sample)
node:
  name: switchyard-01
  data_dir: /var/lib/relayfabric

plugins:
  smtp:  { listen: 127.0.0.1:2525 }
  matrix:
    homeserver: https://fen.example
    as_token: \${env:RF_MATRIX_TOKEN}

routes:
  inbound-mail:
    sources: [smtp:inbox]
    destinations: [matrix:#ops:fen.example]
    identity_mode: pseudonymous`;

render(html`<${App} />`, document.getElementById('app'));
