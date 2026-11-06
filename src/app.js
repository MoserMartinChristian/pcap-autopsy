/*
 * PCAP Autopsy – user interface. Talks to the analysis worker, renders verdict, findings,
 * connections, packet list, charts, report export and thresholds.
 */
(function () {
  'use strict';
  const PA = window.PA;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const esc = PA.report.esc;
  const ICON = {
    critical: '<svg viewBox="0 0 12 12" aria-hidden="true"><rect x="1" y="1" width="10" height="10" rx="1.5"/></svg>',
    warning: '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M6 .8l5.4 10.2H.6z"/></svg>',
    info: '<svg viewBox="0 0 12 12" aria-hidden="true"><circle cx="6" cy="6" r="5"/></svg>',
    ok: '<svg viewBox="0 0 12 12" aria-hidden="true"><path d="M1.5 6.5l3 3 6-7" fill="none" stroke="currentColor" stroke-width="2.2"/></svg>',
  };
  const VICON = {
    network: '<svg viewBox="0 0 24 24"><circle cx="5" cy="12" r="2.5"/><circle cx="19" cy="12" r="2.5"/><path d="M7.5 12h3l1.5-3 2 6 1.5-3h1"/></svg>',
    client: '<svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/></svg>',
    server: '<svg viewBox="0 0 24 24"><rect x="4" y="3" width="16" height="7" rx="1.5"/><rect x="4" y="14" width="16" height="7" rx="1.5"/><path d="M8 6.5h.01M8 17.5h.01"/></svg>',
    mixed: '<svg viewBox="0 0 24 24"><path d="M4 7h10l-3-3M20 17H10l3 3"/></svg>',
    inconclusive: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M9.5 9.5a2.5 2.5 0 1 1 3.5 2.3c-.7.3-1 .9-1 1.7M12 17h.01"/></svg>',
    clean: '<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  };
  const st = { lang: 'en', result: null, file: '', worker: null, reqId: 0, pending: new Map(), conn: null, pkConn: null, sortConn: 'sev', anon: false, charts: [], chartConn: null, chartDir: null, rowsCache: new Map(), rowTotal: 0, hit: null };

  // ---------- language ----------
  const L = () => (st.lang === 'de' ? PA.i18n.de : PA.i18n.en);
  const U = () => L().ui;
  const n0 = (v) => PA.i18n.n0(v, st.lang);
  const kb = (v) => PA.i18n.kb(v, st.lang);
  function applyLang() {
    document.documentElement.lang = st.lang;
    for (const el of $$('[data-i18n]')) { const v = U()[el.dataset.i18n]; if (typeof v === 'string') el.textContent = v; }
    for (const el of $$('[data-i18n-aria]')) { const v = U()[el.dataset.i18nAria]; if (v) el.setAttribute('aria-label', v); }
    $('#lang-en').setAttribute('aria-pressed', String(st.lang === 'en'));
    $('#lang-de').setAttribute('aria-pressed', String(st.lang === 'de'));
    const lim = PA.config.limits.testedMB;
    $('#dz-limit').textContent = lim ? U().filesizeNote(lim, PA.config.limits.testedPackets) : '';
    renderDemos();
    if (st.result) renderResult(false);
    try { localStorage.setItem('pa-lang', st.lang); } catch (e) { /* storage may be blocked */ }
  }
  function setLang(l) { st.lang = l; applyLang(); }

  // ---------- theme ----------
  function setTheme(t) { document.documentElement.dataset.theme = t; try { localStorage.setItem('pa-theme', t); } catch (e) { /* ignore */ } st.charts.forEach((c) => c.redraw()); }
  function isDark() { const t = document.documentElement.dataset.theme; return t === 'dark' || (t === 'auto' && !window.matchMedia('(prefers-color-scheme: light)').matches); }

  // ---------- toast / clipboard ----------
  let toastT = 0;
  function toast(msg) { const t = $('#toast'); t.textContent = msg; t.classList.add('on'); clearTimeout(toastT); toastT = setTimeout(() => t.classList.remove('on'), 1600); }
  async function copy(text) {
    try { await navigator.clipboard.writeText(text); }
    catch (e) { const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch (e2) { /* ignore */ } ta.remove(); }
    toast(U().copied);
  }
  function download(name, text, type) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = document.createElement('a'); a.href = url; a.download = name; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // ---------- views ----------
  function show(view) { for (const v of ['intake', 'busy', 'error', 'result']) $('#view-' + v).hidden = v !== view; }

  // ---------- worker ----------
  function newWorker() {
    if (st.worker) st.worker.terminate();
    const src = $('#pa-core').textContent + '\n' + $('#pa-worker').textContent;
    const url = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
    const w = new Worker(url);
    URL.revokeObjectURL(url);
    w.onmessage = onWorker;
    w.onerror = (e) => { e.preventDefault(); showError('err.internal', { msg: e.message || 'worker error' }); };
    st.worker = w;
    st.pending.clear(); st.rowsCache.clear();
    return w;
  }
  function ask(msg) { return new Promise((res) => { const id = ++st.reqId; st.pending.set(id, res); st.worker.postMessage(Object.assign({ reqId: id }, msg)); }); }
  function onWorker(ev) {
    const m = ev.data;
    if (m.type === 'progress') progress(m);
    else if (m.type === 'result') { st.result = m.result; renderResult(true); }
    else if (m.type === 'error') showError(m.code, m.params);
    else if (m.reqId && st.pending.has(m.reqId)) { const f = st.pending.get(m.reqId); st.pending.delete(m.reqId); f(m); }
  }
  function start(label, msg) {
    st.result = null; st.file = label; st.conn = null; st.pkConn = null; st.chartConn = null; st.hit = null;
    destroyCharts();
    $('#busy-file').textContent = label;
    $('#busy-fill').style.width = '0%';
    $('#busy-text').textContent = U().reading + ' …';
    show('busy');
    $('#btn-cancel').focus();
    newWorker().postMessage(msg);
  }
  function analyzeFile(file) { if (!file) return; start(file.name + ' · ' + kb(file.size), { type: 'file', file }); st.fileName = file.name; }
  function analyzeDemo(id) { const s = PA.scenarios.list.find((x) => x.id === id); st.fileName = 'demo-' + id + '.pcap'; start('demo-' + id + '.pcap · ' + (st.lang === 'de' ? s.de : s.en), { type: 'demo', id }); }
  function progress(m) {
    const pct = m.total ? Math.min(100, (m.done / m.total) * 100) : 0;
    $('#busy-fill').style.width = (m.phase === 'analyse' ? 100 : pct).toFixed(1) + '%';
    $('#busy-bar').setAttribute('aria-valuenow', String(Math.round(pct)));
    $('#busy-text').textContent = m.phase === 'analyse' ? U().analyzing + ' · ' + n0(m.packets) + ' ' + U().packets + ' …' : U().reading + ' ' + kb(m.done) + ' ' + U().of + ' ' + kb(m.total) + ' · ' + n0(m.packets) + ' ' + U().packets;
  }
  function cancel() { if (st.worker) st.worker.terminate(); st.worker = null; show('intake'); toast(U().cancelled); }
  function showError(code, params) {
    window.__paLastError = code + (params && params.msg ? ': ' + params.msg : '');
    let t = U().err[code] || U().err['err.internal'];
    t = t.replace(/\{(\w+)\}/g, (m, k) => (params && params[k] !== undefined ? params[k] : ''));
    $('#error-text').textContent = t;
    show('error');
    $('#btn-error-back').focus();
  }

  // ---------- demos ----------
  function renderDemos() {
    const g = U().groups;
    $('#demos').innerHTML = PA.scenarios.list.map((s) => `<button type="button" class="demo${s.group === 'trap' ? ' trap' : ''}" data-demo="${s.id}"><span class="g">${esc(g[s.group] || s.group)}</span><span class="n">${esc(st.lang === 'de' ? s.de : s.en)}</span></button>`).join('');
  }

  // ---------- result ----------
  const connLbl = (c) => (c ? PA.report.connLabel(c) : '');
  function fmtDur(s) { return s >= 1 ? n0(s) + ' s' : n0(s * 1000) + ' ms'; }
  function renderResult(first) {
    const r = st.result;
    show('result');
    $('#res-file').textContent = st.file;
    renderVerdict(first);
    renderFindings();
    renderConns();
    renderPacketsShell();
    renderCharts();
    renderReport();
    renderThresholds();
    const fin = r.findings.filter((f) => f.sev !== 'info').length;
    $('#cnt-findings').textContent = fin || '';
    $('#cnt-conns').textContent = r.connTotal || r.conns.length;
    if (first) { selectTab('findings', false); $('#verdict').focus({ preventScroll: true }); }
  }
  function renderVerdict(first) {
    const r = st.result, T = L(), v = r.verdict;
    const el = $('#verdict');
    el.className = 'verdict v-' + v.v + (first ? ' reveal' : '');
    const max = Math.max(1, v.score.network, v.score.client, v.score.server);
    const sc = (k, col) => `<div class="score"><span>${esc(T.cat[k])}</span><span class="track" aria-hidden="true"><span class="fill" style="background:var(${col})" data-w="${(100 * v.score[k] / max).toFixed(0)}"></span></span><span class="num">${v.score[k]}</span></div>`;
    const p = r.point;
    const share = p.share === null ? 0.5 : p.share;
    const pinLeft = p.pos === 'unknown' ? 50 : Math.max(6, Math.min(94, (1 - share) * 100));
    const s = r.summary;
    el.innerHTML = `
      <div class="v-left">
        <div class="v-label"><span>${esc(U().verdictLabel)}</span><span class="pill conf-${v.conf}" title="${esc(U().confidence)}">${esc(U().confidence)}: ${esc(T.confShort[v.conf])}</span></div>
        <div class="v-main"><span class="v-icon" aria-hidden="true">${VICON[v.v]}</span><span>${esc(T.verdict[v.v])}</span></div>
        <p class="v-sub">${esc(T.verdictSub[v.v])}</p>
        ${v.missing.length && (v.v === 'inconclusive' || v.v === 'clean' || v.missing.includes('oneWay')) ? '<ul class="v-missing">' + v.missing.map((k) => '<li>' + esc(T.missing[k]) + '</li>').join('') + '</ul>' : ''}
        ${v.second.length ? '<div class="second"><b>' + esc(U().secondCap) + ':</b> ' + v.second.map((k) => esc(T.second[k])).join(' ') + '</div>' : ''}
        <div class="stats" style="margin-top:14px">
          <span>${esc(U().packetsTab)} <b>${n0(s.packets)}</b></span><span>${esc(U().duration)} <b>${fmtDur(s.duration)}</b></span>
          <span>TCP <b>${n0(s.tcpConns)}</b></span><span>UDP <b>${n0(s.udpFlows)}</b></span><span>DNS <b>${n0(s.dnsQueries)}</b></span>
          <span>${esc(U().format)} <b>${esc(s.format)}</b></span><span>${esc(U().link)} <b>${esc(s.linktypes.map((l) => l.name).join(', '))}</b></span>
        </div>
      </div>
      <div class="v-side">
        <div class="scores" role="group" aria-label="${esc(U().cat)}"><h3>${esc(st.lang === 'de' ? 'Belege nach Ursache' : 'Evidence by cause')}</h3>${sc('network', '--net')}${sc('client', '--cli')}${sc('server', '--srv')}</div>
        <div class="point"><h3>${esc(U().pointLabel)}</h3>
          <div class="path" aria-hidden="true"><span class="line"></span><span class="host c">C</span><span class="host s">S</span><span class="pin ${p.pos === 'unknown' ? 'unknown' : ''}" style="left:${first ? 50 : pinLeft}%" data-left="${pinLeft}"><svg viewBox="0 0 20 20"><path d="M10 0a7 7 0 0 0-7 7c0 5 7 13 7 13s7-8 7-13a7 7 0 0 0-7-7zm0 9.5A2.5 2.5 0 1 1 10 4.5a2.5 2.5 0 0 1 0 5z"/></svg></span></div>
          <p><b>${esc(T.point[p.pos])}</b> · ${esc(T.conf[p.conf])}. ${esc(T.point.expl(p))}</p>
          <p class="mut" style="color:var(--mut)">${esc(T.point.why)}</p>
        </div>
      </div>`;
    requestAnimationFrame(() => requestAnimationFrame(() => {
      $$('.fill', el).forEach((f) => { f.style.width = f.dataset.w + '%'; });
      const pin = $('.pin', el); if (pin) pin.style.left = pin.dataset.left + '%';
    }));
  }

  function findingCard(f, idx) {
    const T = L(), tx = PA.i18n.text(st.lang, f);
    const c = f.conn !== undefined ? st.result.conns[f.conn] : null;
    const m = PA.i18n.metrics(st.lang, f);
    const pk = f.pkts || [];
    return `<article class="finding" id="f-${idx}" data-f="${idx}">
      <div class="f-head"><span class="sev ${f.sev}">${ICON[f.sev]}${esc(T.sev[f.sev])}</span>
        <div><h3 class="f-title">${esc(tx.t)}</h3>
        <div class="f-meta"><span class="pill">${esc(U().cat)}: ${esc(T.cat[f.cat])}</span><span class="pill">${esc(U().side)}: ${esc(T.Side[f.side])}</span><span class="pill conf-${f.conf}">${esc(T.confShort[f.conf])}</span>${c ? `<button type="button" class="pill" data-conn="${c.id}" style="cursor:pointer">${esc(connLbl(c))}</button>` : ''}</div></div></div>
      <div class="f-body"><div><p>${esc(tx.d)}</p><div class="next"><b>${esc(U().nextStep)}</b>${esc(tx.n)}</div></div>
        <div>
          ${pk.length ? `<div class="evid"><span class="lbl">${esc(U().evidence)}:</span>${pk.slice(0, 16).map((p) => `<button type="button" class="pkt" data-pkt="${p}" data-pconn="${f.conn !== undefined ? f.conn : ''}" aria-label="${esc(U().jump)} ${p}">#${p}</button>`).join('')}${pk.length > 16 ? `<span class="lbl">+${pk.length - 16}</span>` : ''}</div>` : ''}
          ${m.length ? `<dl class="kv">${m.map((x) => `<dt>${esc(x.label)}</dt><dd>${esc(x.value)}</dd>`).join('')}</dl>` : ''}
          ${f.filter ? `<div class="filter-l">${esc(U().filter)}</div><div class="filter"><code>${esc(f.filter)}</code><button type="button" data-copy="${esc(f.filter)}">${esc(U().copy)}</button></div>` : ''}
          ${f.frames ? `<div class="filter-l">${esc(U().frames)}</div><div class="filter"><code>${esc(f.frames)}</code><button type="button" data-copy="${esc(f.frames)}">${esc(U().copy)}</button></div>` : ''}
        </div></div></article>`;
  }
  function renderFindings() {
    const r = st.result;
    const fin = r.findings.map((f, i) => [f, i]).filter(([f]) => f.sev !== 'info');
    const notes = r.findings.map((f, i) => [f, i]).filter(([f]) => f.sev === 'info');
    // repeated findings (same id on many connections) are folded: the first three are shown, the rest render on demand
    st.restGroups = [];
    const groups = (items) => PA.report.groupFindings(items, 3).map((g) => {
      let out = g.shown.map(([f, i]) => findingCard(f, i)).join('');
      if (g.rest.length) { st.restGroups.push(g.rest); out += `<details class="more-same" data-rest="${st.restGroups.length - 1}"><summary>${esc(U().moreSame(g.rest.length))}</summary><div class="rest-body"></div></details>`; }
      return out;
    }).join('');
    let h = '';
    if (fin.length) h += `<h2 class="fgroup-h">${esc(U().findings)} · ${n0(fin.length)}</h2>` + groups(fin);
    else h += `<div class="empty">${esc(U().noFindings)}</div>`;
    if (notes.length) h += `<details class="notes"${fin.length ? '' : ' open'}><summary>${esc(U().notes)} · ${n0(notes.length)}</summary>${groups(notes)}</details>`;
    $('#panel-findings').innerHTML = h;
    for (const d of $$('details.more-same', $('#panel-findings'))) d.addEventListener('toggle', () => fillRest(d));
  }

  const REST_CAP = 200;
  function fillRest(d) {
    const body = $('.rest-body', d);
    if (!d.open || body.childElementCount) return;
    const rest = st.restGroups[Number(d.dataset.rest)] || [];
    body.innerHTML = rest.slice(0, REST_CAP).map(([f, i]) => findingCard(f, i)).join('') + (rest.length > REST_CAP ? `<p style="color:var(--mut)">${esc(U().cappedSame(REST_CAP, rest.length))}</p>` : '');
  }
  // make sure the card of finding idx exists (it may sit in a folded group)
  function revealFinding(idx) {
    let el = $('#f-' + idx);
    if (el) return el;
    for (const d of $$('details.more-same')) {
      const rest = st.restGroups[Number(d.dataset.rest)] || [];
      const pos = rest.findIndex((x) => x[1] === idx);
      if (pos < 0) continue;
      d.open = true; fillRest(d);
      el = $('#f-' + idx);
      if (!el) { $('.rest-body', d).insertAdjacentHTML('beforeend', findingCard(rest[pos][0], idx)); el = $('#f-' + idx); }
      return el;
    }
    return null;
  }

  // ---------- connections ----------
  function timeline(c, findings) {
    const r = st.result, T0 = 0, T1 = Math.max(r.summary.duration, 1e-3);
    const x = (t) => (t - T0) / (T1 - T0) * 216 + 2;
    let s = `<svg class="tl" viewBox="0 0 220 22" aria-hidden="true"><rect x="0" y="10" width="220" height="2" fill="var(--line)"/><rect x="${x(c.start).toFixed(1)}" y="7" width="${Math.max(2, x(c.end) - x(c.start)).toFixed(1)}" height="8" rx="3" fill="var(--line2)"/>`;
    for (const fi of c.findings || []) {
      const f = findings[fi]; if (!f || f.t === undefined) continue;
      const col = f.sev === 'critical' ? 'var(--crit)' : f.sev === 'warning' ? 'var(--warn)' : 'var(--info)';
      const X = x(f.t);
      s += f.sev === 'critical' ? `<rect x="${(X - 3.5).toFixed(1)}" y="7.5" width="7" height="7" fill="${col}"/>` : f.sev === 'warning' ? `<path d="M${X.toFixed(1)} 6.5l4.2 8h-8.4z" fill="${col}"/>` : `<circle cx="${X.toFixed(1)}" cy="11" r="3" fill="${col}"/>`;
    }
    return s + '</svg>';
  }
  function renderConns() {
    const r = st.result, T = L();
    const SEVR = { critical: 0, warning: 1, info: 2, ok: 3 };
    const list = r.conns.slice();
    if (st.sortConn === 'sev') list.sort((a, b) => SEVR[a.sev] - SEVR[b.sev] || b.bytes - a.bytes);
    else if (st.sortConn === 'time') list.sort((a, b) => a.start - b.start);
    else list.sort((a, b) => b.bytes - a.bytes);
    const shown = list.slice(0, 500);
    const sel = st.conn !== null ? r.conns[st.conn] : null;
    let h = `<div class="ctools" role="group" aria-label="sort">
      <button type="button" class="btn small" data-sort="sev" aria-pressed="${st.sortConn === 'sev'}">${esc(U().sortSev)}</button>
      <button type="button" class="btn small" data-sort="time" aria-pressed="${st.sortConn === 'time'}">${esc(U().sortTime)}</button>
      <button type="button" class="btn small" data-sort="bytes" aria-pressed="${st.sortConn === 'bytes'}">${esc(U().sortBytes)}</button>
      <span class="note">${n0(r.connTotal || r.conns.length)} ${esc(U().conns)}${list.length > shown.length ? ' · ' + shown.length + ' ' + (st.lang === 'de' ? 'angezeigt' : 'shown') : ''}</span></div>`;
    if (sel) {
      const fs = (sel.findings || []).map((i) => r.findings[i]);
      h += `<div class="conn-detail"><h3>${esc(connLbl(sel))} <span class="sub" style="color:var(--mut);font-weight:500">${esc(sel.proto.toUpperCase())} · ${esc(sel.app)}</span></h3>
        <div class="stats"><span>${esc(U().pk)} <b>${n0(sel.pkts)}</b></span><span>${esc(U().bytes)} <b>${kb(sel.bytes)}</b></span><span>${esc(U().dur)} <b>${fmtDur(sel.end - sel.start)}</b></span>${sel.hsRtt !== null && sel.hsRtt !== undefined ? `<span>Handshake RTT <b>${n0(sel.hsRtt)} ms</b></span>` : ''}${sel.mss ? `<span>MSS <b>${sel.mss.map((v) => v || '–').join(' / ')}</b></span>` : ''}${sel.ws !== null && sel.ws !== undefined ? `<span>WS <b>${Array.isArray(sel.ws) ? sel.ws.join(' / ') : sel.ws}</b></span>` : ''}<span>${esc(U().retr)} <b>${sel.retrans}</b></span></div>
        ${fs.length ? '<ul style="margin:10px 0 0;padding-left:18px">' + fs.map((f) => `<li><span class="sev ${f.sev}" style="padding:1px 6px">${ICON[f.sev]}${esc(T.sev[f.sev])}</span> <a href="#f-${f.n}" data-gof="${f.n}">${esc(PA.i18n.text(st.lang, f).t)}</a></li>`).join('') + '</ul>' : ''}
        <div class="filter-l">${esc(U().filter)}</div><div class="filter"><code>${esc(sel.filter || '')}</code><button type="button" data-copy="${esc(sel.filter || '')}">${esc(U().copy)}</button></div>
        ${sel.tcpStream >= 0 ? `<div class="filter-l">Wireshark tcp.stream</div><div class="filter"><code>tcp.stream eq ${sel.tcpStream}</code><button type="button" data-copy="tcp.stream eq ${sel.tcpStream}">${esc(U().copy)}</button></div>` : ''}
        <div class="acts"><button type="button" class="btn small" data-showpk="${sel.id}">${esc(U().packetsTab)}</button>${sel.proto === 'tcp' ? `<button type="button" class="btn small" data-showch="${sel.id}">${esc(U().charts)}</button>` : ''}</div></div>`;
    }
    h += `<div class="tbl-wrap"><table class="conns"><thead><tr><th>${esc(U().state)}</th><th>${esc(U().conn)}</th><th class="hide-sm">${esc(U().app)}</th><th class="num">${esc(U().pk)}</th><th class="num hide-sm">${esc(U().bytes)}</th><th class="num hide-sm">${esc(U().rtt)}</th><th class="num">${esc(U().retr)}</th><th class="hide-sm">Timeline</th></tr></thead><tbody>`;
    for (const c of shown) {
      const sevTxt = c.sev === 'ok' ? 'OK' : T.sev[c.sev];
      h += `<tr data-c="${c.id}" tabindex="0" class="${st.conn === c.id ? 'sel' : ''}" aria-selected="${st.conn === c.id}"><td><span class="sev ${c.sev}">${ICON[c.sev]}${esc(sevTxt)}</span></td><td><div class="ep">${esc(c.client)}:${c.cport} → ${esc(c.server)}:${c.sport}</div><div class="sub">${esc(c.proto.toUpperCase())}${c.sni ? ' · ' + esc(c.sni) : c.host ? ' · ' + esc(c.host) : ''}</div></td><td class="hide-sm">${esc(c.app)}</td><td class="num">${n0(c.pkts)}</td><td class="num hide-sm">${kb(c.bytes)}</td><td class="num hide-sm">${c.rtt !== null && c.rtt !== undefined ? n0(c.rtt) + ' ms' : '–'}</td><td class="num">${c.retrans || 0}</td><td class="hide-sm">${timeline(c, r.findings)}</td></tr>`;
    }
    h += '</tbody></table></div>';
    $('#panel-conns').innerHTML = h;
  }

  // ---------- packet list (virtual) ----------
  const ROWH = () => (window.matchMedia('(max-width: 640px)').matches ? 44 : 26);
  function renderPacketsShell() {
    const r = st.result;
    const c = st.pkConn !== null ? r.conns[st.pkConn] : null;
    $('#pk-filter').innerHTML = c ? `<span class="pill">${esc(U().onlyConn)}: ${esc(connLbl(c))}</span><button type="button" class="btn small" id="pk-all">${esc(U().showAll)}</button>` : `<span class="pill">${esc(U().allPackets)} · ${n0(r.summary.packets)}</span>`;
    st.rowTotal = c ? -1 : r.summary.packets;
    st.rowsCache.clear();
    if (st.rowTotal < 0) ask({ type: 'rows', from: 0, count: 1, conn: st.pkConn }).then((m) => { st.rowTotal = m.total; sizeList(); drawRows(); });
    else { sizeList(); drawRows(); }
  }
  function sizeList() { $('#pk-spacer').style.height = Math.max(0, st.rowTotal) * ROWH() + 'px'; $('#pk-list').setAttribute('aria-rowcount', String(st.rowTotal)); }
  let drawQueued = false;
  function drawRows() {
    if (drawQueued) return; drawQueued = true;
    requestAnimationFrame(() => {
      drawQueued = false;
      const list = $('#pk-list'); if (list.offsetParent === null || st.rowTotal <= 0) return;
      const h = ROWH();
      const first = Math.max(0, Math.floor(list.scrollTop / h) - 10);
      const last = Math.min(st.rowTotal, Math.ceil((list.scrollTop + list.clientHeight) / h) + 10);
      const page = 200;
      const need = [];
      for (let p = Math.floor(first / page); p <= Math.floor((last - 1) / page); p++) if (!st.rowsCache.has(p)) need.push(p);
      if (need.length) {
        for (const p of need) st.rowsCache.set(p, null);
        Promise.all(need.map((p) => ask({ type: 'rows', from: p * page, count: page, conn: st.pkConn }).then((m) => st.rowsCache.set(p, m.rows)))).then(drawRows);
      }
      const sp = $('#pk-spacer');
      let html = '';
      for (let k = first; k < last; k++) {
        const pg = st.rowsCache.get(Math.floor(k / page));
        const row = pg ? pg[k % page] : null;
        if (!row) continue;
        const cls = 'pk-row ' + row.cls + (st.hit === row.no ? ' hit' : '');
        html += `<div class="${cls}" role="row" aria-rowindex="${k + 1}" style="top:${k * h}px" data-no="${row.no}"><span>${row.no}</span><span>${row.t.toFixed(6)}</span><span title="${esc(row.src)}">${esc(row.src)}</span><span title="${esc(row.dst)}">${esc(row.dst)}</span><span>${esc(row.proto)}</span><span>${row.len}</span><span title="${esc(row.info)}">${esc(row.info)}</span></div>`;
      }
      sp.innerHTML = html;
    });
  }
  async function jumpToPacket(no, conn) {
    selectTab('packets', false);
    const wantConn = conn !== undefined && conn !== null && conn !== '' ? +conn : null;
    if (wantConn !== st.pkConn) { st.pkConn = wantConn; renderPacketsShell(); }
    const m = await ask({ type: 'locate', no, conn: st.pkConn });
    let pos = m.pos;
    if (pos < 0 && st.pkConn !== null) { st.pkConn = null; renderPacketsShell(); pos = no - 1; }
    if (st.rowTotal < 0) await new Promise((res) => setTimeout(res, 60));
    st.hit = no;
    const list = $('#pk-list');
    list.scrollTop = Math.max(0, pos * ROWH() - list.clientHeight / 3);
    drawRows();
    list.focus({ preventScroll: true });
  }

  // ---------- charts ----------
  function destroyCharts() { st.charts.forEach((c) => c.destroy()); st.charts = []; }
  function chartConns() { return st.result.conns.filter((c) => c.proto === 'tcp' && !c.stub && (c.payload[0] + c.payload[1]) > 0); }
  function renderCharts() {
    const list = chartConns();
    const p = $('#panel-charts');
    destroyCharts();
    if (!list.length) { p.innerHTML = `<div class="empty">${esc(U().pickConn)}</div>`; return; }
    const SEVR = { critical: 0, warning: 1, info: 2, ok: 3 };
    if (st.chartConn === null || !list.some((c) => c.id === st.chartConn)) st.chartConn = list.slice().sort((a, b) => SEVR[a.sev] - SEVR[b.sev] || b.bytes - a.bytes)[0].id;
    const c = st.result.conns[st.chartConn];
    if (st.chartDir === null) st.chartDir = c.payload[1] >= c.payload[0] ? 1 : 0;
    p.innerHTML = `<div class="chart-tools"><label for="ch-conn" class="sr-only">${esc(U().conn)}</label><select id="ch-conn">${list.slice(0, 800).map((x) => `<option value="${x.id}"${x.id === st.chartConn ? ' selected' : ''}>${x.sev === 'ok' ? '✓' : x.sev === 'critical' ? '■' : x.sev === 'warning' ? '▲' : '●'} #${x.id} ${esc(connLbl(x))}</option>`).join('')}</select>
      <div class="seg" role="group" aria-label="direction"><button type="button" data-dir="0" aria-pressed="${st.chartDir === 0}">${esc(U().dirC2S)}</button><button type="button" data-dir="1" aria-pressed="${st.chartDir === 1}">${esc(U().dirS2C)}</button></div>
      <span class="sub" style="color:var(--mut);font-size:.8rem">${st.lang === 'de' ? 'Ziehen zum Zoomen, Doppelklick zurück, Klick auf einen Punkt springt zum Paket.' : 'Drag to zoom, double-click to reset, click a point to jump to its packet.'}</span></div>
      <div class="charts" id="charts"><div class="empty">…</div></div><div class="moments" id="moments"></div>`;
    ask({ type: 'series', conn: st.chartConn }).then((m) => buildCharts(m.series));
  }
  function buildCharts(S) {
    destroyCharts();
    const wrap = $('#charts');
    if (!S) { wrap.innerHTML = `<div class="empty">${esc(U().pickConn)}</div>`; return; }
    const D = S.dirs[st.chartDir], t0 = S.t0;
    const M = PA.store.M;
    const col = { data: 'var(--chart-data)', ack: 'var(--chart-ack)', win: 'var(--chart-win)', rtt: 'var(--chart-rtt)' };
    const cv = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
    const crit = cv('--crit'), warn = cv('--warn'), info = cv('--info');
    const rel = (arr, stride) => { const o = arr.slice(); for (let i = 0; i < o.length; i += stride) o[i] -= t0; return o; };
    const seg = rel(D.seg, 5), ack = rel(D.ack, 5), win = rel(D.win, 4), rtt = rel(D.rtt, 3), tp = rel(D.tput, 2);
    const xmax = Math.max(S.t1 - t0, 1e-3);
    const markers = S.keys.filter((k) => k.k === 'rst' || k.k === 'zw' || (k.k === 'retrans' && k.d === st.chartDir)).slice(0, 120).map((k) => ({ x: k.t - t0, color: k.k === 'zw' ? warn : crit }));
    const fmtT = (v) => (xmax < 2 ? n0(v * 1000) + ' ms' : n0(v) + ' s');
    const fmtB = (v) => (Math.abs(v) >= 1048576 ? n0(v / 1048576) + 'M' : Math.abs(v) >= 1024 ? n0(v / 1024) + 'K' : n0(v));
    // y range follows the data; the window edge may raise it by at most 30 % so the data stays readable
    let segMax = 0, edgeMax = 0, ackMax = 0;
    for (let i = 0; i < seg.length; i += 5) segMax = Math.max(segMax, seg[i + 2]);
    for (let i = 0; i < ack.length; i += 5) { ackMax = Math.max(ackMax, ack[i + 1]); edgeMax = Math.max(edgeMax, ack[i + 2]); }
    const base = Math.max(segMax, ackMax);
    const ymax = base ? Math.max(base, Math.min(edgeMax, base * 1.3)) : edgeMax;
    const segColor = (d, i) => (d[i + 3] & M.RETRANS ? crit : d[i + 3] & M.OOO ? warn : cv('--chart-data'));
    const pickSeg = (d, i) => ({ no: d[i + 4], label: '#' + d[i + 4] + ' · ' + fmtT(d[i]) + ' · seq ' + fmtB(d[i + 1]) + (d[i + 3] & M.RETRANS ? ' · ' + (st.lang === 'de' ? 'Wiederholung' : 'retransmission') : '') });
    const pickAck = (d, i) => ({ no: d[i + 4], label: '#' + d[i + 4] + ' · ACK ' + fmtB(d[i + 1]) + ' · win ' + fmtB(d[i + 2] - d[i + 1]) });
    const charts = [
      { id: 'tseq', title: U().tseq, sub: st.chartDir === 0 ? U().dirC2S : U().dirS2C, wide: true, spec: { x: { min: 0, max: xmax, fmt: fmtT }, y: { min: 0, max: Math.max(ymax, 1), fmt: fmtB, auto: true, label: 'seq' }, markers, layers: [
        { kind: 'step', data: ack, stride: 5, color: cv('--chart-win'), dash: [4, 3], width: 1, map: 2, pick: null, _edge: true },
        { kind: 'step', data: ack, stride: 5, color: cv('--chart-ack'), width: 1.4, pick: pickAck },
        { kind: 'ibeam', data: seg, stride: 5, color: cv('--chart-data'), colorOf: segColor, special: (d, i) => d[i + 3] & M.RETRANS, pick: pickSeg },
      ] }, legend: [[cv('--chart-data'), U().legendData], [crit, U().legendRetr], [cv('--chart-ack'), U().legendAck], [cv('--chart-win'), U().legendWin]] },
      { id: 'rtt', title: U().rttChart, sub: st.lang === 'de' ? 'Daten → ACK am Messpunkt' : 'data → ACK at the capture point', spec: { x: { min: 0, max: xmax, fmt: fmtT }, y: { min: 0, max: Math.max(1e-3, maxStep(rtt, 3, 1)) * 1.1, fmt: (v) => n0(v * 1000) + ' ms', auto: true }, markers, layers: [{ kind: 'dots', data: rtt, stride: 3, color: cv('--chart-rtt'), r: 2.2, pick: (d, i) => ({ no: d[i + 2], label: '#' + d[i + 2] + ' · RTT ' + n0(d[i + 1] * 1000) + ' ms' }) }] }, legend: [[cv('--chart-rtt'), 'RTT']] },
      { id: 'tput', title: U().tput, sub: 'Mbit/s', spec: { x: { min: 0, max: xmax, fmt: fmtT }, y: { min: 0, max: Math.max(1, maxStep(tp, 2, 1)) * 1.1, fmt: (v) => n0(v / 1e6) }, markers, layers: [{ kind: 'step', data: tp, stride: 2, color: cv('--chart-data'), fill: true, pick: (d, i) => ({ no: null, label: fmtT(d[i]) + ' · ' + n0(d[i + 1] / 1e6) + ' Mbit/s' }) }] }, legend: [[cv('--chart-data'), U().tput]] },
      { id: 'win', title: U().winChart, sub: (S.ws === null ? (st.lang === 'de' ? 'Skalierung unbekannt – Rohwerte' : 'scale factor unknown – raw values') : S.ws === 'off' ? (st.lang === 'de' ? 'ohne Window Scaling' : 'window scaling off') : 'WS ' + S.ws.join('/')), spec: { x: { min: 0, max: xmax, fmt: fmtT }, y: { min: 0, max: Math.max(1, maxStep(win, 4, 1)) * 1.1, fmt: fmtB }, markers, layers: [
        { kind: 'step', data: win, stride: 4, color: cv('--chart-win'), width: 1.6, pick: (d, i) => ({ no: d[i + 3], label: '#' + d[i + 3] + ' · win ' + fmtB(d[i + 1]) }) },
        { kind: 'dots', data: zeroPts(win), stride: 4, color: warn, r: 3.5, pick: (d, i) => ({ no: d[i + 3], label: '#' + d[i + 3] + ' · zero window' }) },
      ] }, legend: [[cv('--chart-win'), U().winChart], [warn, U().legendZw]] },
    ];
    // window edge = ack + window: precompute into its own array
    const edge = []; for (let i = 0; i < ack.length; i += 5) edge.push(ack[i], ack[i + 2], 0, 0, ack[i + 4]);
    charts[0].spec.layers[0].data = edge;
    wrap.innerHTML = charts.map((c) => `<figure class="chart${c.wide ? ' wide' : ''}" style="margin:0"><h3>${esc(c.title)} <small>${esc(c.sub || '')}</small></h3><canvas id="cv-${c.id}" role="img" aria-label="${esc(c.title)}"></canvas><div class="legend">${c.legend.map(([cl, t]) => `<span><i style="background:${cl}"></i>${esc(t)}</span>`).join('')}</div></figure>`).join('');
    const pick = (p) => { if (p && p.no) jumpToPacket(p.no, st.chartConn); };
    for (const c of charts) st.charts.push(Object.assign(PA.charts.create($('#cv-' + c.id), c.spec, pick), { id: c.id, title: c.title + ' – ' + (c.sub || '') }));
    // key moments (accessible alternative)
    const fs = (st.result.conns[st.chartConn].findings || []).map((i) => st.result.findings[i]);
    const km = [];
    for (const f of fs) km.push({ t: f.t, txt: PA.i18n.text(st.lang, f).t, no: f.pkts[0], sev: f.sev });
    for (const k of S.keys.filter((k) => k.k === 'syn' || k.k === 'rst').slice(0, 6)) km.push({ t: k.t, txt: k.k === 'syn' ? 'SYN' : 'RST', no: k.no, sev: 'info' });
    km.sort((a, b) => a.t - b.t);
    $('#moments').innerHTML = `<h3>${esc(U().keyMoments)}</h3>${km.length ? '<ol>' + km.map((k) => `<li><span class="sev ${k.sev}" style="padding:0 5px">${ICON[k.sev]}</span> ${fmtT(k.t - t0)}: ${esc(k.txt)} ${k.no ? `<button type="button" class="pkt" data-pkt="${k.no}" data-pconn="${st.chartConn}">#${k.no}</button>` : ''}</li>`).join('') + '</ol>' : '<p style="color:var(--mut);margin:0">' + esc(U().none) + '</p>'}`;
  }
  function maxStep(a, stride, off) { let m = 0; for (let i = off; i < a.length; i += stride) if (a[i] > m) m = a[i]; return m; }
  function zeroPts(win) { const o = []; for (let i = 0; i < win.length; i += 4) if (win[i + 1] === 0) o.push(win[i], 0, win[i + 2], win[i + 3]); return o; }

  // ---------- report ----------
  function renderReport() {
    $('#panel-report').innerHTML = `<div class="report-grid"><div class="card"><h3>${esc(U().report)}</h3>
      <label class="check"><input type="checkbox" id="anon" ${st.anon ? 'checked' : ''}><span>${esc(U().anon)}<small>${esc(U().anonHelp)}</small></span></label>
      <div class="btn-row"><button type="button" class="btn primary" id="exp-html">${esc(U().exportHtml)}</button><button type="button" class="btn" id="exp-md">${esc(U().exportMd)}</button></div>
      <p style="color:var(--mut);font-size:.82rem;margin:12px 0 0">${st.lang === 'de' ? 'Der HTML-Report ist eine eigenständige Datei mit eigener Content Security Policy; er enthält die Diagramme der wichtigsten Verbindung als Bilder.' : 'The HTML report is a standalone file with its own Content Security Policy; it contains the charts of the most important connection as images.'}</p></div>
      <div class="card"><h3>${esc(U().ticket)}</h3><textarea class="ticket" id="ticket" readonly aria-label="${esc(U().ticket)}"></textarea><div class="btn-row" style="margin-top:8px"><button type="button" class="btn" id="copy-ticket">${esc(U().copyTicket)}</button></div></div></div>`;
    updateTicket();
  }
  function updateTicket() { const t = $('#ticket'); if (t) t.value = PA.report.ticket(st.result, st.lang, { anon: st.anon, fileName: st.fileName }); }
  function baseName() { return (st.fileName || 'capture').replace(/\.(pcapng|pcap|cap)$/i, '') + (st.anon ? '-anon' : ''); }
  async function exportHtml() {
    let charts = [];
    if (chartConns().length) {
      if (!st.charts.length) { selectTab('charts', false); await new Promise((r) => setTimeout(r, 400)); selectTab('report', false); }
      charts = st.charts.map((c) => ({ title: c.title, src: c.toDataURL() }));
    }
    const html = PA.report.html(st.result, st.lang, { anon: st.anon, fileName: st.anon ? '' : st.fileName, charts: st.anon ? [] : charts });
    download(baseName() + '-autopsy.html', html, 'text/html');
  }
  function exportMd() { download(baseName() + '-autopsy.md', PA.report.markdown(st.result, st.lang, { anon: st.anon, fileName: st.anon ? '' : st.fileName }), 'text/markdown'); }

  // ---------- thresholds ----------
  function renderThresholds() {
    const T = PA.config.T;
    $('#panel-thresholds').innerHTML = `<p style="color:var(--fg2);margin:0 0 12px">${st.lang === 'de' ? 'Alle Detektoren lesen ihre Grenzen aus einer zentralen Tabelle (src/config.js). Das Gesamturteil gewichtet Befunde nach Schwere (kritisch 3, Warnung 2, Hinweis 0) und Sicherheit (hoch 1, mittel 0,6, gering 0,3); die stärkste Ursache muss die nächste um das Doppelte übertreffen, sonst lautet das Urteil „gemischt“.' : 'All detectors read their limits from one central table (src/config.js). The verdict weights findings by severity (critical 3, warning 2, note 0) and confidence (high 1, medium 0.6, low 0.3); the strongest cause must beat the next one by a factor of two, otherwise the verdict is “mixed”.'}</p>
      <div class="tbl-wrap"><table class="th"><thead><tr><th>${esc(U().thName)}</th><th>${esc(U().thValue)}</th><th>${esc(U().thWhy)}</th></tr></thead><tbody>${Object.entries(T).map(([k, v]) => `<tr><td>${esc(k)}</td><td>${esc(n0(v.v))} ${esc(v.unit)}</td><td>${esc(st.lang === 'de' ? v.de : v.en)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  // ---------- tabs ----------
  function selectTab(name, focus) {
    for (const b of $$('#tabs [role="tab"]')) {
      const on = b.dataset.tab === name;
      b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1;
      $('#' + b.getAttribute('aria-controls')).hidden = !on;
      if (on && focus) b.focus();
    }
    if (name === 'packets') { sizeList(); drawRows(); }
    if (name === 'charts') st.charts.forEach((c) => c.redraw());
  }

  // ---------- events ----------
  function bind() {
    $('#lang-en').onclick = () => setLang('en');
    $('#lang-de').onclick = () => setLang('de');
    $('#btn-theme').onclick = () => setTheme(isDark() ? 'light' : 'dark');
    $('#btn-local').onclick = () => { const p = $('#local-pop'); p.hidden = !p.hidden; $('#btn-local').setAttribute('aria-expanded', String(!p.hidden)); };
    document.addEventListener('click', (e) => { if (!e.target.closest('#btn-local') && !e.target.closest('#local-pop')) { $('#local-pop').hidden = true; $('#btn-local').setAttribute('aria-expanded', 'false'); } });
    $('#file-input').onchange = (e) => { analyzeFile(e.target.files[0]); e.target.value = ''; };
    $('#btn-cancel').onclick = cancel;
    $('#btn-new').onclick = () => { show('intake'); $('#file-input').focus(); };
    $('#btn-error-back').onclick = () => show('intake');
    $('#brand').onclick = (e) => { e.preventDefault(); if (!$('#view-busy').hidden) return; show('intake'); };
    $('#demos').onclick = (e) => { const b = e.target.closest('[data-demo]'); if (b) analyzeDemo(b.dataset.demo); };
    // drag & drop anywhere
    let depth = 0;
    const veil = $('#drag-veil');
    const hasFiles = (e) => e.dataTransfer && Array.from(e.dataTransfer.types || []).includes('Files');
    window.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth++; veil.classList.add('on'); $('#dropzone').classList.add('over'); });
    window.addEventListener('dragover', (e) => { if (!hasFiles(e)) return; e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; });
    window.addEventListener('dragleave', () => { depth = Math.max(0, depth - 1); if (!depth) { veil.classList.remove('on'); $('#dropzone').classList.remove('over'); } });
    window.addEventListener('drop', (e) => { if (!hasFiles(e)) return; e.preventDefault(); depth = 0; veil.classList.remove('on'); $('#dropzone').classList.remove('over'); const f = e.dataTransfer.files[0]; if (f && $('#view-busy').hidden) analyzeFile(f); });
    // tabs with keyboard
    $('#tabs').addEventListener('click', (e) => { const b = e.target.closest('[role="tab"]'); if (b) selectTab(b.dataset.tab, false); });
    $('#tabs').addEventListener('keydown', (e) => {
      const tabs = $$('#tabs [role="tab"]'); const i = tabs.indexOf(document.activeElement);
      if (i < 0) return;
      let j = -1;
      if (e.key === 'ArrowRight') j = (i + 1) % tabs.length; else if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length; else if (e.key === 'Home') j = 0; else if (e.key === 'End') j = tabs.length - 1;
      if (j >= 0) { e.preventDefault(); selectTab(tabs[j].dataset.tab, true); }
    });
    // delegated result actions
    $('#view-result').addEventListener('click', (e) => {
      const t = e.target.closest('button, a, tr');
      if (!t) return;
      if (t.dataset.copy !== undefined) return copy(t.dataset.copy);
      if (t.dataset.pkt) return jumpToPacket(+t.dataset.pkt, t.dataset.pconn);
      if (t.dataset.conn !== undefined && t.tagName === 'BUTTON') { st.conn = +t.dataset.conn; renderConns(); selectTab('conns', false); return; }
      if (t.dataset.sort) { st.sortConn = t.dataset.sort; renderConns(); return; }
      if (t.dataset.showpk !== undefined) { st.pkConn = +t.dataset.showpk; renderPacketsShell(); selectTab('packets', false); return; }
      if (t.dataset.showch !== undefined) { st.chartConn = +t.dataset.showch; st.chartDir = null; renderCharts(); selectTab('charts', false); return; }
      if (t.dataset.gof !== undefined) { e.preventDefault(); selectTab('findings', false); const el = revealFinding(Number(t.dataset.gof)); if (el) { const nd = el.closest('details.notes'); if (nd) nd.open = true; el.scrollIntoView({ block: 'center' }); el.classList.add('sel'); setTimeout(() => el.classList.remove('sel'), 1800); } return; }
      if (t.dataset.dir !== undefined) { st.chartDir = +t.dataset.dir; renderCharts(); return; }
      if (t.id === 'pk-all') { st.pkConn = null; renderPacketsShell(); return; }
      if (t.id === 'exp-html') return exportHtml();
      if (t.id === 'exp-md') return exportMd();
      if (t.id === 'copy-ticket') return copy($('#ticket').value);
      if (t.tagName === 'TR' && t.dataset.c !== undefined) { st.conn = +t.dataset.c; renderConns(); const d = $('.conn-detail'); if (d) d.scrollIntoView({ block: 'nearest' }); }
    });
    $('#view-result').addEventListener('keydown', (e) => { const tr = e.target.closest('tr[data-c]'); if (tr && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); tr.click(); } });
    $('#view-result').addEventListener('change', (e) => {
      if (e.target.id === 'anon') { st.anon = e.target.checked; updateTicket(); }
      if (e.target.id === 'ch-conn') { st.chartConn = +e.target.value; st.chartDir = null; renderCharts(); }
    });
    $('#pk-list').addEventListener('scroll', drawRows, { passive: true });
    $('#pk-list').addEventListener('keydown', (e) => {
      const l = $('#pk-list'), h = ROWH();
      const map = { ArrowDown: h, ArrowUp: -h, PageDown: l.clientHeight, PageUp: -l.clientHeight };
      if (map[e.key] !== undefined) { e.preventDefault(); l.scrollTop += map[e.key]; }
      if (e.key === 'Home') { e.preventDefault(); l.scrollTop = 0; } if (e.key === 'End') { e.preventDefault(); l.scrollTop = l.scrollHeight; }
    });
    window.addEventListener('resize', () => { if (!$('#panel-packets').hidden) { sizeList(); drawRows(); } });
  }

  function init() {
    try { const t = localStorage.getItem('pa-theme'); if (t) document.documentElement.dataset.theme = t; const l = localStorage.getItem('pa-lang'); if (l === 'de' || l === 'en') st.lang = l; } catch (e) { /* ignore */ }
    if (!localStorageLang() && /^de\b/i.test(navigator.language || '')) st.lang = 'de';
    $('#ver').textContent = PA.config.version;
    bind();
    applyLang();
    show('intake');
    // test hook (no side effects): lets automated tests read the current result
    window.__paState = st;
  }
  function localStorageLang() { try { return localStorage.getItem('pa-lang'); } catch (e) { return null; } }
  init();
})();
