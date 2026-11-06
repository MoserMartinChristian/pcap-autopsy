/*
 * PCAP Autopsy – report export (HTML, Markdown, ticket text) and consistent anonymisation.
 * Pure string functions, testable in Node.
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  const esc = (s) => String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  /*
   * Anonymiser: every IPv4/IPv6 address, MAC address and host name (DNS names, SNI, HTTP Host)
   * is replaced by a stable placeholder. The mapping is built from the capture's own lists, in order
   * of first appearance, so the same value always gets the same placeholder in every export.
   */
  function createAnonymizer(anon) {
    const map = new Map();
    const cnt = { ip: 0, ip6: 0, mac: 0, host: 0 };
    const ph = (kind, v) => { const k = kind + '|' + v.toLowerCase(); if (!map.has(k)) map.set(k, '[' + kind + '-' + (++cnt[kind]) + ']'); return map.get(k); };
    const addrs = (anon && anon.addrs) || [];
    for (const a of addrs) ph(a.includes(':') ? 'ip6' : 'ip', a);
    for (const m of (anon && anon.macs) || []) ph('mac', m);
    const names = Array.from(new Set(((anon && anon.names) || []).filter((n) => n && n.length > 2 && /[a-z]/i.test(n)).map((n) => n.toLowerCase())));
    names.sort((a, b) => b.length - a.length);
    for (const n of names) ph('host', n);
    const v6 = addrs.filter((a) => a.includes(':')).sort((a, b) => b.length - a.length);
    const nameRe = names.length ? new RegExp('(^|[^a-z0-9.-])(' + names.map(reEsc).join('|') + ')(?![a-z0-9-])', 'gi') : null;
    const v6Re = v6.length ? new RegExp('(^|[^0-9a-f:])(' + v6.map(reEsc).join('|') + ')(?![0-9a-f:])', 'gi') : null;
    const v4Re = /(^|[^\d.])((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})(?![\d.])/g;
    const macRe = /(^|[^0-9a-f:])([0-9a-f]{2}(?::[0-9a-f]{2}){5})(?![0-9a-f:])/gi;
    // generic IPv6 (addresses that only appear in text): 8 groups, or fewer with exactly one '::'
    const v6Gen = /(^|[^0-9a-z:.])([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?![0-9a-z:])/gi;
    const isV6 = (a) => { const dbl = a.split('::').length - 1; const g = a.split(':').filter((x) => x !== '').length; return /[0-9a-f]/i.test(a) && (dbl === 0 ? g === 8 && !/(^|:)(:|$)/.test(a) : dbl === 1 && g <= 7); };
    function apply(s) {
      if (s === null || s === undefined) return s;
      s = String(s);
      if (nameRe) s = s.replace(nameRe, (m, pre, n) => pre + ph('host', n));
      if (macRe) s = s.replace(macRe, (m, pre, mac) => pre + ph('mac', mac));
      if (v6Re) s = s.replace(v6Re, (m, pre, a) => pre + ph('ip6', a));
      s = s.replace(v6Gen, (m, pre, a) => (isV6(a) ? pre + ph('ip6', a) : m));
      s = s.replace(v4Re, (m, pre, a) => pre + ph('ip', a));
      return s;
    }
    return { apply, map };
  }

  function L(lang) { return lang === 'de' ? PA.i18n.de : PA.i18n.en; }
  function fmtDur(s, lang) { const n0 = PA.i18n.n0; return s >= 1 ? n0(s, lang) + ' s' : n0(s * 1000, lang) + ' ms'; }
  function connLabel(c) { if (!c) return ''; const v6 = c.l3 === 6; const a = v6 ? '[' + c.client + ']' : c.client; const b = v6 ? '[' + c.server + ']' : c.server; return a + ':' + c.cport + ' → ' + b + ':' + c.sport + (c.sni ? ' (' + c.sni + ')' : c.host ? ' (' + c.host + ')' : ''); }
  function metricsList(f, lang) {
    return PA.i18n.metrics(lang, f).map((x) => x.label + ' ' + x.value).join(', ');
  }

  // Groups repeated findings (same id on many connections): the first `keep` stay, the rest are summarised.
  // Input and output items are [finding, index]; groups keep the order of first appearance.
  function groupFindings(items, keep) {
    keep = keep || 3;
    const by = new Map();
    for (const it of items) { const k = it[0].id; if (!by.has(k)) by.set(k, []); by.get(k).push(it); }
    return [...by.values()].map((g) => ({ shown: g.slice(0, keep), rest: g.slice(keep) }));
  }
  function model(result, lang, opts) {
    opts = opts || {};
    const T = L(lang);
    const v = result.verdict;
    const fin = result.findings.filter((f) => f.sev !== 'info');
    const notes = result.findings.filter((f) => f.sev === 'info');
    const gFin = groupFindings(fin.map((f, i) => [f, i]));
    const gNotes = groupFindings(notes.map((f, i) => [f, i]));
    return { T, v, fin, notes, gFin, gNotes, conns: result.conns, point: result.point, sum: result.summary, file: opts.fileName || '', lang };
  }

  function markdown(result, lang, opts) {
    opts = opts || {};
    const M = model(result, lang, opts);
    const T = M.T, U = T.ui, n0 = PA.i18n.n0;
    const lines = [];
    lines.push('# PCAP Autopsy – ' + (M.file || 'capture'));
    lines.push('');
    lines.push('## ' + U.verdictLabel + ': ' + T.verdict[M.v.v]);
    lines.push('');
    lines.push(T.verdictSub[M.v.v] + ' (' + U.confidence + ': ' + T.confShort[M.v.conf] + ')');
    if (M.v.missing.length) { lines.push(''); for (const k of M.v.missing) lines.push('- ' + T.missing[k]); }
    if (M.v.second.length) { lines.push(''); lines.push('**' + U.secondCap + ':**'); for (const k of M.v.second) lines.push('- ' + T.second[k]); }
    lines.push('');
    lines.push('**' + U.pointLabel + ':** ' + T.point[M.point.pos] + ' (' + T.conf[M.point.conf] + '). ' + T.point.expl(M.point));
    lines.push('');
    lines.push('## ' + U.summary);
    lines.push('');
    lines.push('| | |\n|---|---|');
    lines.push('| ' + U.packetsTab + ' | ' + n0(M.sum.packets, lang) + ' |');
    lines.push('| ' + U.duration + ' | ' + fmtDur(M.sum.duration, lang) + ' |');
    lines.push('| ' + U.format + ' | ' + M.sum.format + ' |');
    lines.push('| ' + U.link + ' | ' + M.sum.linktypes.map((l) => l.name).join(', ') + ' |');
    lines.push('| ' + U.tcpConns + ' | ' + M.sum.tcpConns + ' |');
    lines.push('| ' + U.udpFlows + ' | ' + M.sum.udpFlows + ' |');
    lines.push('| ' + U.dnsQ + ' | ' + M.sum.dnsQueries + ' |');
    lines.push('');
    const block = (f) => {
      const tx = PA.i18n.text(lang, f);
      const c = f.conn !== undefined ? M.conns[f.conn] : null;
      lines.push('### ' + (f.sev === 'critical' ? '🔴 ' : f.sev === 'warning' ? '🟠 ' : 'ℹ️ ') + T.sev[f.sev] + ': ' + tx.t);
      lines.push('');
      lines.push('*' + U.cat + ': ' + T.cat[f.cat] + ' · ' + U.side + ': ' + T.Side[f.side] + ' · ' + U.confidence + ': ' + T.confShort[f.conf] + (c ? ' · ' + U.conn + ': ' + connLabel(c) : '') + '*');
      lines.push('');
      lines.push(tx.d);
      lines.push('');
      if (f.pkts && f.pkts.length) lines.push('- **' + U.evidence + ':** ' + U.packetsTab + ' ' + f.pkts.slice(0, 25).join(', ') + (f.pkts.length > 25 ? ' …' : ''));
      const ml = metricsList(f, lang); if (ml) lines.push('- **' + U.measured + ':** ' + ml);
      lines.push('- **' + U.nextStep + ':** ' + tx.n);
      if (f.filter) lines.push('- **' + U.filter + ':** `' + f.filter + '`');
      lines.push('');
    };
    lines.push('## ' + U.findings + ' (' + M.fin.length + ')');
    lines.push('');
    if (!M.fin.length) { lines.push(U.noFindings); lines.push(''); }
    const restLabel = (x) => (x[0].conn !== undefined && M.conns[x[0].conn] ? connLabel(M.conns[x[0].conn]) : '#' + (x[0].pkts || [])[0]);
    const groupsMd = (gs) => gs.forEach((g) => { g.shown.forEach((x) => block(x[0])); if (g.rest.length) { lines.push('*' + U.moreSame(g.rest.length) + ': ' + g.rest.slice(0, 20).map(restLabel).join('; ') + (g.rest.length > 20 ? ' …' : '') + '*'); lines.push(''); } });
    groupsMd(M.gFin);
    if (M.notes.length) { lines.push('## ' + U.notes); lines.push(''); groupsMd(M.gNotes); }
    lines.push('## ' + U.connections);
    lines.push('');
    lines.push('| # | ' + U.conn + ' | ' + U.app + ' | ' + U.pk + ' | ' + U.rtt + ' | ' + U.retr + ' | ' + U.state + ' |\n|---|---|---|---|---|---|---|');
    const SEVR = { critical: 0, warning: 1, info: 2, ok: 3 };
    M.conns.slice().sort((a, b) => SEVR[a.sev] - SEVR[b.sev] || b.bytes - a.bytes).slice(0, 50).forEach((c) => {
      lines.push('| ' + c.id + ' | ' + connLabel(c) + ' (' + c.proto.toUpperCase() + ') | ' + c.app + ' | ' + c.pkts + ' | ' + (c.rtt !== null ? n0(c.rtt, lang) + ' ms' : '–') + ' | ' + c.retrans + ' | ' + (c.sev === 'ok' ? 'OK' : T.sev[c.sev]) + ' |');
    });
    lines.push('');
    lines.push('## ' + U.checks);
    lines.push('');
    lines.push(M.v.checks.map((k) => U.checkNames[k]).join(', '));
    lines.push('');
    lines.push('---');
    lines.push('PCAP Autopsy ' + PA.config.version + ' · ' + (lang === 'de' ? 'lokal im Browser erstellt, keine Daten übertragen' : 'generated locally in the browser, no data transmitted') + (opts.anon ? ' · ' + (lang === 'de' ? 'anonymisiert' : 'anonymised') : ''));
    let md = lines.join('\n') + '\n';
    if (opts.anon) md = createAnonymizer(result.anon).apply(md);
    return md;
  }

  function ticket(result, lang, opts) {
    opts = opts || {};
    const M = model(result, lang, opts);
    const T = M.T, U = T.ui;
    const out = [];
    out.push('PCAP Autopsy: ' + T.verdict[M.v.v] + ' (' + U.confidence + ': ' + T.confShort[M.v.conf] + ')' + (M.file ? ' – ' + M.file : ''));
    out.push(U.pointLabel + ': ' + T.point[M.point.pos] + '. ' + U.packetsTab + ': ' + M.sum.packets + ', ' + U.duration + ': ' + fmtDur(M.sum.duration, lang) + '.');
    const top = M.fin.slice(0, 5);
    if (!top.length) out.push('- ' + U.noFindings);
    for (const f of top) {
      const tx = PA.i18n.text(lang, f);
      const c = f.conn !== undefined ? M.conns[f.conn] : null;
      out.push('- [' + T.sev[f.sev] + '] ' + tx.t + (c ? ' – ' + connLabel(c) : '') + (f.pkts && f.pkts.length ? ' (' + U.packetsTab + ' ' + f.pkts.slice(0, 6).join(', ') + ')' : ''));
    }
    if (M.fin.length > 5) out.push('- … +' + (M.fin.length - 5) + ' ' + U.more);
    if (top[0]) out.push(U.nextStep + ': ' + PA.i18n.text(lang, top[0]).n);
    if (M.v.missing.length && (M.v.v === 'inconclusive' || M.v.v === 'clean')) out.push(M.v.missing.map((k) => T.missing[k]).join(' '));
    if (M.v.second.length) out.push(U.secondCap + ': ' + T.second[M.v.second[0]]);
    let s = out.join('\n');
    if (opts.anon) s = createAnonymizer(result.anon).apply(s);
    return s;
  }

  const REPORT_CSS = `:root{--bg:#f6f7f9;--card:#fff;--fg:#14181f;--mut:#566070;--line:#d9dee6;--crit:#b3261e;--warn:#9a5b00;--info:#2457a6;--ok:#1d7a46;--code:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#0f1217;--card:#171b22;--fg:#e7eaf0;--mut:#9aa3b2;--line:#2a313c;--crit:#ff7b72;--warn:#f0b35a;--info:#7fb0ff;--ok:#5fd394;--code:#202631}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:980px;margin:0 auto;padding:24px 16px 60px}h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 10px;border-bottom:1px solid var(--line);padding-bottom:6px}
.v{background:var(--card);border:1px solid var(--line);border-left:6px solid var(--mut);border-radius:10px;padding:16px 18px;margin:16px 0}.v.network{border-left-color:var(--crit)}.v.server,.v.client{border-left-color:var(--warn)}.v.mixed{border-left-color:var(--warn)}.v.clean{border-left-color:var(--ok)}
.v b{font-size:1.35rem;display:block}.mut{color:var(--mut)}.f{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px;margin:12px 0}
.f h3{margin:0 0 6px;font-size:1rem}.tag{display:inline-block;font-size:.75rem;font-weight:600;padding:1px 8px;border-radius:99px;border:1px solid currentColor;margin-right:6px}
.critical{color:var(--crit)}.warning{color:var(--warn)}.info{color:var(--info)}code{background:var(--code);padding:1px 5px;border-radius:4px;font:13px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;word-break:break-all}
dl{display:grid;grid-template-columns:max-content 1fr;gap:4px 12px;margin:8px 0 0}dt{color:var(--mut)}dd{margin:0}table{border-collapse:collapse;width:100%;font-size:.88rem}td,th{border-bottom:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
.wrap{overflow-x:auto}img{max-width:100%;height:auto;border:1px solid var(--line);border-radius:8px;background:var(--card)}footer{margin-top:40px;color:var(--mut);font-size:.85rem}
@media (max-width:600px){dl{grid-template-columns:1fr}dt{margin-top:6px}}`;

  function html(result, lang, opts) {
    opts = opts || {};
    const M = model(result, lang, opts);
    const T = M.T, U = T.ui, n0 = PA.i18n.n0;
    const A = opts.anon ? createAnonymizer(result.anon).apply : (s) => s;
    const e = (s) => esc(A(s));
    const h = [];
    h.push('<!doctype html><html lang="' + (lang === 'de' ? 'de' : 'en') + '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">');
    h.push('<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'; img-src data:">');
    h.push('<title>' + e('PCAP Autopsy – ' + (M.file || 'report')) + '</title><style>' + REPORT_CSS + '</style></head><body><main>');
    h.push('<h1>PCAP Autopsy</h1><div class="mut">' + e(M.file) + '</div>');
    h.push('<div class="v ' + M.v.v + '"><span class="mut">' + esc(U.verdictLabel) + '</span><b>' + esc(T.verdict[M.v.v]) + '</b><div>' + esc(T.verdictSub[M.v.v]) + '</div>');
    h.push('<div class="mut">' + esc(U.confidence) + ': ' + esc(T.confShort[M.v.conf]) + '</div>');
    if (M.v.missing.length) h.push('<ul>' + M.v.missing.map((k) => '<li>' + esc(T.missing[k]) + '</li>').join('') + '</ul>');
    if (M.v.second.length) h.push('<p><b style="font-size:1rem;display:inline">' + esc(U.secondCap) + ':</b> ' + M.v.second.map((k) => esc(T.second[k])).join(' ') + '</p>');
    h.push('</div>');
    h.push('<p><b>' + esc(U.pointLabel) + ':</b> ' + esc(T.point[M.point.pos]) + ' (' + esc(T.conf[M.point.conf]) + '). ' + e(T.point.expl(M.point)) + ' <span class="mut">' + esc(T.point.why) + '</span></p>');
    h.push('<h2>' + esc(U.summary) + '</h2><dl>');
    const row = (k, v) => h.push('<dt>' + esc(k) + '</dt><dd>' + e(v) + '</dd>');
    row(U.packetsTab, n0(M.sum.packets, lang)); row(U.duration, fmtDur(M.sum.duration, lang)); row(U.format, M.sum.format); row(U.link, M.sum.linktypes.map((l) => l.name).join(', '));
    row(U.tcpConns, M.sum.tcpConns); row(U.udpFlows, M.sum.udpFlows); row(U.dnsQ, M.sum.dnsQueries);
    h.push('</dl>');
    if (opts.charts && opts.charts.length) {
      h.push('<h2>' + esc(U.charts) + '</h2>');
      for (const c of opts.charts) h.push('<figure style="margin:12px 0"><img alt="' + e(c.title) + '" src="' + c.src + '"><figcaption class="mut">' + e(c.title) + '</figcaption></figure>');
    }
    const block = (f) => {
      const tx = PA.i18n.text(lang, f);
      const c = f.conn !== undefined ? M.conns[f.conn] : null;
      h.push('<div class="f"><h3><span class="tag ' + f.sev + '">' + (f.sev === 'critical' ? '■ ' : f.sev === 'warning' ? '▲ ' : '● ') + esc(T.sev[f.sev]) + '</span>' + e(tx.t) + '</h3>');
      h.push('<div class="mut">' + esc(U.cat) + ': ' + esc(T.cat[f.cat]) + ' · ' + esc(U.side) + ': ' + esc(T.Side[f.side]) + ' · ' + esc(U.confidence) + ': ' + esc(T.confShort[f.conf]) + (c ? ' · ' + e(connLabel(c)) : '') + '</div>');
      h.push('<p>' + e(tx.d) + '</p><dl>');
      if (f.pkts && f.pkts.length) h.push('<dt>' + esc(U.evidence) + '</dt><dd>' + esc(U.packetsTab) + ' ' + f.pkts.slice(0, 30).join(', ') + (f.pkts.length > 30 ? ' …' : '') + '</dd>');
      const ml = metricsList(f, lang); if (ml) h.push('<dt>' + esc(U.measured) + '</dt><dd>' + e(ml) + '</dd>');
      h.push('<dt>' + esc(U.nextStep) + '</dt><dd>' + e(tx.n) + '</dd>');
      if (f.filter) h.push('<dt>' + esc(U.filter) + '</dt><dd><code>' + e(f.filter) + '</code></dd>');
      h.push('</dl></div>');
    };
    h.push('<h2>' + esc(U.findings) + ' (' + M.fin.length + ')</h2>');
    if (!M.fin.length) h.push('<p>' + esc(U.noFindings) + '</p>');
    const restLabel = (x) => (x[0].conn !== undefined && M.conns[x[0].conn] ? connLabel(M.conns[x[0].conn]) : '#' + (x[0].pkts || [])[0]);
    const groupsHtml = (gs) => gs.forEach((g) => { g.shown.forEach((x) => block(x[0])); if (g.rest.length) h.push('<p class="mut">' + esc(U.moreSame(g.rest.length)) + ': ' + e(g.rest.slice(0, 20).map(restLabel).join('; ')) + (g.rest.length > 20 ? ' …' : '') + '</p>'); });
    groupsHtml(M.gFin);
    if (M.notes.length) { h.push('<h2>' + esc(U.notes) + '</h2>'); groupsHtml(M.gNotes); }
    h.push('<h2>' + esc(U.connections) + '</h2><div class="wrap"><table><thead><tr><th>#</th><th>' + esc(U.conn) + '</th><th>' + esc(U.app) + '</th><th>' + esc(U.pk) + '</th><th>' + esc(U.rtt) + '</th><th>' + esc(U.retr) + '</th><th>' + esc(U.state) + '</th></tr></thead><tbody>');
    const SEVR = { critical: 0, warning: 1, info: 2, ok: 3 };
    M.conns.slice().sort((a, b) => SEVR[a.sev] - SEVR[b.sev] || b.bytes - a.bytes).slice(0, 100).forEach((c) => {
      h.push('<tr><td>' + c.id + '</td><td>' + e(connLabel(c)) + ' <span class="mut">' + c.proto.toUpperCase() + '</span></td><td>' + e(c.app) + '</td><td>' + c.pkts + '</td><td>' + (c.rtt !== null ? n0(c.rtt, lang) + ' ms' : '–') + '</td><td>' + c.retrans + '</td><td class="' + (c.sev === 'ok' ? '' : c.sev) + '">' + esc(c.sev === 'ok' ? 'OK' : T.sev[c.sev]) + '</td></tr>');
    });
    h.push('</tbody></table></div>');
    h.push('<footer>PCAP Autopsy ' + esc(PA.config.version) + ' · ' + esc(lang === 'de' ? 'lokal im Browser erstellt, keine Daten übertragen' : 'generated locally in the browser, no data transmitted') + (opts.anon ? ' · ' + esc(lang === 'de' ? 'anonymisiert' : 'anonymised') : '') + ' · ' + esc(U.checks) + ': ' + esc(M.v.checks.map((k) => U.checkNames[k]).join(', ')) + '</footer>');
    h.push('</main></body></html>');
    return h.join('\n');
  }

  PA.report = { groupFindings, createAnonymizer, markdown, html, ticket, esc, connLabel };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.report;
})(typeof globalThis !== 'undefined' ? globalThis : self);
