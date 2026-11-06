/*
 * PCAP Autopsy – Web Worker. Runs parser and analysis off the main thread.
 * Built into a Blob together with the core modules; never touches the network.
 */
(function () {
  'use strict';
  const PA = self.PA;
  let pipe = null, result = null, store = null;
  const idxCache = new Map();
  const CHUNK = 8 * 1024 * 1024;

  function post(m) { self.postMessage(m); }
  function fail(e) {
    if (e && e.code && String(e.code).startsWith('err.')) post({ type: 'error', code: e.code, params: e.params || {} });
    else if (e instanceof RangeError || /memory|allocation/i.test(String(e && e.message))) post({ type: 'error', code: 'err.memory', params: { msg: String(e && e.message || e) } });
    else post({ type: 'error', code: 'err.internal', params: { msg: String(e && e.message || e) } });
  }
  function publicResult(r) {
    const out = Object.assign({}, r);
    delete out.store;
    out.connTotal = r.conns.length;
    if (r.conns.length > 5000) {
      const SEVR = { critical: 0, warning: 1, info: 2, ok: 3 };
      const keep = new Set(r.conns.slice().sort((a, b) => SEVR[a.sev] - SEVR[b.sev] || b.bytes - a.bytes).slice(0, 5000).map((c) => c.id));
      for (const f of r.findings) if (f.conn !== undefined) keep.add(f.conn);
      out.conns = r.conns.map((c) => (keep.has(c.id) ? c : { id: c.id, stub: true, proto: c.proto, client: c.client, server: c.server, cport: c.cport, sport: c.sport, l3: c.l3, sev: c.sev, pkts: c.pkts, bytes: c.bytes, app: c.app, rtt: c.rtt, retrans: c.retrans, start: c.start, end: c.end, findings: [] }));
    }
    if (out.anon.addrs.length > 50000) out.anon = Object.assign({}, out.anon, { addrs: out.anon.addrs.slice(0, 50000) });
    return out;
  }
  async function runFile(file) {
    pipe = PA.pipeline.createPipeline();
    const total = file.size;
    let off = 0, lastPost = 0;
    post({ type: 'progress', done: 0, total, packets: 0, phase: 'read' });
    while (off < total) {
      const end = Math.min(total, off + CHUNK);
      const buf = new Uint8Array(await file.slice(off, end).arrayBuffer());
      pipe.push(buf);
      off = end;
      const now = Date.now();
      if (now - lastPost > 80 || off === total) { post({ type: 'progress', done: off, total, packets: pipe.store.S.n, phase: 'read' }); lastPost = now; }
    }
    finish();
  }
  function runBytes(bytes) {
    pipe = PA.pipeline.createPipeline();
    const total = bytes.length;
    const n = 1 << 20;
    for (let o = 0; o < total; o += n) {
      pipe.push(bytes.subarray(o, Math.min(total, o + n)));
      post({ type: 'progress', done: Math.min(total, o + n), total, packets: pipe.store.S.n, phase: 'read' });
    }
    finish();
  }
  function finish() {
    post({ type: 'progress', done: 1, total: 1, packets: pipe.store.S.n, phase: 'analyse' });
    const t0 = Date.now();
    result = pipe.finish();
    store = pipe.store;
    result.analysisMs = Date.now() - t0;
    idxCache.clear();
    post({ type: 'result', result: publicResult(result) });
  }
  function index(conn) {
    if (conn === null || conn === undefined || conn < 0) return null;
    if (!idxCache.has(conn)) idxCache.set(conn, PA.analyze.packetIndex(store.S, conn));
    return idxCache.get(conn);
  }
  self.onmessage = async (ev) => {
    const m = ev.data;
    try {
      if (m.type === 'file') await runFile(m.file);
      else if (m.type === 'demo') { const b = PA.scenarios.build(m.id); post({ type: 'demoBytes', size: b.bytes.length }); runBytes(b.bytes); }
      else if (m.type === 'bytes') runBytes(new Uint8Array(m.buffer));
      else if (m.type === 'rows') {
        if (!store) return;
        const S = store.S;
        const idx = index(m.conn);
        const total = idx ? idx.length : S.n;
        const rows = [];
        for (let k = m.from; k < Math.min(total, m.from + m.count); k++) rows.push(PA.analyze.rowOf(S, idx ? idx[k] : k));
        post({ type: 'rows', reqId: m.reqId, rows, total, from: m.from, conn: m.conn });
      } else if (m.type === 'locate') {
        // position of packet number in the current list
        const idx = index(m.conn);
        let pos = m.no - 1;
        if (idx) { pos = -1; let lo = 0, hi = idx.length - 1; while (lo <= hi) { const mid = (lo + hi) >> 1; if (idx[mid] === m.no - 1) { pos = mid; break; } if (idx[mid] < m.no - 1) lo = mid + 1; else hi = mid - 1; } }
        post({ type: 'locate', reqId: m.reqId, pos, conn: m.conn });
      } else if (m.type === 'series') {
        post({ type: 'series', reqId: m.reqId, series: PA.analyze.series(store.S, m.conn) });
      }
    } catch (e) { fail(e); }
  };
})();
