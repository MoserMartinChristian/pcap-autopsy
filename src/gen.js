/*
 * PCAP Autopsy – synthetic capture generator.
 * Builds pcap / pcapng files from scripted and simulated traffic. No real data is used.
 * Every scenario returns the bytes plus a "truth" record of what was deliberately built in,
 * so the tests can check the analysis against it. The UI uses the same scenarios as demos.
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  const F = { FIN: 1, SYN: 2, RST: 4, PSH: 8, ACK: 16 };

  // ---------- deterministic PRNG ----------
  function rng(seed) {
    let s = seed >>> 0 || 1;
    return () => { s ^= s << 13; s >>>= 0; s ^= s >>> 17; s ^= s << 5; s >>>= 0; return s / 4294967296; };
  }

  // ---------- byte helpers ----------
  function parseIp(a) {
    if (a.includes(':')) {
      const [h, t] = a.split('::');
      const hs = h ? h.split(':') : [], ts = t !== undefined ? (t ? t.split(':') : []) : [];
      const words = t !== undefined ? hs.concat(new Array(8 - hs.length - ts.length).fill('0'), ts) : hs;
      const b = new Uint8Array(16);
      words.forEach((w, i) => { const v = parseInt(w, 16); b[2 * i] = v >> 8; b[2 * i + 1] = v & 255; });
      return b;
    }
    return Uint8Array.from(a.split('.').map(Number));
  }
  function csum(bufs, init) {
    let s = init || 0;
    for (const b of bufs) {
      let i = 0;
      for (; i + 1 < b.length; i += 2) s += (b[i] << 8) | b[i + 1];
      if (i < b.length) s += b[i] << 8;
    }
    while (s > 0xffff) s = (s & 0xffff) + (s >>> 16);
    return (~s) & 0xffff;
  }
  const w16 = (b, o, v) => { b[o] = (v >> 8) & 255; b[o + 1] = v & 255; };
  const w32 = (b, o, v) => { b[o] = (v >>> 24) & 255; b[o + 1] = (v >>> 16) & 255; b[o + 2] = (v >>> 8) & 255; b[o + 3] = v & 255; };

  function tcpBytes(f, src, dst, l3) {
    const opts = [];
    const o = f.opts || {};
    if (o.mss) opts.push(2, 4, o.mss >> 8, o.mss & 255);
    if (o.sackOk) opts.push(4, 2);
    if (o.ts) { opts.push(8, 10); for (const v of o.ts) opts.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); }
    if (o.ws !== undefined) opts.push(1, 3, 3, o.ws);
    if (o.sack && o.sack.length) {
      opts.push(1, 1, 5, 2 + 8 * o.sack.length);
      for (const [l, r] of o.sack) for (const v of [l, r]) opts.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255);
    }
    while (opts.length % 4) opts.push(0);
    const hl = 20 + opts.length;
    const len = f.len || 0;
    const b = new Uint8Array(hl + len);
    w16(b, 0, f.sport); w16(b, 2, f.dport); w32(b, 4, f.seq >>> 0); w32(b, 8, f.ack >>> 0);
    b[12] = (hl / 4) << 4; b[13] = f.flags; w16(b, 14, Math.max(0, Math.min(65535, f.win | 0)));
    b.set(opts, 20);
    if (f.payload) b.set(f.payload.subarray(0, len), hl);
    const ph = pseudo(src, dst, 6, b.length, l3);
    let c = csum([ph, b]);
    if (f.badCsum) c = (c ^ 0x5a5a) & 0xffff;
    w16(b, 16, c);
    return b;
  }
  function pseudo(src, dst, proto, len, l3) {
    if (l3 === 4) { const p = new Uint8Array(12); p.set(src, 0); p.set(dst, 4); p[9] = proto; w16(p, 10, len); return p; }
    const p = new Uint8Array(40); p.set(src, 0); p.set(dst, 16); w32(p, 32, len); p[39] = proto; return p;
  }
  function udpBytes(sport, dport, payload, src, dst, l3, bad) {
    const b = new Uint8Array(8 + payload.length);
    w16(b, 0, sport); w16(b, 2, dport); w16(b, 4, b.length); b.set(payload, 8);
    let c = csum([pseudo(src, dst, 17, b.length, l3), b]);
    if (c === 0) c = 0xffff;
    if (bad) c = (c ^ 0x5a5a) & 0xffff;
    w16(b, 6, c);
    return b;
  }
  function ipBytes(l3, src, dst, proto, payload, o) {
    o = o || {};
    if (l3 === 4) {
      const b = new Uint8Array(20 + payload.length);
      b[0] = 0x45; w16(b, 2, b.length); w16(b, 4, o.id || 0);
      let ff = (o.df ? 0x4000 : 0) | (o.mf ? 0x2000 : 0) | ((o.fragOff || 0) >> 3);
      w16(b, 6, ff); b[8] = o.ttl || 64; b[9] = proto; b.set(src, 12); b.set(dst, 16);
      w16(b, 10, csum([b.subarray(0, 20)]));
      b.set(payload, 20);
      return b;
    }
    const ext = o.frag6 ? 8 : 0;
    const b = new Uint8Array(40 + ext + payload.length);
    b[0] = 0x60; w16(b, 4, ext + payload.length); b[6] = o.frag6 ? 44 : proto; b[7] = o.ttl || 64;
    b.set(src, 8); b.set(dst, 24);
    if (o.frag6) { b[40] = proto; w16(b, 42, (o.fragOff || 0) | (o.mf ? 1 : 0)); w32(b, 44, o.frag6); }
    b.set(payload, 40 + ext);
    return b;
  }

  // ---------- capture container ----------
  class Capture {
    constructor(opts) {
      this.o = Object.assign({ link: 'eth', format: 'pcap', snaplen: 262144, startEpoch: 1767000000 }, opts || {});
      this.frames = [];
      this.macs = {};
      this.macN = 1;
      this.rnd = rng(this.o.seed || 7);
    }
    macOf(ip) {
      if (!this.macs[ip]) { const n = this.macN++; this.macs[ip] = [0x02, 0x00, 0x5e, 0x10, (n >> 8) & 255, n & 255]; }
      return this.macs[ip];
    }
    // l3 packet bytes, at capture time t
    add(t, l3bytes, meta) {
      const fr = Object.assign({ t, bytes: l3bytes, no: 0 }, meta || {});
      this.frames.push(fr);
      return fr;
    }
    l2(fr) {
      const p = fr.bytes, ver = p[0] >> 4, et = ver === 6 ? 0x86dd : 0x0800;
      const link = this.o.link;
      if (link === 'raw') return p;
      if (link === 'null') { const b = new Uint8Array(4 + p.length); const fam = ver === 6 ? 30 : 2; b[0] = fam; b.set(p, 4); return b; }
      if (link === 'sll') {
        const b = new Uint8Array(16 + p.length); w16(b, 0, fr.out ? 4 : 0); w16(b, 2, 1); w16(b, 4, 6); b.set(this.macOf(fr.src || '0'), 6); w16(b, 14, et); b.set(p, 16); return b;
      }
      if (link === 'sll2') {
        const b = new Uint8Array(20 + p.length); w16(b, 0, et); w32(b, 4, 2); w16(b, 8, 1); b[10] = fr.out ? 4 : 0; b[11] = 6; b.set(this.macOf(fr.src || '0'), 12); b.set(p, 20); return b;
      }
      const tags = link === 'vlan' ? [[0x8100, 100]] : link === 'qinq' ? [[0x88a8, 200], [0x8100, 100]] : [];
      const hl = 14 + 4 * tags.length;
      const total = Math.max(hl + p.length, 60);
      const b = new Uint8Array(total);
      b.set(this.macOf(fr.dst || '0'), 0); b.set(this.macOf(fr.src || '0'), 6);
      let o = 12;
      for (const [tp, id] of tags) { w16(b, o, tp); w16(b, o + 2, id); o += 4; }
      w16(b, o, et); b.set(p, o + 2);
      return b;
    }
    linktype() { return { eth: 1, vlan: 1, qinq: 1, raw: 101, null: 0, sll: 113, sll2: 276 }[this.o.link]; }
    // sort by time and number the frames
    finalize() {
      this.frames.forEach((f, i) => { f._i = i; });
      this.frames.sort((a, b) => a.t - b.t || a._i - b._i);
      this.frames.forEach((f, i) => { f.no = i + 1; });
      return this;
    }
    bytes() {
      this.finalize();
      const fmt = this.o.format, lt = this.linktype(), snap = this.o.snaplen;
      const parts = [];
      let total = 0;
      const push = (b) => { parts.push(b); total += b.length; };
      const be = fmt === 'pcap-be-ns';
      const ns = fmt === 'pcap-be-ns' || fmt === 'pcap-le-ns';
      const W32 = (b, o, v) => { if (be) w32(b, o, v); else { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; } };
      const W16 = (b, o, v) => { if (be) w16(b, o, v); else { b[o] = v & 255; b[o + 1] = (v >> 8) & 255; } };
      if (fmt.startsWith('pcap-') || fmt === 'pcap') {
        const h = new Uint8Array(24);
        W32(h, 0, ns ? 0xa1b23c4d : 0xa1b2c3d4); W16(h, 4, 2); W16(h, 6, 4); W32(h, 16, snap); W32(h, 20, lt);
        push(h);
        for (const fr of this.frames) {
          const d = this.l2(fr);
          const cap = Math.min(d.length, snap);
          const r = new Uint8Array(16 + cap);
          const tt = this.o.startEpoch + fr.t;
          const sec = Math.floor(tt);
          const sub = Math.min(Math.round((tt - sec) * (ns ? 1e9 : 1e6)), ns ? 999999999 : 999999);
          W32(r, 0, sec); W32(r, 4, sub); W32(r, 8, cap); W32(r, 12, d.length);
          r.set(d.subarray(0, cap), 16);
          push(r);
        }
      } else { // pcapng, little endian, ns resolution
        const shb = new Uint8Array(28);
        const L32 = (b, o, v) => { b[o] = v & 255; b[o + 1] = (v >>> 8) & 255; b[o + 2] = (v >>> 16) & 255; b[o + 3] = (v >>> 24) & 255; };
        const L16 = (b, o, v) => { b[o] = v & 255; b[o + 1] = (v >> 8) & 255; };
        L32(shb, 0, 0x0a0d0d0a); L32(shb, 4, 28); L32(shb, 8, 0x1a2b3c4d); L16(shb, 12, 1); L16(shb, 14, 0);
        L32(shb, 16, 0xffffffff); L32(shb, 20, 0xffffffff); L32(shb, 24, 28);
        push(shb);
        const idb = new Uint8Array(32);
        L32(idb, 0, 1); L32(idb, 4, 32); L16(idb, 8, lt); L32(idb, 12, snap);
        L16(idb, 16, 9); L16(idb, 18, 1); idb[20] = 9; // if_tsresol = 10^-9
        L16(idb, 24, 0); L16(idb, 26, 0); L32(idb, 28, 32);
        push(idb);
        for (const fr of this.frames) {
          const d = this.l2(fr);
          const cap = Math.min(d.length, snap);
          const pad = (4 - (cap % 4)) % 4;
          const bl = 32 + cap + pad;
          const b = new Uint8Array(bl);
          const units = Math.round((this.o.startEpoch + fr.t) * 1e6) * 1000; // keep exact at µs
          const hi = Math.floor(units / 4294967296), lo = units - hi * 4294967296;
          L32(b, 0, 6); L32(b, 4, bl); L32(b, 8, 0); L32(b, 12, hi); L32(b, 16, lo); L32(b, 20, cap); L32(b, 24, d.length);
          b.set(d.subarray(0, cap), 28); L32(b, bl - 4, bl);
          push(b);
        }
      }
      const out = new Uint8Array(total);
      let o = 0;
      for (const p of parts) { out.set(p, o); o += p.length; }
      return out;
    }
  }

  // ---------- TCP flow ----------
  // dir 0 = client → server, dir 1 = server → client
  class Flow {
    constructor(cap, o) {
      this.cap = cap;
      this.l3 = o.l3 || (o.c.includes(':') ? 6 : 4);
      this.ip = [o.c, o.s]; this.ipb = [parseIp(o.c), parseIp(o.s)];
      this.port = [o.cport || 50000 + Math.floor(cap.rnd() * 10000), o.sport || 443];
      this.dC = o.dC !== undefined ? o.dC : 0.0005; // one-way delay client ↔ capture point (s)
      this.dS = o.dS !== undefined ? o.dS : 0.01; // one-way delay capture point ↔ server (s)
      this.mss = [o.mssC || (this.l3 === 6 ? 1440 : 1460), o.mssS || (this.l3 === 6 ? 1440 : 1460)];
      this.ws = [o.wsC !== undefined ? o.wsC : 7, o.wsS !== undefined ? o.wsS : 7];
      this.wsOn = this.ws[0] !== null && this.ws[1] !== null;
      this.sack = o.sack !== false;
      this.isn = [Math.floor(cap.rnd() * 4e9), Math.floor(cap.rnd() * 4e9)];
      this.nxt = [this.isn[0], this.isn[1]];
      this.rwnd = [o.rwndC || 131072 * 4, o.rwndS || 65535 * 4];
      const hops = 9;
      this.ttl = [o.ttlC || (this.dC <= this.dS ? 64 : 64 - hops), o.ttlS || (this.dS < this.dC ? 64 : 64 - hops)];
      this.ipId = [Math.floor(cap.rnd() * 60000), Math.floor(cap.rnd() * 60000)];
      this.badCsumDir = o.badCsumDir; // checksum offload on this side's outgoing frames
      this.ttlAtCapture = (d) => this.ttl[d];
    }
    rtt() { return 2 * (this.dC + this.dS); }
    scale(d) { return this.wsOn ? this.ws[d] : 0; }
    seg(d, t, f) {
      const src = this.ipb[d], dst = this.ipb[1 - d];
      const win = f.rawWin !== undefined ? f.rawWin : Math.min(65535, Math.floor((f.win !== undefined ? f.win : this.rwnd[d]) / Math.pow(2, f.flags & F.SYN ? 0 : this.scale(d))));
      const tcp = tcpBytes({ sport: this.port[d], dport: this.port[1 - d], seq: f.seq !== undefined ? f.seq : this.nxt[d], ack: f.ack !== undefined ? f.ack : (f.flags & F.ACK ? this.nxt[1 - d] : 0), flags: f.flags, win, opts: f.opts, len: f.len || 0, payload: f.payload, badCsum: f.badCsum || this.badCsumDir === d }, src, dst, this.l3);
      const ip = ipBytes(this.l3, src, dst, 6, tcp, { ttl: f.ttl || this.ttl[d], id: (this.ipId[d] = (this.ipId[d] + 1) & 0xffff), df: true });
      return this.cap.add(t, ip, { src: this.ip[d], dst: this.ip[1 - d], dir: d, flow: this, out: d === 0, tcp: { seq: f.seq !== undefined ? f.seq : this.nxt[d], ack: f.ack !== undefined ? f.ack : (f.flags & F.ACK ? this.nxt[1 - d] : 0), flags: f.flags, win, len: f.len || 0, ttl: f.ttl || this.ttl[d] } });
    }
    // handshake; t = capture time of the SYN. Returns time the client's ACK passes the capture point.
    handshake(t, o) {
      o = o || {};
      const so = (d) => ({ mss: this.mss[d], sackOk: this.sack, ws: this.wsOn ? this.ws[d] : undefined });
      const r = {};
      r.syn = this.seg(0, t, { flags: F.SYN, opts: so(0), win: 64240, seq: this.isn[0] });
      this.nxt[0] = (this.isn[0] + 1) >>> 0;
      const t2 = t + 2 * this.dS + (o.serverSynDelay || 0);
      r.synack = this.seg(1, t2, { flags: F.SYN | F.ACK, opts: so(1), win: 65160, seq: this.isn[1] });
      this.nxt[1] = (this.isn[1] + 1) >>> 0;
      const t3 = t2 + 2 * this.dC;
      r.ack = this.seg(0, t3, { flags: F.ACK });
      r.t = t3;
      return r;
    }
    adv(d, n) { this.nxt[d] = (this.nxt[d] + n) >>> 0; }
    data(d, t, len, f) {
      const fr = this.seg(d, t, Object.assign({ flags: F.ACK | F.PSH, len }, f || {}));
      this.adv(d, len);
      return fr;
    }
    ack(d, t, f) { return this.seg(d, t, Object.assign({ flags: F.ACK }, f || {})); }
    // orderly close initiated by d at capture time t
    close(d, t) {
      const a = this.seg(d, t, { flags: F.FIN | F.ACK }); this.adv(d, 1);
      const delay = d === 0 ? 2 * this.dS : 2 * this.dC;
      const b = this.seg(1 - d, t + delay, { flags: F.FIN | F.ACK }); this.adv(1 - d, 1);
      const c = this.seg(d, t + delay + (d === 0 ? 2 * this.dC : 2 * this.dS), { flags: F.ACK });
      return { fin: a, fin2: b, last: c, t: c.t };
    }
    // a small request from client and a response from the server via the transfer simulator
    request(t, reqLen, respLen, o) {
      o = o || {};
      const req = this.data(0, t, reqLen, { payload: o.reqPayload });
      // server receives at t + dS, acks (delayed) or responds
      const think = o.think || 0.002;
      const tSrv = t + this.dS; // server local time of request arrival
      let ackFr = null;
      if (think > 0.03) ackFr = this.ack(1, tSrv + 0.0002 + Math.min(0.04, think / 2) + this.dS);
      const res = sim(this, 1, tSrv + think, Object.assign({ bytes: respLen }, o.sim || {}));
      return { req, ack: ackFr, res, t: res.tEnd };
    }
  }

  // ---------- discrete event TCP transfer simulator ----------
  // Simulates one bulk transfer on an established flow from sender S to receiver R.
  // t0 is the sender-local time at which the app has the data. All emitted frames
  // carry capture-point timestamps. Returns marks for the truth record.
  function sim(flow, S, t0, o) {
    const R = 1 - S;
    const dSnd = S === 0 ? flow.dC : flow.dS;
    const dRcv = S === 0 ? flow.dS : flow.dC;
    const mss = o.mss || Math.min(flow.mss[R], flow.mss[S]);
    const total = o.bytes;
    const base = flow.nxt[S];
    const rBase = flow.nxt[R];
    const rwndMax = o.rwnd || flow.rwnd[R];
    const rtt0 = flow.rtt();
    const res = { fast: [], rto: [], dup: [], zw: [], probe: [], winupd: [], dropAfter: [], dropBefore: [], tail: [], segs: 0, first: null, last: null, tEnd: t0, rst: null, pauseFrames: [], delack: [] };
    // event heap
    const H = [];
    let seqNo = 0;
    const lt = (a, b) => a.t < b.t || (a.t === b.t && a.s < b.s);
    const push = (e) => { e.s = seqNo++; H.push(e); let i = H.length - 1; while (i > 0) { const p = (i - 1) >> 1; if (!lt(e, H[p])) break; H[i] = H[p]; i = p; } H[i] = e; };
    const pop = () => { const top = H[0]; const last = H.pop(); if (H.length) { let i = 0; for (;;) { const l = 2 * i + 1, r = l + 1; let m = -1; let best = last; if (l < H.length && lt(H[l], best)) { m = l; best = H[l]; } if (r < H.length && lt(H[r], best)) { m = r; } if (m < 0) break; H[i] = H[m]; i = m; } H[i] = last; } return top; };
    // ---- sender ----
    let una = 0, nxt = 0, cwnd = (o.initCwnd || 10) * mss, ssth = o.ssthresh || Infinity;
    let dup = 0, inRec = false, recover = 0, peerWnd = o.peerWnd !== undefined ? o.peerWnd : rwndMax, backoff = 1;
    let rtoGen = 0, rtoPending = false, srtt = rtt0;
    const sent = new Map(); // off -> {len, attempts, t}
    let probing = false, retries = 0, finished = false;
    let pauseDone = false, resumeT = -1;
    let linkFree = 0;
    const rtoVal = () => Math.max(o.rtoMin || 0.2, srtt * 2 + 0.01) * backoff;
    const capT = (t) => t + dSnd;
    function transmit(t, off, len, kind) {
      const s = sent.get(off) || { len, attempts: 0, t };
      s.attempts++; s.t = t; s.len = len; sent.set(off, s);
      let fate = o.drop ? o.drop(off, s.attempts, len, kind) : null;
      if (o.blackholeAbove && len > o.blackholeAbove) fate = 'after';
      const tc = capT(t);
      let fr = null;
      if (fate !== 'before') {
        fr = flow.seg(S, tc, { flags: F.ACK | (off + len === total || kind === 'probe' ? F.PSH : 0), seq: (base + off) >>> 0, ack: rBase, len, win: o.senderWnd });
        if (!res.first) res.first = fr;
        res.last = fr;
        res.segs++;
        if (kind === 'fast') res.fast.push(fr);
        if (kind === 'rto') { res.rto.push(fr); if (s.tailCand) res.tail.push(fr); }
        if (kind === 'probe') res.probe.push(fr);
        if (fate === 'after') res.dropAfter.push(fr);
      } else res.dropBefore.push({ off, len, t: tc });
      if (fate === 'after' || fate === 'before') return;
      // bottleneck after capture point
      let arr = tc;
      if (o.bwBps) { const dep = Math.max(tc, linkFree) + (len + 54) * 8 / o.bwBps; linkFree = dep; arr = dep; }
      if (o.jitter) arr += o.jitter * flow.cap.rnd();
      push({ t: arr + dRcv, k: 'rcv', off, len, probe: kind === 'probe' });
    }
    function armRto(t) { rtoGen++; rtoPending = true; push({ t: t + rtoVal(), k: 'rto', g: rtoGen }); }
    function avail(t) {
      if (o.pauseAt !== undefined && !pauseDone) {
        if (nxt >= o.pauseAt) { if (resumeT < 0) { resumeT = Math.max(t, 0) + o.pauseMs / 1000; push({ t: resumeT, k: 'resume' }); } if (t < resumeT) return o.pauseAt; pauseDone = true; }
        else return o.pauseAt;
      }
      return total;
    }
    function trySend(t) {
      if (finished) return;
      const lim = avail(t);
      let sentAny = false;
      while (nxt < lim) {
        const len = Math.min(mss, lim - nxt);
        const wnd = Math.min(cwnd, peerWnd);
        if (nxt - una + len > wnd) break;
        transmit(t, nxt, len, 'new');
        nxt += len; sentAny = true;
        t += o.pacing || 0;
      }
      if (sentAny && !rtoPending) armRto(t);
      if (nxt < lim && peerWnd < mss && nxt === una && !probing) { probing = true; push({ t: t + rtoVal(), k: 'probe' }); }
      if (sentAny && nxt === total) { const s = sent.get(nxt - Math.min(mss, total - (Math.floor((total - 1) / mss) * mss))); if (s) s.tailCand = true; }
    }
    // ---- receiver ----
    let rcvNxt = 0, ooo = [], pendingAcks = 0, delGen = 0, buffered = 0, lastRead = t0, lastAdvWnd = rwndMax, lastAckT = -1;
    const readRate = o.appReadBps || Infinity;
    function doRead(t) {
      if (readRate === Infinity) { buffered = 0; lastRead = t; return; }
      let rate = readRate;
      if (o.rcvStall && t > o.rcvStall.from) rate = t < o.rcvStall.from + o.rcvStall.ms / 1000 ? 0 : readRate;
      buffered = Math.max(0, buffered - (t - lastRead) * rate); lastRead = t;
    }
    function rwnd() { return Math.max(0, Math.floor(rwndMax - buffered)); }
    function sendAck(t, kind) {
      doRead(t);
      let w = rwnd();
      const sc = Math.pow(2, flow.scale(R));
      w = Math.floor(w / sc) * sc;
      if (w < mss && w > 0) w = 0; // receiver SWS avoidance (RFC 1122)
      const sack = flow.sack && ooo.length ? ooo.slice(0, 3).map(([l, r]) => [(base + l) >>> 0, (base + r) >>> 0]) : null;
      const tc = t + dRcv;
      const fr = flow.seg(R, tc, { flags: F.ACK, seq: rBase, ack: (base + rcvNxt) >>> 0, win: w, opts: sack ? { sack } : undefined });
      if (kind === 'dup') res.dup.push(fr);
      if (w === 0) res.zw.push(fr);
      if (kind === 'upd') res.winupd.push(fr);
      if (kind === 'delack') res.delack.push(fr);
      lastAdvWnd = w; lastAckT = t;
      pendingAcks = 0; delGen++;
      push({ t: tc + dSnd, k: 'ack', ack: rcvNxt, wnd: w, isDup: kind === 'dup' });
    }
    function onRcv(t, e) {
      doRead(t);
      if (e.probe || (e.off >= rcvNxt && buffered + e.len > rwndMax + 1)) { sendAck(t, 'probe'); return; }
      if (e.off + e.len <= rcvNxt) { sendAck(t, 'dup'); return; }
      if (e.off > rcvNxt) {
        // out of order: store as SACK block
        ooo.push([e.off, e.off + e.len]); ooo.sort((a, b) => a[0] - b[0]);
        const m = []; for (const b of ooo) { if (m.length && b[0] <= m[m.length - 1][1]) m[m.length - 1][1] = Math.max(m[m.length - 1][1], b[1]); else m.push(b.slice()); }
        ooo = m;
        // most recent block first (RFC 2018)
        const idx = ooo.findIndex((b) => b[0] <= e.off && e.off < b[1]);
        if (idx > 0) { const b = ooo.splice(idx, 1)[0]; ooo.unshift(b); }
        buffered += e.len;
        sendAck(t, 'dup');
        return;
      }
      const hadHole = ooo.length > 0;
      rcvNxt = Math.max(rcvNxt, e.off + e.len); buffered += e.len;
      ooo.sort((a, b) => a[0] - b[0]);
      while (ooo.length && ooo[0][0] <= rcvNxt) { rcvNxt = Math.max(rcvNxt, ooo[0][1]); ooo.shift(); }
      if (hadHole) { sendAck(t, 'fill'); return; }
      pendingAcks++;
      const quick = o.quickAck || (o.delAck === 0);
      if (pendingAcks >= 2 || quick || rcvNxt === total && o.ackLastNow) sendAck(t, 'normal');
      else { const g = ++delGen; push({ t: t + (o.delAck !== undefined ? o.delAck : 0.04), k: 'delack', g }); }
      if (readRate !== Infinity) push({ t: t + 0.01, k: 'read' });
    }
    // ---- sender ack processing ----
    function onAck(t, e) {
      if (finished) return;
      const prevWnd = peerWnd;
      peerWnd = e.wnd;
      if (e.ack > una) {
        const s = sent.get(una);
        if (s && s.attempts === 1) srtt = 0.875 * srtt + 0.125 * (t - s.t);
        const acked = e.ack - una;
        una = e.ack; dup = 0; backoff = 1; retries = 0;
        if (inRec) {
          if (una >= recover) { inRec = false; cwnd = ssth; }
          else { const s2 = sent.get(una); if (s2) transmit(t, una, s2.len, 'fast'); }
        } else if (cwnd < ssth) cwnd += Math.min(acked, mss * 2);
        else cwnd += mss * mss / cwnd;
        if (o.maxCwnd) cwnd = Math.min(cwnd, o.maxCwnd);
        rtoPending = false;
        if (una < nxt) armRto(t);
        if (peerWnd >= mss) probing = false;
        if (una >= total) { finished = true; res.tEnd = t; return; }
      } else if (e.ack === una && una < nxt && e.isDup && peerWnd === prevWnd) {
        dup++;
        if (dup === (o.dupThresh || 3) && !inRec) {
          const s = sent.get(una);
          if (s) {
            ssth = Math.max(2 * mss, (nxt - una) / 2); cwnd = ssth; inRec = true; recover = nxt;
            transmit(t, una, s.len, 'fast');
            rtoPending = false; armRto(t);
          }
        }
      }
      if (peerWnd >= mss) probing = false;
      trySend(t);
    }
    function onRto(t) {
      rtoPending = false;
      if (finished) return;
      if (una < nxt) {
        retries++;
        if (o.maxRetries && retries > o.maxRetries) {
          finished = true;
          res.rst = flow.seg(S, capT(t), { flags: F.RST | F.ACK, seq: (base + nxt) >>> 0, ack: rBase });
          res.tEnd = t; res.gaveUp = true;
          return;
        }
        const s = sent.get(una);
        ssth = Math.max(2 * mss, (nxt - una) / 2); cwnd = mss; inRec = false; dup = 0;
        transmit(t, una, s.len, 'rto');
        backoff = Math.min(backoff * 2, 64);
        armRto(t);
      }
    }
    trySend(t0);
    let guard = 0;
    while (H.length && guard++ < 2e6) {
      const e = pop();
      if (e.k === 'rcv') onRcv(e.t, e);
      else if (e.k === 'ack') onAck(e.t, e);
      else if (e.k === 'delack') { if (e.g === delGen && pendingAcks > 0) sendAck(e.t, 'delack'); }
      else if (e.k === 'rto') { if (e.g === rtoGen && rtoPending) onRto(e.t); }
      else if (e.k === 'resume') trySend(e.t);
      else if (e.k === 'probe') {
        if (finished || !probing) continue;
        if (peerWnd >= mss) { probing = false; trySend(e.t); continue; }
        // zero window probe: one new byte at snd.nxt (receiver drops it)
        const fr = flow.seg(S, capT(e.t), { flags: F.ACK, seq: (base + nxt) >>> 0, ack: rBase, len: 1 });
        res.probe.push(fr);
        push({ t: e.t + dSnd + dRcv, k: 'rcv', off: nxt, len: 1, probe: true });
        backoff = Math.min(backoff * 2, 64);
        push({ t: e.t + rtoVal(), k: 'probe' });
      } else if (e.k === 'read') {
        doRead(e.t);
        const w = rwnd();
        if (lastAdvWnd < mss && w >= Math.min(rwndMax / 2, 4 * mss)) sendAck(e.t, 'upd');
        else if (buffered > 0 && lastAdvWnd < mss) push({ t: e.t + 0.01, k: 'read' });
      }
      if (finished && !H.some((x) => x.k === 'rcv' || x.k === 'ack')) break;
    }
    flow.nxt[S] = (base + (res.gaveUp ? nxt : total)) >>> 0;
    res.mss = mss;
    return res;
  }

  // ---------- UDP based helpers ----------
  function dnsName(name) {
    const out = [];
    for (const l of name.split('.')) { out.push(l.length); for (const ch of l) out.push(ch.charCodeAt(0)); }
    out.push(0);
    return out;
  }
  function dnsMsg(id, name, qtype, resp, rcode, answers) {
    const q = dnsName(name);
    const b = [id >> 8, id & 255, resp ? 0x81 : 0x01, resp ? (0x80 | rcode) : 0, 0, 1, 0, resp ? (answers || []).length : 0, 0, 0, 0, 0];
    b.push(...q, 0, qtype, 0, 1);
    if (resp) for (const a of answers || []) {
      b.push(0xc0, 12, 0, qtype, 0, 1, 0, 0, 0x0e, 0x10);
      const ab = parseIp(a);
      b.push(0, ab.length, ...ab);
    }
    return Uint8Array.from(b);
  }
  function udp(cap, t, src, dst, sport, dport, payload, o) {
    o = o || {};
    const l3 = src.includes(':') ? 6 : 4;
    const sb = parseIp(src), db = parseIp(dst);
    const u = udpBytes(sport, dport, payload, sb, db, l3, o.bad);
    if (o.fragMtu && u.length + (l3 === 4 ? 20 : 48) > o.fragMtu) {
      // fragment the UDP datagram
      const max = Math.floor((o.fragMtu - (l3 === 4 ? 20 : 48)) / 8) * 8;
      const frs = [];
      const id = o.id || 0x1234;
      for (let off = 0; off < u.length; off += max) {
        const part = u.subarray(off, Math.min(u.length, off + max));
        const mf = off + max < u.length;
        const ip = ipBytes(l3, sb, db, 17, part, { ttl: o.ttl, id, mf, fragOff: off, frag6: l3 === 6 ? id : 0 });
        frs.push(cap.add(t + frs.length * 0.00001, ip, { src, dst }));
      }
      return frs;
    }
    const ip = ipBytes(l3, sb, db, 17, u, { ttl: o.ttl, id: o.id || Math.floor(cap.rnd() * 65535) });
    return cap.add(t, ip, { src, dst });
  }
  function icmpErr(cap, t, from, to, type, code, origL3Bytes, o) {
    o = o || {};
    const v6 = from.includes(':');
    const inner = origL3Bytes.subarray(0, Math.min(origL3Bytes.length, v6 ? 1232 : 28 + 20));
    const b = new Uint8Array(8 + inner.length);
    b[0] = type; b[1] = code;
    if (o.mtu !== undefined) { if (v6) w32(b, 4, o.mtu); else w16(b, 6, o.mtu); }
    b.set(inner, 8);
    const fb = parseIp(from), tb = parseIp(to);
    const c = v6 ? csum([pseudo(fb, tb, 58, b.length, 6), b]) : csum([b]);
    w16(b, 2, c);
    const ip = ipBytes(v6 ? 6 : 4, fb, tb, v6 ? 58 : 1, b, { ttl: o.ttl || 250 });
    return cap.add(t, ip, { src: from, dst: to });
  }

  // ---------- TLS record builders (structure only, no real crypto) ----------
  function tlsClientHello(sni, r) {
    const ext = [];
    const host = Array.from(sni).map((c) => c.charCodeAt(0));
    const sn = [0, host.length + 3, 0, host.length >> 8, host.length & 255, ...host];
    ext.push(0, 0, sn.length >> 8, sn.length & 255, ...sn);
    ext.push(0, 43, 0, 5, 4, 3, 4, 3, 3); // supported_versions: TLS1.3, 1.2
    ext.push(0, 10, 0, 4, 0, 2, 0, 29); // groups x25519
    const ks = [0, 36, 0, 29, 0, 32]; for (let i = 0; i < 32; i++) ks.push(Math.floor(r() * 256));
    ext.push(0, 51, 0, ks.length, ...ks);
    const body = [3, 3]; for (let i = 0; i < 32; i++) body.push(Math.floor(r() * 256));
    body.push(32); for (let i = 0; i < 32; i++) body.push(Math.floor(r() * 256));
    body.push(0, 6, 0x13, 1, 0x13, 2, 0xc0, 0x2f, 1, 0, ext.length >> 8, ext.length & 255, ...ext);
    const hs = [1, 0, body.length >> 8, body.length & 255, ...body];
    return Uint8Array.from([0x16, 3, 1, hs.length >> 8, hs.length & 255, ...hs]);
  }
  function tlsServerHello(r, extraBytes) {
    const body = [3, 3]; for (let i = 0; i < 32; i++) body.push(Math.floor(r() * 256));
    body.push(32); for (let i = 0; i < 32; i++) body.push(Math.floor(r() * 256));
    body.push(0x13, 1, 0, 0, 6, 0, 43, 0, 2, 3, 4);
    const hs = [2, 0, body.length >> 8, body.length & 255, ...body];
    const out = [0x16, 3, 3, hs.length >> 8, hs.length & 255, ...hs, 0x14, 3, 3, 0, 1, 1];
    const n = extraBytes || 0;
    if (n > 5) { out.push(0x17, 3, 3, (n - 5) >> 8, (n - 5) & 255); for (let i = 0; i < n - 5; i++) out.push(Math.floor(r() * 256)); }
    return Uint8Array.from(out);
  }
  function tlsAppData(n, r, ccs) {
    const out = ccs ? [0x14, 3, 3, 0, 1, 1] : [];
    const m = n - out.length - 5;
    out.push(0x17, 3, 3, m >> 8, m & 255);
    for (let i = 0; i < m; i++) out.push(Math.floor(r() * 256));
    return Uint8Array.from(out);
  }
  function tlsAlert(level, desc) { return Uint8Array.from([0x15, 3, 3, 0, 2, level, desc]); }
  function httpReq(host, path) {
    const s = 'GET ' + (path || '/') + ' HTTP/1.1\r\nHost: ' + host + '\r\nUser-Agent: synthetic/1.0\r\nAccept: */*\r\n\r\n';
    return Uint8Array.from(Array.from(s).map((c) => c.charCodeAt(0)));
  }

  PA.gen = { F, rng, Capture, Flow, sim, udp, dnsMsg, icmpErr, tlsClientHello, tlsServerHello, tlsAppData, tlsAlert, httpReq, parseIp, ipBytes, tcpBytes, udpBytes };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.gen;
})(typeof globalThis !== 'undefined' ? globalThis : self);
