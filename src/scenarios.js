/*
 * PCAP Autopsy – synthetic scenarios (demo captures + test ground truth).
 * Addresses come from documentation ranges (RFC 5737 / RFC 3849), names from .example / .test.
 * Each build() returns { cap, truth }. truth.verdict is the expected overall verdict,
 * truth.expect lists findings that must appear together with packet numbers that must be cited,
 * truth.forbid lists finding ids that must NOT appear.
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});
  const g = PA.gen;
  const { Capture, Flow, sim, udp, dnsMsg, icmpErr, F } = g;
  const NO = (fr) => fr.no;
  const CL = '10.20.30.40', CL6 = '2001:db8:10::40';

  // ---------- building blocks ----------
  function dnsOk(cap, t, name, ans, o) {
    o = o || {};
    const id = o.id || Math.floor(cap.rnd() * 65535);
    const sport = o.sport || 40000 + Math.floor(cap.rnd() * 20000);
    const srv = o.server || '10.20.0.53';
    const q = udp(cap, t, o.client || CL, srv, sport, 53, dnsMsg(id, name, o.qtype || 1, false));
    let r = null;
    if (o.rt !== null) r = udp(cap, t + (o.rt !== undefined ? o.rt : 0.004 + cap.rnd() * 0.006), srv, o.client || CL, 53, sport, dnsMsg(id, name, o.qtype || 1, true, o.rcode || 0, o.rcode ? [] : [ans || '192.0.2.10']));
    return { q, r, id, sport };
  }
  function tlsSession(cap, fl, t, o) {
    o = o || {};
    const r = cap.rnd;
    const h = fl.handshake(t, o.hs);
    const chp = g.tlsClientHello(o.sni || 'www.example.com', r);
    const chFr = fl.data(0, h.t + 0.0002, chp.length, { payload: chp });
    const tSrv = h.t + 0.0002 + fl.dS + (o.shDelay || 0.0015);
    if (o.alert) {
      const al = g.tlsAlert(2, o.alert);
      const aFr = fl.data(1, tSrv + fl.dS, al.length, { payload: al });
      const c = fl.close(1, aFr.t + 0.0005);
      return { h, ch: chFr, alert: aFr, close: c, t: c.t };
    }
    const sh = g.tlsServerHello(r, 1200);
    const shFr = fl.data(1, tSrv + fl.dS, sh.length, { payload: sh });
    const more = g.tlsAppData(1400, r);
    const sh2 = fl.data(1, tSrv + fl.dS + 0.0001, more.length, { payload: more });
    const tC = sh2.t + 2 * fl.dC + 0.001;
    const fin = g.tlsAppData(80, r, true);
    const finFr = fl.data(0, tC, fin.length, { payload: fin });
    const req = g.tlsAppData(o.reqLen || 420, r);
    const reqFr = fl.data(0, tC + 0.0001, req.length, { payload: req });
    const res = sim(fl, 1, reqFr.t + fl.dS + (o.think || 0.003), Object.assign({ bytes: o.resp || 60000 }, o.sim || {}));
    return { h, ch: chFr, sh: shFr, fin: finFr, req: reqFr, res, t: Math.max(res.tEnd + fl.dS, res.last ? res.last.t : 0) };
  }
  function httpGet(cap, fl, t, host, resp, o) {
    o = o || {};
    const p = g.httpReq(host, o.path || '/');
    const req = fl.data(0, t, p.length, { payload: p });
    let ack = null;
    const tSrv = req.t + fl.dS;
    if ((o.think || 0) > 0.05) ack = fl.ack(1, tSrv + 0.04 + fl.dS);
    const respHdr = Uint8Array.from(Array.from('HTTP/1.1 200 OK\r\nContent-Length: ' + resp + '\r\n\r\n').map((c) => c.charCodeAt(0)));
    const hdrFr = fl.data(1, tSrv + (o.think || 0.002) + fl.dS, respHdr.length, { payload: respHdr });
    const res = sim(fl, 1, hdrFr.t - fl.dS + 0.0001, Object.assign({ bytes: resp }, o.sim || {}));
    return { req, ack, hdr: hdrFr, res, t: (res.last ? res.last.t : hdrFr.t) + 2 * fl.dC + 0.05 };
  }
  // background traffic that must never produce findings
  function background(cap, t0, dur) {
    let t = t0;
    let k = 0;
    while (t < t0 + dur) {
      dnsOk(cap, t, ['api.example.com', 'cdn.example.net', 'time.example.org'][k % 3], '192.0.2.' + (20 + (k % 3)));
      t += 0.7 + cap.rnd() * 0.4; k++;
    }
    // NTP
    udp(cap, t0 + 0.3, CL, '192.0.2.123', 123, 123, new Uint8Array(48).fill(0x23));
    udp(cap, t0 + 0.32, '192.0.2.123', CL, 123, 123, new Uint8Array(48).fill(0x24));
  }
  function healthyWeb(cap, t, o) {
    o = o || {};
    const fl = new Flow(cap, Object.assign({ c: CL, s: '192.0.2.10', sport: 443, dC: 0.0004, dS: 0.012 }, o));
    return tlsSession(cap, fl, t, { sni: o.sni || 'www.example.com', resp: o.resp || 180000 });
  }

  // TSO / GRO: merge back-to-back data frames of one direction into one large frame
  function tsoMerge(cap, flow, dir, maxBytes) {
    const fr = cap.frames.filter((f) => f.flow === flow && f.dir === dir && f.tcp && f.tcp.len > 0).sort((a, b) => a.t - b.t);
    const remove = new Set();
    let grp = [];
    const flush = () => {
      if (grp.length > 1) {
        const first = grp[0], last = grp[grp.length - 1];
        const len = grp.reduce((a, f) => a + f.tcp.len, 0);
        const src = flow.ipb[dir], dst = flow.ipb[1 - dir];
        const tcp = g.tcpBytes({ sport: flow.port[dir], dport: flow.port[1 - dir], seq: first.tcp.seq, ack: last.tcp.ack, flags: last.tcp.flags, win: last.tcp.win, len, badCsum: flow.badCsumDir === dir }, src, dst, flow.l3);
        const ip = g.ipBytes(flow.l3, src, dst, 6, tcp, { ttl: first.tcp.ttl, id: 1, df: true });
        first.bytes = ip; first.tcp = Object.assign({}, first.tcp, { len });
        first.merged = grp.length;
        for (let k = 1; k < grp.length; k++) remove.add(grp[k]);
      }
      grp = [];
    };
    for (const f of fr) {
      const prev = grp[grp.length - 1];
      const tot = grp.reduce((a, x) => a + x.tcp.len, 0);
      if (prev && Math.abs(f.t - prev.t) < 2e-6 && ((prev.tcp.seq + prev.tcp.len) >>> 0) === f.tcp.seq && tot + f.tcp.len <= maxBytes) grp.push(f);
      else { flush(); grp = [f]; }
    }
    flush();
    cap.frames = cap.frames.filter((f) => !remove.has(f));
    return remove.size;
  }

  // ---------- scenarios ----------
  const S = [];
  const def = (id, o) => { S.push(Object.assign({ id }, o)); };

  def('healthy', {
    group: 'reference', en: 'Healthy reference traffic', de: 'Gesunder Referenzverkehr',
    build() {
      const cap = new Capture({ seed: 11 });
      background(cap, 0, 9);
      healthyWeb(cap, 0.2, { resp: 250000 });
      const api = new Flow(cap, { c: CL, s: '192.0.2.20', sport: 80, dC: 0.0004, dS: 0.008 });
      const h = api.handshake(1.0);
      let t = h.t + 0.001;
      for (let k = 0; k < 4; k++) { const r = httpGet(cap, api, t, 'api.example.com', 3000 + k * 5000); t = r.t + 0.3; }
      api.close(0, t);
      const dl = new Flow(cap, { c: CL, s: '192.0.2.21', sport: 443, dC: 0.0004, dS: 0.015 });
      tlsSession(cap, dl, 2.5, { sni: 'cdn.example.net', resp: 5000000 });
      const v6 = new Flow(cap, { c: CL6, s: '2001:db8:443::10', sport: 443, dC: 0.0004, dS: 0.01 });
      tlsSession(cap, v6, 4.0, { sni: 'ipv6.example.com', resp: 400000 });
      udp(cap, 6.0, CL, '192.0.2.30', 51111, 443, Uint8Array.from([0xc3, 0, 0, 0, 1, 8, 1, 2, 3, 4, 5, 6, 7, 8]));
      udp(cap, 6.02, '192.0.2.30', CL, 443, 51111, Uint8Array.from([0xc3, 0, 0, 0, 1, 8, 9, 9, 9, 9, 9, 9, 9, 9]));
      for (let k = 0; k < 6; k++) udp(cap, 6.05 + k * 0.01, CL, '192.0.2.30', 51111, 443, new Uint8Array(1200).fill(0x40));
      return { cap, truth: { verdict: 'clean', expect: [], forbidSev: ['warning', 'critical'] } };
    },
  });

  def('syn-timeout', {
    group: 'handshake', en: 'SYN without answer (filtered port)', de: 'SYN ohne Antwort (gefilterter Port)',
    build() {
      const cap = new Capture({ seed: 21 });
      background(cap, 0, 8);
      healthyWeb(cap, 0.1, { resp: 60000 });
      const fl = new Flow(cap, { c: CL, s: '203.0.113.50', sport: 8443, cport: 51544 });
      const syns = [0.5, 1.5, 3.5].map((t) => fl.seg(0, t, { flags: F.SYN, opts: { mss: 1460, sackOk: true, ws: 7 }, win: 64240, seq: fl.isn[0] }));
      return { cap, truth: { verdict: 'network', expect: [{ id: 'hs.syn_unanswered', pkts: () => syns.map(NO) }] } };
    },
  });

  def('rst-on-syn', {
    group: 'handshake', en: 'Connection refused (RST on SYN)', de: 'Verbindung abgelehnt (RST auf SYN)',
    build() {
      const cap = new Capture({ seed: 22 });
      background(cap, 0, 5);
      const out = [];
      for (let k = 0; k < 3; k++) {
        const fl = new Flow(cap, { c: CL, s: '192.0.2.60', sport: 5432, cport: 52000 + k, dS: 0.006 });
        const t = 0.4 + k * 1.1;
        const syn = fl.seg(0, t, { flags: F.SYN, opts: { mss: 1460, sackOk: true, ws: 7 }, win: 64240, seq: fl.isn[0] });
        const rst = fl.seg(1, t + 0.012, { flags: F.RST | F.ACK, seq: 0, ack: (fl.isn[0] + 1) >>> 0, rawWin: 0 });
        out.push(syn, rst);
      }
      return { cap, truth: { verdict: 'server', expect: [{ id: 'hs.rst_on_syn', pkts: () => [out[0].no, out[1].no] }] } };
    },
  });

  def('loss', {
    group: 'loss', en: 'Packet loss: fast retransmit, RTO, tail loss', de: 'Paketverlust: Fast Retransmit, RTO, Tail Loss',
    build() {
      const cap = new Capture({ seed: 31 });
      background(cap, 0, 7);
      const fl = new Flow(cap, { c: CL, s: '198.51.100.80', sport: 443, dC: 0.0004, dS: 0.024 });
      const lost = new Set([60, 61, 230, 400, 520, 700, 701, 880, 1000, 1150]);
      const total = 1460 * 1400;
      const r = tlsSession(cap, fl, 0.3, {
        sni: 'downloads.example.com', resp: total,
        sim: { drop: (off, att) => (att === 1 && off === total - 1460 ? 'after' : att === 1 && lost.has(off / 1460) ? 'before' : null) },
      });
      // a second connection with reordering
      const f2 = new Flow(cap, { c: CL, s: '198.51.100.81', sport: 443, dC: 0.0004, dS: 0.02 });
      const h = f2.handshake(4.0);
      const req = f2.data(0, h.t + 0.001, 300);
      const t0 = req.t + 2 * f2.dS + 0.002;
      const seqs = []; for (let k = 0; k < 12; k++) seqs.push((f2.nxt[1] + k * 1400) >>> 0);
      const order = [0, 1, 2, 4, 3, 5, 6, 8, 7, 9, 10, 11];
      const oooFr = [];
      for (let k = 0; k < order.length; k++) { const fr = f2.seg(1, t0 + k * 0.0001, { flags: F.ACK | F.PSH, seq: seqs[order[k]], len: 1400 }); if (k === 4 || k === 8) oooFr.push(fr); }
      f2.adv(1, 12 * 1400);
      f2.ack(0, t0 + 0.002);
      f2.close(0, t0 + 0.3);
      return { cap, truth: { verdict: 'network', expect: [{ id: 'tcp.loss', pkts: () => r.res.fast.slice(0, 2).map(NO) }, { id: 'tcp.tail_loss', pkts: () => r.res.rto.slice(0, 1).map(NO) }, { id: 'tcp.reorder', pkts: () => oooFr.map(NO) }], forbid: ['tcp.spurious', 'capture.loss'] } };
    },
  });

  def('zero-window', {
    group: 'receiver', en: 'Receiver stalls: zero window', de: 'Empfänger hängt: Zero Window',
    build() {
      const cap = new Capture({ seed: 41 });
      background(cap, 0, 9);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.40', sport: 443, dC: 0.0004, dS: 0.01, rwndC: 65536 });
      const r = tlsSession(cap, fl, 0.3, { sni: 'reports.example.com', resp: 1200000, sim: { rwnd: 65536, appReadBps: 1.6e6 / 8 * 8 / 8, rcvStall: { from: 1.0, ms: 1500 } } });
      return { cap, truth: { verdict: 'client', expect: [{ id: 'tcp.zero_window', pkts: () => r.res.zw.slice(0, 2).map(NO) }] } };
    },
  });

  def('small-window', {
    group: 'receiver', en: 'No window scaling: 64 KB window on a long path', de: 'Kein Window Scaling: 64-KB-Fenster auf langer Strecke',
    build() {
      const cap = new Capture({ seed: 42 });
      background(cap, 0, 9);
      const fl = new Flow(cap, { c: CL, s: '198.51.100.90', sport: 443, dC: 0.0004, dS: 0.045, wsC: null, rwndC: 65535 });
      const r = tlsSession(cap, fl, 0.3, { sni: 'backup.example.com', resp: 4000000, sim: { rwnd: 65535 } });
      return { cap, truth: { verdict: 'client', expect: [{ id: 'tcp.no_wscale', pkts: () => [] }], forbid: ['tcp.zero_window', 'net.bufferbloat'] } };
    },
  });

  def('server-delay', {
    group: 'server', en: 'Slow server: long wait for the first byte', de: 'Langsamer Server: lange Wartezeit aufs erste Byte',
    build() {
      const cap = new Capture({ seed: 51 });
      background(cap, 0, 9);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.70', sport: 80, dC: 0.0004, dS: 0.009 });
      const h = fl.handshake(0.4);
      let t = h.t + 0.001;
      const reqs = [];
      for (let k = 0; k < 3; k++) { const r = httpGet(cap, fl, t, 'erp.example.com', 20000, { think: 1.2 + 0.3 * k, path: '/report?id=' + k }); reqs.push(r); t = r.t + 0.4; }
      fl.close(0, t);
      return { cap, truth: { verdict: 'server', expect: [{ id: 'app.server_delay', pkts: () => [reqs[0].req.no, reqs[0].hdr.no] }], forbid: ['tcp.loss', 'tcp.delack_nagle'] } };
    },
  });

  def('app-pause', {
    group: 'server', en: 'Server pauses mid-transfer', de: 'Server pausiert mitten in der Übertragung',
    build() {
      const cap = new Capture({ seed: 52 });
      background(cap, 0, 8);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.71', sport: 443, dC: 0.0004, dS: 0.011 });
      const r = tlsSession(cap, fl, 0.3, { sni: 'export.example.com', resp: 900000, sim: { pauseAt: 1460 * 200, pauseMs: 1800 } });
      return { cap, truth: { verdict: 'server', expect: [{ id: 'app.pause', pkts: () => [] }], forbid: ['tcp.loss', 'tcp.rto', 'tcp.zero_window'] } };
    },
  });

  def('delack-nagle', {
    group: 'delay', en: 'Delayed ACK meets Nagle (40 ms stalls)', de: 'Delayed ACK trifft Nagle (40-ms-Staus)',
    build() {
      const cap = new Capture({ seed: 61 });
      background(cap, 0, 6);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.80', sport: 6379, dC: 0.0003, dS: 0.006 });
      const h = fl.handshake(0.3);
      let t = h.t + 0.002;
      const ev = [];
      for (let k = 0; k < 8; k++) {
        const a = fl.data(0, t, 160);
        const ack = fl.ack(1, t + 2 * fl.dS + 0.040);
        const b = fl.data(0, ack.t + 2 * fl.dC, 380);
        const resp = fl.data(1, b.t + 2 * fl.dS + 0.0015, 700);
        fl.ack(0, resp.t + 2 * fl.dC + 0.0001);
        ev.push(a, ack, b);
        t = resp.t + 0.25;
      }
      fl.close(0, t);
      return { cap, truth: { verdict: 'client', expect: [{ id: 'tcp.delack_nagle', pkts: () => ev.slice(0, 3).map(NO) }], forbid: ['app.server_delay', 'tcp.loss'] } };
    },
  });

  def('bufferbloat', {
    group: 'queue', en: 'Bufferbloat: RTT grows under load', de: 'Bufferbloat: RTT steigt unter Last',
    build() {
      const cap = new Capture({ seed: 71 });
      background(cap, 0, 9);
      const fl = new Flow(cap, { c: CL, s: '198.51.100.100', sport: 443, dC: 0.0003, dS: 0.009, rwndS: 2 * 1024 * 1024 });
      const h = fl.handshake(0.3);
      const r = sim(fl, 0, h.t + 0.001, { bytes: 6000000, bwBps: 12e6, rwnd: 2 * 1024 * 1024, maxCwnd: 900000 });
      fl.close(0, r.tEnd + 0.01);
      return { cap, truth: { verdict: 'network', expect: [{ id: 'net.bufferbloat', pkts: () => [] }], forbid: ['tcp.window_limited', 'tcp.loss'] } };
    },
  });

  def('pmtud-blackhole', {
    group: 'mtu', en: 'PMTUD blackhole: big segments vanish', de: 'PMTUD-Blackhole: große Segmente verschwinden',
    build() {
      const cap = new Capture({ seed: 81 });
      background(cap, 0, 30);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.90', sport: 443, dC: 0.022, dS: 0.0003 });
      const r = tlsSession(cap, fl, 0.3, { sni: 'vpn-portal.example.com', resp: 300000, sim: { blackholeAbove: 1400, maxRetries: 6 } });
      return { cap, truth: { verdict: 'network', expect: [{ id: 'mtu.blackhole', pkts: () => r.res.rto.slice(0, 2).map(NO) }], forbid: ['end.rst_abort'] } };
    },
  });

  def('icmp-ptb', {
    group: 'mtu', en: 'ICMP Packet Too Big and MSS mismatch', de: 'ICMP Packet Too Big und MSS-Abweichung',
    build() {
      const cap = new Capture({ seed: 82 });
      background(cap, 0, 7);
      // IPv6: server sends 1440-byte segments, a tunnel router answers Packet Too Big (MTU 1280)
      const fl = new Flow(cap, { c: CL6, s: '2001:db8:443::20', sport: 443, dC: 0.0004, dS: 0.014 });
      const h = fl.handshake(0.3);
      const req = fl.data(0, h.t + 0.001, 380);
      const t0 = req.t + 2 * fl.dS + 0.002;
      const big = [];
      const start = fl.nxt[1];
      for (let k = 0; k < 4; k++) big.push(fl.seg(1, t0 + k * 0.0001, { flags: F.ACK | F.PSH, seq: (start + k * 1440) >>> 0, len: 1440 }));
      const ptb = icmpErr(cap, t0 + 0.0006, '2001:db8:ffff::1', '2001:db8:443::20', 2, 0, big[0].bytes, { mtu: 1280 });
      // the router sits between capture point and server here only for the ICMP; the capture sees it on the way
      const re = [];
      let off = 0;
      for (let k = 0; off < 4 * 1440; k++) { const len = Math.min(1220, 4 * 1440 - off); re.push(fl.seg(1, ptb.t + 2 * fl.dS + 0.0002 + k * 0.0001, { flags: F.ACK | F.PSH, seq: (start + off) >>> 0, len })); off += len; }
      fl.adv(1, 4 * 1440);
      fl.ack(0, re[re.length - 1].t + 0.0005);
      const r = sim(fl, 1, re[re.length - 1].t + 0.001 - fl.dS, { bytes: 200000, mss: 1220 });
      fl.close(0, (r.last ? r.last.t : t0) + 0.1);
      // IPv4: MSS clamped on the server side (1460 vs 1360)
      const f4 = new Flow(cap, { c: CL, s: '192.0.2.95', sport: 443, dC: 0.0004, dS: 0.01, mssS: 1360 });
      const r4 = tlsSession(cap, f4, 3.0, { sni: 'branch.example.com', resp: 120000 });
      return { cap, truth: { verdict: 'network', expect: [{ id: 'mtu.icmp_ptb', pkts: () => [ptb.no] }, { id: 'mtu.mss_mismatch', pkts: () => [r4.h.syn.no, r4.h.synack.no] }] } };
    },
  });

  def('rst-middlebox', {
    group: 'end', en: 'Reset injected by a middlebox (TTL mismatch)', de: 'Reset von einer Middlebox (abweichende TTL)',
    build() {
      const cap = new Capture({ seed: 91 });
      background(cap, 0, 6);
      const fl = new Flow(cap, { c: CL, s: '203.0.113.20', sport: 443, dC: 0.0004, dS: 0.018, ttlS: 52 });
      const r = tlsSession(cap, fl, 0.3, { sni: 'files.example.org', resp: 3000000 });
      // cut the transfer: drop everything after 40 % and insert a RST with TTL 254
      const cutT = r.res.first.t + (r.res.last.t - r.res.first.t) * 0.4;
      cap.frames = cap.frames.filter((f) => !(f.flow === fl && f.t > cutT));
      const seqNow = Math.max(...cap.frames.filter((f) => f.flow === fl && f.dir === 1 && f.tcp).map((f) => f.tcp.seq + f.tcp.len));
      const rst = fl.seg(1, cutT + 0.0005, { flags: F.RST | F.ACK, seq: seqNow >>> 0, ack: fl.nxt[0], ttl: 254, rawWin: 0 });
      return { cap, truth: { verdict: 'network', expect: [{ id: 'end.rst_middlebox', pkts: () => [rst.no] }], forbid: ['end.rst_abort'] } };
    },
  });

  def('dns', {
    group: 'dns', en: 'DNS: slow, SERVFAIL, NXDOMAIN, unanswered', de: 'DNS: langsam, SERVFAIL, NXDOMAIN, unbeantwortet',
    build() {
      const cap = new Capture({ seed: 101 });
      healthyWeb(cap, 0.1, { resp: 50000 });
      const slow = [];
      let t = 0.3;
      for (let k = 0; k < 5; k++) { slow.push(dnsOk(cap, t, 'intranet' + k + '.corp.example', '10.1.0.' + k, { rt: 0.45 + 0.1 * k, server: '10.20.0.53' })); t += 0.8; }
      const sf = dnsOk(cap, t, 'crm.corp.example', null, { rcode: 2, rt: 0.9 }); t += 0.5;
      const nx = dnsOk(cap, t, 'wpad.corp.example', null, { rcode: 3, rt: 0.01 }); t += 0.5;
      const un = dnsOk(cap, t, 'legacy.corp.example', null, { rt: null, server: '10.20.0.54' });
      for (let k = 1; k <= 2; k++) udp(cap, t + k * 1.0, CL, '10.20.0.54', un.sport, 53, dnsMsg(un.id, 'legacy.corp.example', 1, false));
      for (let k = 0; k < 4; k++) dnsOk(cap, t + 3.5 + k * 0.3, 'www.example.com', '192.0.2.10', { rt: 0.004 });
      return { cap, truth: { verdict: 'server', expect: [{ id: 'dns.slow', pkts: () => [slow[0].q.no, slow[0].r.no] }, { id: 'dns.servfail', pkts: () => [sf.r.no] }, { id: 'dns.nxdomain', pkts: () => [nx.r.no] }, { id: 'dns.unanswered', pkts: () => [un.q.no] }] } };
    },
  });

  def('tls', {
    group: 'tls', en: 'TLS: handshake failure alert and slow handshake', de: 'TLS: Handshake-Failure-Alert und langsamer Handshake',
    build() {
      const cap = new Capture({ seed: 111 });
      background(cap, 0, 7);
      const a = new Flow(cap, { c: CL, s: '192.0.2.110', sport: 443, dC: 0.0004, dS: 0.01 });
      const ra = tlsSession(cap, a, 0.3, { sni: 'legacy-app.example.com', alert: 40 });
      const b = new Flow(cap, { c: CL, s: '192.0.2.111', sport: 443, dC: 0.0004, dS: 0.01 });
      const rb = tlsSession(cap, b, 2.0, { sni: 'sso.example.com', shDelay: 1.6, resp: 30000 });
      return { cap, truth: { verdict: 'server', expect: [{ id: 'tls.alert', pkts: () => [ra.alert.no] }, { id: 'tls.slow', pkts: () => [rb.ch.no] }] } };
    },
  });

  def('icmp-unreach', {
    group: 'icmp', en: 'ICMP unreachable and TTL exceeded', de: 'ICMP Unreachable und TTL Exceeded',
    build() {
      const cap = new Capture({ seed: 121 });
      background(cap, 0, 6);
      const fl = new Flow(cap, { c: CL, s: '203.0.113.77', sport: 22, cport: 53001 });
      const syn = fl.seg(0, 0.5, { flags: F.SYN, opts: { mss: 1460, sackOk: true, ws: 7 }, win: 64240, seq: fl.isn[0] });
      const un = icmpErr(cap, 0.512, '198.51.100.1', CL, 3, 1, syn.bytes, { ttl: 253 });
      const syn2 = fl.seg(0, 1.5, { flags: F.SYN, opts: { mss: 1460, sackOk: true, ws: 7 }, win: 64240, seq: fl.isn[0] });
      const un2 = icmpErr(cap, 1.512, '198.51.100.1', CL, 3, 1, syn2.bytes, { ttl: 253 });
      const u = udp(cap, 2.0, CL, '192.0.2.120', 50514, 514, new Uint8Array(90).fill(0x41));
      const pu = icmpErr(cap, 2.006, '192.0.2.120', CL, 3, 3, u.bytes, { ttl: 62 });
      const tx = [];
      for (let k = 0; k < 3; k++) { const p = udp(cap, 3 + k * 0.1, CL, '203.0.113.99', 33434 + k, 33434 + k, new Uint8Array(32), { ttl: 1 + k }); tx.push(icmpErr(cap, 3.004 + k * 0.1, '10.20.0.1', CL, 11, 0, p.bytes, { ttl: 255 })); }
      return { cap, truth: { verdict: 'network', expect: [{ id: 'icmp.unreach', pkts: () => [un.no] }, { id: 'icmp.ttl', pkts: () => [tx[0].no] }, { id: 'hs.syn_unanswered', pkts: () => [syn.no] }] } };
    },
  });

  def('mixed', {
    group: 'mixed', en: 'Mixed: lossy WAN and a slow backend', de: 'Gemischt: verlustbehaftetes WAN und langsames Backend',
    build() {
      const cap = new Capture({ seed: 131 });
      background(cap, 0, 9);
      const fl = new Flow(cap, { c: CL, s: '198.51.100.140', sport: 443, dC: 0.0004, dS: 0.03 });
      const lost = new Set([40, 41, 160, 300, 301, 302, 420]);
      tlsSession(cap, fl, 0.3, { sni: 'media.example.net', resp: 1460 * 600, sim: { drop: (off, att) => (att === 1 && lost.has(off / 1460) ? 'before' : null) } });
      const ap = new Flow(cap, { c: CL, s: '192.0.2.141', sport: 80, dC: 0.0004, dS: 0.008 });
      const h = ap.handshake(3.0);
      let t = h.t + 0.001;
      for (let k = 0; k < 2; k++) { const r = httpGet(cap, ap, t, 'billing.example.com', 8000, { think: 1.4 }); t = r.t + 0.3; }
      ap.close(0, t);
      return { cap, truth: { verdict: 'mixed', expect: [{ id: 'tcp.loss', pkts: () => [] }, { id: 'app.server_delay', pkts: () => [] }] } };
    },
  });

  // ----- traps: must NOT produce a network verdict -----
  def('trap-offload', {
    group: 'trap', en: 'Trap: TSO super-segments and checksum offload', de: 'Falle: TSO-Supersegmente und Checksum Offload',
    build() {
      const cap = new Capture({ seed: 141 });
      background(cap, 0, 7);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.150', sport: 443, dC: 0.00002, dS: 0.012, badCsumDir: 0, rwndS: 4 * 1024 * 1024 });
      const h = fl.handshake(0.3);
      const r = sim(fl, 0, h.t + 0.001, { bytes: 3000000, rwnd: 4 * 1024 * 1024 });
      fl.close(0, r.tEnd + 0.01);
      const merged = tsoMerge(cap, fl, 0, 64000);
      return { cap, truth: { verdict: 'clean', expect: [{ id: 'capture.offload_tso', pkts: () => [] }, { id: 'capture.offload_csum', pkts: () => [] }], forbidSev: ['warning', 'critical'], merged } };
    },
  });

  def('trap-caploss', {
    group: 'trap', en: 'Trap: packets dropped by the capture, not the network', de: 'Falle: Pakete fehlen in der Capture, nicht im Netz',
    build() {
      const cap = new Capture({ seed: 151 });
      background(cap, 0, 7);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.160', sport: 443, dC: 0.0004, dS: 0.012 });
      const r = tlsSession(cap, fl, 0.3, { sni: 'storage.example.com', resp: 2000000 });
      const data = cap.frames.filter((f) => f.flow === fl && f.dir === 1 && f.tcp && f.tcp.len > 1000);
      const drop = new Set([data[100], data[101], data[400], data[900], data[1200]]);
      cap.frames = cap.frames.filter((f) => !drop.has(f));
      return { cap, truth: { verdict: 'clean', expect: [{ id: 'capture.loss', pkts: () => [] }], forbid: ['tcp.loss', 'tcp.rto'], forbidSev: ['warning', 'critical'] } };
    },
  });

  def('trap-snaplen', {
    group: 'trap', en: 'Trap: snaplen 96 bytes (headers only)', de: 'Falle: Snaplen 96 Byte (nur Header)',
    build() {
      const cap = new Capture({ seed: 161, snaplen: 96 });
      background(cap, 0, 7);
      healthyWeb(cap, 0.2, { resp: 800000 });
      const api = new Flow(cap, { c: CL, s: '192.0.2.20', sport: 80, dC: 0.0004, dS: 0.008 });
      const h = api.handshake(2.0);
      const r = httpGet(cap, api, h.t + 0.001, 'api.example.com', 40000);
      api.close(0, r.t);
      return { cap, truth: { verdict: 'clean', expect: [{ id: 'capture.snaplen', pkts: () => [] }], forbidSev: ['warning', 'critical'] } };
    },
  });

  def('trap-midstream', {
    group: 'trap', en: 'Trap: capture starts mid-connection (no handshake)', de: 'Falle: Capture beginnt mitten in der Verbindung',
    build() {
      const cap = new Capture({ seed: 171 });
      const fl = new Flow(cap, { c: CL, s: '192.0.2.170', sport: 443, dC: 0.0004, dS: 0.03, wsC: 9, rwndC: 1024 * 1024 });
      tlsSession(cap, fl, 0.1, { sni: 'sync.example.com', resp: 9000000, sim: { rwnd: 1024 * 1024, maxCwnd: 600000 } });
      background(cap, 0.5, 7);
      const cut = 0.5;
      cap.frames = cap.frames.filter((f) => f.t >= cut);
      return { cap, truth: { verdict: 'clean', expect: [{ id: 'capture.no_handshake', pkts: () => [] }], forbid: ['tcp.window_limited', 'tcp.no_wscale', 'tcp.loss'], forbidSev: ['warning', 'critical'] } };
    },
  });

  def('trap-keepalive', {
    group: 'trap', en: 'Trap: keep-alives and a spurious retransmission', de: 'Falle: Keep-Alives und eine Spurious Retransmission',
    build() {
      const cap = new Capture({ seed: 181 });
      background(cap, 0, 30);
      const fl = new Flow(cap, { c: CL, s: '192.0.2.180', sport: 443, dC: 0.0004, dS: 0.06 });
      const r = tlsSession(cap, fl, 0.2, { sni: 'push.example.com', resp: 4000 });
      let t = r.t + 1;
      const ka = [];
      for (let k = 0; k < 3; k++) {
        t += 8;
        ka.push(fl.seg(0, t, { flags: F.ACK, seq: (fl.nxt[0] - 1) >>> 0, len: 1 }));
        fl.ack(1, t + 2 * fl.dS);
      }
      // spurious RTO: server data, client ACK is late (150 ms), server retransmits after its 200 ms RTO
      t += 1;
      const d1 = fl.data(1, t, 600);
      const lateAck = fl.ack(0, t + 0.15);
      const sp = fl.seg(1, t + 0.2, { flags: F.ACK | F.PSH, seq: d1.tcp.seq, len: 600 });
      fl.ack(0, sp.t + 0.0005);
      fl.close(0, t + 2);
      return { cap, truth: { verdict: 'clean', expect: [{ id: 'capture.keepalive', pkts: () => ka.map(NO) }, { id: 'tcp.spurious', pkts: () => [sp.no] }], forbid: ['tcp.loss', 'tcp.rto', 'app.pause'], forbidSev: ['warning', 'critical'] } };
    },
  });

  def('trap-short', {
    group: 'trap', en: 'Trap: capture too short for a verdict', de: 'Falle: Capture zu kurz für ein Urteil',
    build() {
      const cap = new Capture({ seed: 191 });
      const fl = new Flow(cap, { c: CL, s: '192.0.2.190', sport: 443, dC: 0.0004, dS: 0.01 });
      const h = fl.handshake(0.01);
      fl.data(0, h.t + 0.001, 500);
      fl.data(1, h.t + 0.022, 1400);
      fl.ack(0, h.t + 0.0235);
      dnsOk(cap, 0.1, 'www.example.com');
      return { cap, truth: { verdict: 'inconclusive', expect: [], forbidSev: ['warning', 'critical'] } };
    },
  });

  // ----- format / link-type variants (parser coverage) -----
  const VARIANTS = [
    { id: 'fmt-pcap-le-us-eth', link: 'eth', format: 'pcap' },
    { id: 'fmt-pcap-be-ns-raw', link: 'raw', format: 'pcap-be-ns' },
    { id: 'fmt-pcap-le-ns-vlan', link: 'vlan', format: 'pcap-le-ns' },
    { id: 'fmt-pcapng-qinq', link: 'qinq', format: 'pcapng' },
    { id: 'fmt-pcapng-sll', link: 'sll', format: 'pcapng' },
    { id: 'fmt-pcap-sll2', link: 'sll2', format: 'pcap' },
    { id: 'fmt-pcap-null', link: 'null', format: 'pcap' },
  ];
  function variant(v) {
    const cap = new Capture({ seed: 201, link: v.link, format: v.format });
    const fl = new Flow(cap, { c: CL, s: '192.0.2.10', sport: 443, dC: 0.0004, dS: 0.01 });
    tlsSession(cap, fl, 0.1, { sni: 'fmt.example.com', resp: 50000 });
    const f6 = new Flow(cap, { c: CL6, s: '2001:db8:443::10', sport: 443, dC: 0.0004, dS: 0.01 });
    tlsSession(cap, f6, 0.5, { sni: 'fmt6.example.com', resp: 30000 });
    // fragmented DNS responses (IPv4 and IPv6)
    const big = dnsMsg(0x4242, 'big.example.com', 1, true, 0, Array.from({ length: 150 }, (_, k) => '192.0.2.' + (k % 250)));
    udp(cap, 1.0, CL, '10.20.0.53', 41000, 53, dnsMsg(0x4242, 'big.example.com', 1, false));
    const frs = udp(cap, 1.003, '10.20.0.53', CL, 53, 41000, big, { fragMtu: 1500, id: 0x777 });
    udp(cap, 1.1, CL6, '2001:db8::53', 41001, 53, dnsMsg(0x4343, 'big6.example.com', 1, false));
    const frs6 = udp(cap, 1.103, '2001:db8::53', CL6, 53, 41001, dnsMsg(0x4343, 'big6.example.com', 1, true, 0, Array.from({ length: 150 }, (_, k) => '192.0.2.' + (k % 250))), { fragMtu: 1280, id: 0x888 });
    for (let k = 0; k < 30; k++) udp(cap, 1.2 + k * 0.08, CL, '192.0.2.123', 123, 123, new Uint8Array(48));
    return { cap, truth: { verdict: 'clean', frags: frs.length + frs6.length, forbidSev: ['warning', 'critical'], tcpConns: 2 } };
  }

  function build(id) {
    const v = VARIANTS.find((x) => x.id === id);
    const r = v ? variant(v) : S.find((s) => s.id === id).build();
    const bytes = r.cap.bytes();
    const truth = Object.assign({}, r.truth);
    truth.expect = (truth.expect || []).map((e) => ({ id: e.id, pkts: e.pkts() }));
    truth.frames = r.cap.frames.length;
    return { bytes, truth };
  }

  PA.scenarios = { list: S.map((s) => ({ id: s.id, group: s.group, en: s.en, de: s.de })), variants: VARIANTS.map((v) => v.id), build };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.scenarios;
})(typeof globalThis !== 'undefined' ? globalThis : self);
