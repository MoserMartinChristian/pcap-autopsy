/*
 * PCAP Autopsy – analysis.
 * Reads the packet store and produces findings, a verdict, the capture-point estimate,
 * per-connection summaries, packet-list rows and chart series. Pure JS, no DOM.
 */
(function (G) {
  'use strict';
  function maxOf(a) { let m = -Infinity; for (let i = 0; i < a.length; i++) if (a[i] > m) m = a[i]; return m; }
  function minOf(a) { let m = Infinity; for (let i = 0; i < a.length; i++) if (a[i] < m) m = a[i]; return m; }
  function pushAll(dst, src) { for (let i = 0; i < src.length; i++) dst.push(src[i]); return dst.length; }
  const PA = G.PA || (G.PA = {});
  const C = PA.config;
  const th = (k) => C.T[k].v;
  const M = PA.store.M, KIND = PA.store.KIND;

  const median = (a) => { if (!a.length) return NaN; const s = Array.from(a).sort((x, y) => x - y); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
  const pct = (a, p) => { if (!a.length) return NaN; const s = Array.from(a).sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.max(0, Math.round(p * (s.length - 1))))]; };
  const ms = (s) => Math.round(s * 1e4) / 10; // seconds → ms with 0.1 precision
  function spearman(x, y) {
    const n = x.length; if (n < 3) return 0;
    const rank = (v) => { const idx = v.map((_, i) => i).sort((a, b) => v[a] - v[b]); const r = new Array(n); let i = 0; while (i < n) { let j = i; while (j + 1 < n && v[idx[j + 1]] === v[idx[i]]) j++; const avg = (i + j) / 2; for (let k = i; k <= j; k++) r[idx[k]] = avg; i = j + 1; } return r; };
    const rx = rank(x), ry = rank(y);
    const mx = (n - 1) / 2;
    let num = 0, dx = 0, dy = 0;
    for (let i = 0; i < n; i++) { num += (rx[i] - mx) * (ry[i] - mx); dx += (rx[i] - mx) ** 2; dy += (ry[i] - mx) ** 2; }
    return dx && dy ? num / Math.sqrt(dx * dy) : 0;
  }
  const initialTtl = (t) => (t <= 64 ? 64 : t <= 128 ? 128 : 255);
  function modeOf(map) { let best = -1, n = -1; for (const [k, v] of map) if (v > n) { n = v; best = k; } return best; }
  const sideName = (d) => (d === 0 ? 'client' : 'server');
  const limitList = (a, n) => (a.length > n ? a.slice(0, n) : a);

  function connFilter(S, f) {
    const v = f.l3 === 6 ? 'ipv6' : 'ip';
    const a = S.addrs[f.c], b = S.addrs[f.s];
    return v + '.addr==' + a + ' && ' + v + '.addr==' + b + ' && ' + f.proto + '.port==' + f.cp + ' && ' + f.proto + '.port==' + f.sp;
  }
  const framesFilter = (pkts) => (pkts.length ? 'frame.number in {' + limitList(pkts, 60).join(' ') + '}' : '');

  // ---------- TCP connection analysis ----------
  function analyzeTcp(S, f, ctx) {
    const out = [];
    const mk = () => ({
      base: null, lastRaw: 0, lastRel: 0, aLastRaw: null, aLastRel: 0,
      maxEnd: -1, holes: [], highAck: -1, lastAckR: null, lastWin: -1, lastWinB: -1, dupN: 0, dupVal: null, lastSackLeft: null,
      lastPktT: -1, lastDataT: -1, lastNewDataT: -1, lastNewDataI: -1, lastRetransT: -1,
      ttl: new Map(), rttQ: [], rttQh: 0, rtt: [], dataSegs: 0, dataBytes: 0, newSegs: 0,
      retrans: [], fast: [], rto: [], tail: [], spurious: [], ooo: [], dup: [], sackPkts: 0, prevLost: [], ackUnseen: [],
      lostBefore: 0, lostAfter: 0, capLossBytes: 0, capLossPkts: [], zwp: [], ka: [], overMss: [], maxSeg: 0,
      zw: [], zwOpen: null, lastSmallWinT: -1, winFull: [], winLimited: 0, winUpd: [], maxWinB: 0, minWinB: Infinity, karnUntil: -1,
      pendingNagle: null, pauses: [], retransBySeq: new Map(), synAt: [], firstDataI: -1, lastAckI: -1,
    });
    const st = [mk(), mk()];
    const relSeq = (x, raw) => {
      if (x.base === null) { x.base = raw; x.lastRaw = raw; x.lastRel = 0; return 0; }
      const d = (raw - x.lastRaw) | 0; x.lastRaw = raw; x.lastRel += d; return x.lastRel;
    };
    const relAck = (x, raw) => {
      if (x.base === null) { x.base = raw; x.lastRaw = raw; x.lastRel = 0; x.aLastRaw = raw; x.aLastRel = 0; return 0; }
      if (x.aLastRaw === null) { x.aLastRaw = x.base; x.aLastRel = 0; }
      const d = (raw - x.aLastRaw) | 0; x.aLastRaw = raw; x.aLastRel += d; return x.aLastRel;
    };
    // handshake facts
    const hs = { syn: [], synack: [], ack3: -1, rstOnSyn: -1, mss: [null, null], ws: [null, null], sackOk: [false, false], ts: [false, false] };
    const rsts = [];
    const exchanges = [];
    let lastDataDir = -1, reqLastI = -1, reqFirstI = -1, srvAckI = -1;
    const mssOf = (d) => hs.mss[d] || (f.l3 === 6 ? 1440 : 1460);
    let wsKnown = false, wsActive = false;
    const scale = (d) => (wsActive ? hs.ws[d] : 0);

    for (let i = f.head; i !== -1; i = S.next[i]) {
      if (S.kind[i] !== KIND.TCP) continue;
      const d = S.dir[i], o = 1 - d, x = st[d], y = st[o];
      const fl = S.tfl[i], len = S.plen[i], t = S.ts[i];
      const syn = (fl & 2) !== 0, fin = (fl & 1) !== 0, rst = (fl & 4) !== 0, ackf = (fl & 16) !== 0;
      if (!rst) x.ttl.set(S.ttl[i], (x.ttl.get(S.ttl[i]) || 0) + 1);
      if (syn) {
        const op = S.opts.get(i) || {};
        if (!ackf && hs.syn.length && S.seq[i] === S.seq[hs.syn[0]]) S.marks[i] |= M.RETRANS;
        if (ackf && hs.synack.length) S.marks[i] |= M.RETRANS;
        if (!ackf) { hs.syn.push(i); hs.mss[0] = op.mss || null; hs.ws[0] = op.ws !== undefined ? op.ws : null; hs.sackOk[0] = op.sackOk; hs.ts[0] = op.ts; if (x.base === null) x.base = S.seq[i], x.lastRaw = S.seq[i]; }
        else { hs.synack.push(i); hs.mss[1] = op.mss || null; hs.ws[1] = op.ws !== undefined ? op.ws : null; hs.sackOk[1] = op.sackOk; hs.ts[1] = op.ts; }
        if (hs.syn.length && hs.synack.length) { wsKnown = true; wsActive = hs.ws[0] !== null && hs.ws[1] !== null; }
      }
      const seqR = relSeq(x, S.seq[i]);
      const segEnd = seqR + len + (syn ? 1 : 0) + (fin ? 1 : 0);
      if (rst) {
        rsts.push({ i, d, t, ttl: S.ttl[i], established: hs.synack.length > 0 || !f.synSeen, outstanding: Math.max(0, st[0].maxEnd - (st[1].highAck < 0 ? st[0].maxEnd : st[1].highAck)) + Math.max(0, st[1].maxEnd - (st[0].highAck < 0 ? st[1].maxEnd : st[0].highAck)), finSeen: f.fin[0] && S.ts[i] >= 0 ? hadFin(st) : false });
        if (!hs.synack.length && hs.syn.length && d === 1 && hs.rstOnSyn < 0) hs.rstOnSyn = i;
        S.marks[i] |= M.KEY;
      }
      if (hs.synack.length && hs.ack3 < 0 && d === 0 && ackf && !syn && i > hs.synack[hs.synack.length - 1]) hs.ack3 = i;

      // ----- sequence space of the sender -----
      if (len > 0 || syn || fin) {
        let isKa = false, isZwp = false;
        if (len > 0 && len <= 1 && !syn && !fin && x.maxEnd > 0 && seqR === x.maxEnd - 1) { isKa = true; S.marks[i] |= M.KEEPALIVE; x.ka.push(i); }
        else if (len > 0 && len <= 1 && y.lastWin === 0 && x.maxEnd >= 0 && seqR >= x.maxEnd - 1 && seqR <= x.maxEnd) { isZwp = true; S.marks[i] |= M.ZWP; x.zwp.push(i); }
        if (!isKa && !isZwp) {
          if (len > 0) { x.dataSegs++; x.dataBytes += len; if (x.firstDataI < 0) x.firstDataI = i; if (len > x.maxSeg) x.maxSeg = len; }
          if (x.maxEnd < 0) x.maxEnd = seqR;
          if (len > 0 && hs.mss[o] && len > hs.mss[o]) { S.marks[i] |= M.OVERMSS; x.overMss.push(i); }
          if (seqR > x.maxEnd) {
            S.marks[i] |= M.PREVLOST; x.prevLost.push(i);
            x.holes.push({ l: x.maxEnd, r: seqR, t, i });
            if (x.holes.length > 2000) x.holes.shift();
          }
          if (seqR >= x.maxEnd) {
            // new data
            x.maxEnd = segEnd;
            if (len > 0) {
              x.newSegs++;
              x.rttQ.push({ end: segEnd, t, i, len, inflight: y.highAck >= 0 ? segEnd - y.highAck : len });
              // application pause in an ongoing transfer
              if (x.lastNewDataT >= 0 && lastDataDir === d && t - x.lastNewDataT >= th('idleGapMs') / 1000) {
                const allAcked = y.highAck >= seqR;
                const winOpen = (y.lastWinB < 0 || y.lastWinB >= mssOf(o)) && !(y.lastSmallWinT >= x.lastNewDataT);
                const noLoss = x.lastRetransT < x.lastNewDataT;
                const noKa = !(st[0].ka.length && S.ts[st[0].ka[st[0].ka.length - 1]] > x.lastNewDataT) && !(st[1].ka.length && S.ts[st[1].ka[st[1].ka.length - 1]] > x.lastNewDataT);
                if (allAcked && winOpen && noLoss && noKa) x.pauses.push({ from: x.lastNewDataI, to: i, gap: t - x.lastNewDataT });
              }
              x.lastNewDataT = t; x.lastNewDataI = i;
            }
          } else if (len > 0 || fin) {
            // segment behind the highest sequence seen: retransmission or reordering
            let hole = null, hi = -1;
            for (let k = x.holes.length - 1; k >= 0; k--) { const h = x.holes[k]; if (seqR >= h.l && seqR < h.r) { hole = h; hi = k; break; } }
            let kind;
            if (hole) {
              const e = Math.min(segEnd, hole.r);
              // split the hole
              const parts = [];
              if (seqR > hole.l) parts.push({ l: hole.l, r: seqR, t: hole.t, i: hole.i });
              if (e < hole.r) parts.push({ l: e, r: hole.r, t: hole.t, i: hole.i });
              x.holes.splice(hi, 1, ...parts);
              kind = t - hole.t < th('oooMaxMs') / 1000 ? 'ooo' : 'retrans-before';
            } else kind = 'retrans';
            if (kind === 'ooo') { S.marks[i] |= M.OOO; x.ooo.push(i); }
            else {
              S.marks[i] |= M.RETRANS; x.retrans.push(i); x.lastRetransT = t;
              x.retransBySeq.set(seqR, (x.retransBySeq.get(seqR) || 0) + 1);
              x.karnUntil = Math.max(x.karnUntil, segEnd);
              if (kind === 'retrans-before') x.lostBefore++; else x.lostAfter++;
              if (segEnd <= y.highAck) { S.marks[i] |= M.SPURIOUS; x.spurious.push(i); }
              else {
                const dupOk = y.dupVal === seqR && y.dupN >= th('dupAckThreshold');
                const sackOk = y.lastSackLeft !== null && y.lastAckR === seqR;
                const gap = t - x.lastPktT;
                const minR = x.rtt.length ? x.minRtt : (ctx.hsRtt || 0);
                if (dupOk || (sackOk && y.dupN >= 1)) { S.marks[i] |= M.FAST; x.fast.push(i); }
                else if (gap >= Math.max(th('rtoMinMs') / 1000 * 0.9, 1.5 * minR)) {
                  S.marks[i] |= M.RTO; x.rto.push(i);
                  if (segEnd >= x.maxEnd - 0) { S.marks[i] |= M.TAIL; x.tail.push(i); }
                }
              }
            }
          }
          if (len > 0 && y.lastWinB >= 0 && y.lastAckR !== null) {
            const inflight = segEnd - y.lastAckR;
            const w = y.lastWinB;
            if (w > 0 && inflight >= w) { S.marks[i] |= M.WINFULL; x.winFull.push(i); }
            if (w > 0 && w - inflight < Math.max(x.maxSeg, 536)) x.winLimited++;
          }
        }
        if (len > 0 && !(S.marks[i] & (M.KEEPALIVE | M.ZWP))) {
          x.lastDataT = t;
          if (lastDataDir !== d) {
            // turn change: a response starts
            if (d === 1 && lastDataDir === 0 && reqLastI >= 0) exchanges.push({ req: reqLastI, reqFirst: reqFirstI, resp: i, delay: t - S.ts[reqLastI], srvAck: srvAckI });
            if (d === 0) { reqFirstI = i; srvAckI = -1; }
            lastDataDir = d;
          }
          if (d === 0) reqLastI = i;
          if (x.pendingNagle) { x.pendingNagle.next = t - x.pendingNagle.tAck; x.pendingNagle.nextLen = len; x.pendingNagle.nextI = i; x.pendingNagle = null; }
        }
      }

      // ----- acknowledgement side -----
      if (ackf && !syn || (syn && ackf)) {
        const ackR = relAck(y, S.ack[i]);
        if (!syn && !rst) {
          if (y.maxEnd >= 0 && ackR > y.maxEnd && y.dataSegs + y.newSegs > 0) {
            // ACK for bytes the capture never saw
            const lastZwp = y.zwp.length && ackR === y.maxEnd + 1;
            if (!lastZwp) { S.marks[i] |= M.ACKUNSEEN; x.ackUnseen.push(i); y.capLossBytes += ackR - y.maxEnd; y.capLossPkts.push(i); }
            y.maxEnd = ackR;
          }
          // holes that are now acknowledged were never retransmitted → dropped by the capture
          if (y.holes.length) {
            const keep = [];
            for (const h of y.holes) {
              if (ackR >= h.r) { y.capLossBytes += h.r - h.l; y.capLossPkts.push(h.i); S.marks[h.i] |= M.LOSTCAP; }
              else if (ackR > h.l) { y.capLossBytes += ackR - h.l; y.capLossPkts.push(h.i); S.marks[h.i] |= M.LOSTCAP; keep.push({ l: ackR, r: h.r, t: h.t, i: h.i }); }
              else keep.push(h);
            }
            y.holes = keep;
          }
          // RTT sample (Karn: skip retransmitted ranges)
          let last = null, n = 0;
          while (y.rttQh < y.rttQ.length && y.rttQ[y.rttQh].end <= ackR) { last = y.rttQ[y.rttQh++]; n++; }
          if (y.rttQh > 4096) { y.rttQ = y.rttQ.slice(y.rttQh); y.rttQh = 0; }
          if (last && last.end > y.karnUntil) {
            const v = t - last.t;
            const smp = { t, v, inflight: last.inflight, seg: last.i, ack: i, segLen: last.len, n, pure: len === 0, tAck: t, next: null };
            y.rtt.push(smp);
            y.minRtt = y.rtt.length === 1 ? v : Math.min(y.minRtt, v);
            if (len === 0) y.pendingNagle = smp;
          }
          if (d === 1 && reqLastI >= 0 && lastDataDir === 0 && srvAckI < 0 && len === 0 && ackR >= st[0].maxEnd) srvAckI = i;
          // duplicate ACKs and window updates
          const winRaw = S.win[i];
          if (len === 0 && !fin && x.lastAckR !== null && ackR === x.lastAckR && y.maxEnd > ackR) {
            if (winRaw === x.lastWin) {
              if (!(S.marks[i] & M.KEEPALIVE)) { S.marks[i] |= M.DUPACK; x.dup.push(i); x.dupN = x.dupVal === ackR ? x.dupN + 1 : 1; x.dupVal = ackR; }
            } else { S.marks[i] |= M.WINUPD; x.winUpd.push(i); }
          } else if (len === 0 && !fin && x.lastAckR !== null && ackR === x.lastAckR && winRaw !== x.lastWin && x.lastWin >= 0) { S.marks[i] |= M.WINUPD; x.winUpd.push(i); }
          else if (ackR !== x.lastAckR) { x.dupN = 0; x.dupVal = null; }
          if (S.sack.has(i)) { x.sackPkts++; const b = S.sack.get(i)[0]; x.lastSackLeft = b ? b[0] : null; } else x.lastSackLeft = null;
          if (ackR > x.highAck) x.highAck = ackR;
          x.lastAckR = ackR; x.lastAckI = i;
        } else if (syn) { x.highAck = Math.max(x.highAck, ackR); x.lastAckR = ackR; }
      }
      if (!rst && !syn) {
        const winRaw = S.win[i];
        const wb = winRaw * Math.pow(2, scale(d));
        if (wb < mssOf(o) && len === 0) x.lastSmallWinT = t;
        if (winRaw === 0) {
          S.marks[i] |= M.ZEROWIN;
          if (!x.zwOpen) x.zwOpen = { from: i, t, pkts: [i] }; else if (x.zwOpen.pkts.length < 20) x.zwOpen.pkts.push(i);
        } else if (x.zwOpen) { x.zwOpen.to = i; x.zwOpen.dur = t - x.zwOpen.t; x.zw.push(x.zwOpen); x.zwOpen = null; }
        x.lastWin = winRaw; x.lastWinB = wb;
        if (wb > x.maxWinB) x.maxWinB = wb;
        if (len === 0 && wb < x.minWinB && wb > 0) x.minWinB = wb;
      } else if (syn) { x.lastWin = S.win[i]; x.lastWinB = S.win[i]; x.maxWinB = Math.max(x.maxWinB, S.win[i]); }
      x.lastPktT = t;
    }
    for (const x of st) if (x.zwOpen) { x.zwOpen.dur = S.ts[f.last] - x.zwOpen.t; x.zwOpen.open = true; x.zw.push(x.zwOpen); x.zwOpen = null; }
    f.base = [st[0].base, st[1].base];
    f.rttSamples = [st[0].rtt, st[1].rtt];
    f.hs = hs;
    f.wsKnown = wsKnown; f.wsActive = wsActive;

    // ----- derived values -----
    const capEnd = ctx.capEnd;
    const tSyn = hs.syn.length ? S.ts[hs.syn[hs.syn.length - 1]] : null;
    let hsA = null, hsB = null;
    if (hs.synack.length && hs.syn.length) {
      const sa = hs.synack[0];
      let lastSynBefore = -1; for (const s of hs.syn) if (s < sa) lastSynBefore = s;
      if (lastSynBefore >= 0) hsA = S.ts[sa] - S.ts[lastSynBefore];
      if (hs.ack3 >= 0) hsB = S.ts[hs.ack3] - S.ts[hs.synack[hs.synack.length - 1]];
    }
    const hsRtt = hsA !== null && hsB !== null ? hsA + hsB : null;
    // path RTT seen from the capture point: data from the client is acked by the server and vice versa
    const minRtt = [st[0].rtt.length ? st[0].minRtt : null, st[1].rtt.length ? st[1].minRtt : null];
    const rttEst = hsRtt !== null ? hsRtt : (minRtt[0] !== null && minRtt[1] !== null ? minRtt[0] + minRtt[1] : (minRtt[0] || minRtt[1] || null));
    const ff = f.analysis = { hsA, hsB, hsRtt, minRtt, rttEst, st, exchanges, rsts };
    const base = { conn: f.id };
    const filt = connFilter(S, f);
    const add = (o2) => { out.push(Object.assign({}, base, o2, { filter: o2.filterExtra ? '(' + filt + ') && (' + o2.filterExtra + ')' : filt, frames: framesFilter(o2.pkts || []) })); };
    const P = (i) => i + 1;

    // ----- handshake -----
    if (hs.syn.length && !hs.synack.length) {
      if (hs.rstOnSyn >= 0) {
        add({ id: 'hs.rst_on_syn', sev: 'critical', conf: 'high', cat: 'server', side: 'server', pkts: [P(hs.syn[0]), P(hs.rstOnSyn)], m: { port: f.sp, ttl: S.ttl[hs.rstOnSyn] }, t: S.ts[hs.rstOnSyn], filterExtra: 'tcp.flags.syn==1 || tcp.flags.reset==1' });
      } else if (capEnd - tSyn >= th('synWaitS')) {
        const icmpFor = ctx.icmpByFlow.get(f.id) || [];
        add({ id: 'hs.syn_unanswered', sev: 'critical', conf: icmpFor.length ? 'high' : 'medium', cat: 'network', side: 'path', pkts: hs.syn.map(P).concat(icmpFor.map((e) => P(e.pkt))), m: { syns: hs.syn.length, waited: ms(capEnd - S.ts[hs.syn[0]]), port: f.sp, icmp: icmpFor.length }, t: S.ts[hs.syn[0]], filterExtra: 'tcp.flags.syn==1' });
        ctx.needSecond.add('syn');
      } else ctx.notes.add('synTooShort');
    }
    if (hs.syn.length > 1 && hs.synack.length) {
      const delay = S.ts[hs.synack[0]] - S.ts[hs.syn[0]];
      add({ id: 'hs.syn_retrans', sev: 'warning', conf: 'high', cat: 'network', side: 'path', pkts: hs.syn.map(P).concat([P(hs.synack[0])]), m: { syns: hs.syn.length, delay: ms(delay) }, t: S.ts[hs.syn[0]], filterExtra: 'tcp.flags.syn==1' });
    }
    if (hsRtt !== null && hsRtt * 1000 >= th('handshakeRttWarnMs')) {
      add({ id: 'hs.slow', sev: 'warning', conf: 'medium', cat: 'network', side: 'path', pkts: [P(hs.syn[hs.syn.length - 1]), P(hs.synack[0]), P(hs.ack3)], m: { rtt: ms(hsRtt), a: ms(hsA), b: ms(hsB) }, t: tSyn, filterExtra: 'tcp.flags.syn==1' });
    }
    // ----- per sender direction -----
    for (let d = 0; d < 2; d++) {
      const x = st[d], y = st[1 - d];
      const sender = sideName(d), receiver = sideName(1 - d);
      const ptbWin = (ctx.icmpByFlow.get(f.id) || []).filter((e) => e.mtu !== undefined).map((e) => [e.t, e.t + Math.max(0.5, 3 * (ctx.rttHint || 0.1))]);
      const pmtudRe = x.retrans.filter((i) => ptbWin.some(([a, b]) => S.ts[i] >= a && S.ts[i] <= b));
      const realRetrans = x.retrans.length - x.spurious.length - pmtudRe.length;
      // PMTUD blackhole: the same large segment repeated without any ACK
      let bh = null;
      for (const [seq, n] of x.retransBySeq) {
        if (n < th('pmtudMinRetrans')) continue;
        const firstIdx = x.retrans.find((i) => relOf(S, f, i, d) === seq);
        if (firstIdx === undefined || S.plen[firstIdx] < th('pmtudMinLen')) continue;
        if (y.highAck > seq) continue; // eventually acked
        bh = { seq, n, pkts: x.retrans.filter((i) => relOf(S, f, i, d) === seq) };
        break;
      }
      const allPtb = (ctx.icmpByFlow.get(f.id) || []).filter((e) => e.mtu !== undefined);
      const ptb = d === 0 ? allPtb : [];
      if (bh) {
        const smallOk = x.dataSegs - x.retrans.length > 0 || st[1 - d].dataSegs > 0;
        add({ id: 'mtu.blackhole', sev: 'critical', conf: ptb.length ? 'medium' : (smallOk ? 'high' : 'medium'), cat: 'network', side: 'path', dir: d, pkts: bh.pkts.map(P), m: { len: S.plen[bh.pkts[0]], n: bh.n + 1, sender, ptb: ptb.length, mss: mssOf(1 - d) }, t: S.ts[bh.pkts[0]], filterExtra: 'tcp.len>=' + th('pmtudMinLen') });
      }
      if (ptb.length) {
        const mtu = ptb[0].mtu;
        add({ id: 'mtu.icmp_ptb', sev: 'warning', conf: 'high', cat: 'network', side: 'path', pkts: ptb.map((e) => P(e.pkt)), m: { mtu, mss: Math.max(mssOf(0), mssOf(1)), from: ptb[0].from, v6: ptb[0].v6 ? 1 : 0, resent: st[0].retrans.length + st[1].retrans.length }, t: ptb[0].t, filterExtra: ptb[0].v6 ? 'icmpv6.type==2' : 'icmp.type==3 && icmp.code==4' });
        ctx.icmpUsed.add(ptb.map((e) => e.pkt).join(','));
        ptb.length = 0; // report once per connection
        (ctx.icmpByFlow.get(f.id) || []).forEach((e) => { if (e.mtu !== undefined) e.used = true; });
      }
      if (realRetrans > 0 && !bh) {
        const rate = x.dataSegs ? 100 * realRetrans / x.dataSegs : 0;
        let sev = 'info';
        if (x.dataSegs >= th('lossMinSegments') && rate >= th('lossCritPct')) sev = 'critical';
        else if (x.dataSegs >= th('lossMinSegments') && rate >= th('lossWarnPct')) sev = 'warning';
        else if (x.rto.length) sev = 'warning';
        else if (x.dataSegs < th('lossMinSegments') && realRetrans >= 2) sev = 'warning';
        const where = x.lostBefore && !x.lostAfter ? 'before' : x.lostAfter && !x.lostBefore ? 'after' : 'both';
        add({ id: 'tcp.loss', sev, conf: x.dataSegs >= th('lossMinSegments') ? 'high' : 'medium', cat: 'network', side: 'path', dir: d, pkts: limitList(x.retrans.filter((i) => !(S.marks[i] & M.SPURIOUS) && !pmtudRe.includes(i)), 40).map(P), m: { sender, receiver, retrans: realRetrans, segs: x.dataSegs, rate: Math.round(rate * 100) / 100, fast: x.fast.length, rto: x.rto.length, dup: y.dup.length, sack: y.sackPkts, before: x.lostBefore, after: x.lostAfter, where }, t: S.ts[x.retrans[0]], filterExtra: 'tcp.analysis.retransmission || tcp.analysis.duplicate_ack' });
        if (where !== 'both') ctx.lossWhere.push(where);
      }
      if (x.rto.length && !bh) {
        const stalls = x.rto.map((i) => S.ts[i] - prevPktTime(S, f, i, d));
        add({ id: x.tail.length ? 'tcp.tail_loss' : 'tcp.rto', sev: 'warning', conf: 'high', cat: 'network', side: 'path', dir: d, pkts: limitList(x.rto, 30).map(P), m: { sender, n: x.rto.length, tail: x.tail.length, stall: ms(maxOf(stalls)), total: ms(stalls.reduce((a, b) => a + b, 0)) }, t: S.ts[x.rto[0]], filterExtra: 'tcp.analysis.retransmission' });
      }
      if (x.ooo.length) {
        const share = x.dataSegs ? 100 * x.ooo.length / x.dataSegs : 0;
        add({ id: 'tcp.reorder', sev: x.ooo.length >= 3 && share >= 1 ? 'warning' : 'info', conf: 'medium', cat: 'network', side: 'path', dir: d, pkts: limitList(x.ooo, 30).map(P), m: { sender, n: x.ooo.length, share: Math.round(share * 100) / 100 }, t: S.ts[x.ooo[0]], filterExtra: 'tcp.analysis.out_of_order' });
      }
      if (x.spurious.length) add({ id: 'tcp.spurious', sev: 'info', conf: 'medium', cat: 'none', side: sender, dir: d, pkts: limitList(x.spurious, 30).map(P), m: { sender, n: x.spurious.length }, t: S.ts[x.spurious[0]], filterExtra: 'tcp.analysis.spurious_retransmission' });
      if (x.capLossBytes > 0) ctx.capLoss.push({ conn: f.id, bytes: x.capLossBytes, pkts: x.capLossPkts, d });
      if (x.ka.length) pushAll(ctx.keepalives, x.ka);
      if (x.zwp.length) pushAll(ctx.zwps, x.zwp);
      if (x.overMss.length) ctx.overMss.push({ conn: f.id, n: x.overMss.length, max: x.maxSeg, mss: hs.mss[1 - d], pkts: x.overMss, d });
      // receiver window (y is the receiver advertising windows for data from x)
      if (y.zw.length) {
        const max = maxOf(y.zw.map((z) => z.dur));
        const total = y.zw.reduce((a, z) => a + z.dur, 0);
        const pk = []; for (const z of y.zw) { pushAll(pk, z.pkts); if (z.to !== undefined) pk.push(z.to); }
        add({ id: 'tcp.zero_window', sev: max * 1000 >= th('zeroWindowCritMs') ? 'critical' : 'warning', conf: 'high', cat: receiver, side: receiver, dir: 1 - d, pkts: limitList(pk, 40).map(P), m: { receiver, sender, n: y.zw.length, max: ms(max), total: ms(total), probes: x.zwp.length }, t: S.ts[y.zw[0].from], filterExtra: 'tcp.analysis.zero_window || tcp.analysis.window_update || tcp.analysis.zero_window_probe' });
      }
      const enough = x.dataSegs >= th('lossMinSegments');
      const rounds = y.maxWinB > 0 ? x.dataBytes / y.maxWinB : 0;
      const limitedShare = rounds >= 1 ? Math.min(1, x.winLimited / rounds) : 0;
      const rttW = rttEst || minRtt[d];
      const capMbps = rttW ? y.maxWinB * 8 / rttW / 1e6 : 0;
      if (enough && (x.winFull.length >= th('windowFullMin') || limitedShare >= th('windowLimitedFraction')) && !y.zw.length && (!rttW || capMbps < th('windowCapMbps'))) {
        const maxWin = y.maxWinB;
        const rtt = rttW;
        const m = { receiver, sender, maxWin, full: x.winFull.length, share: Math.round(limitedShare * 100), rtt: rtt ? ms(rtt) : null, cap: rtt ? Math.round(maxWin * 8 / rtt / 1e5) / 10 : null, wsR: hs.ws[1 - d], wsS: hs.ws[d] };
        if (!wsKnown) {
          add({ id: 'tcp.window_unverified', sev: 'info', conf: 'low', cat: 'capture', side: receiver, dir: 1 - d, pkts: limitList(x.winFull, 20).map(P), m, t: S.ts[(x.winFull[0] !== undefined ? x.winFull[0] : f.first)], filterExtra: 'tcp.analysis.window_full' });
        } else {
          const noWs = !wsActive;
          const culprit = noWs ? (hs.ws[1 - d] === null ? 1 - d : (hs.ws[d] === null ? d : 1 - d)) : 1 - d;
          add({ id: noWs ? 'tcp.no_wscale' : 'tcp.window_limited', sev: 'warning', conf: rtt ? 'high' : 'medium', cat: sideName(culprit), side: sideName(culprit), dir: 1 - d, pkts: limitList(x.winFull.length ? x.winFull : [x.firstDataI], 30).map(P), m, t: S.ts[x.winFull.length ? x.winFull[0] : x.firstDataI], filterExtra: 'tcp.analysis.window_full' });
        }
      }
      // application pauses (sender app idle while everything is acked and the window is open)
      const rtt = rttEst || 0;
      const pauses = x.pauses.filter((p) => p.gap >= th('delayVsRttFactor') * rtt);
      if (pauses.length) {
        add({ id: 'app.pause', sev: 'warning', conf: rttEst ? 'high' : 'medium', cat: sender, side: sender, dir: d, pkts: limitList(pauses.flatMap((p) => [p.from, p.to]), 30).map(P), m: { sender, n: pauses.length, max: ms(maxOf(pauses.map((p) => p.gap))), total: ms(pauses.reduce((a, p) => a + p.gap, 0)) }, t: S.ts[pauses[0].from] });
      }
      // delayed ACK × Nagle: a sub-MSS segment waits for an ACK that is held by the delayed-ACK timer
      const baseR = minRtt[d] !== null ? minRtt[d] : null;
      if (baseR !== null && x.rtt.length) {
        const ev = [];
        const tol = th('delAckToleranceMs') / 1000;
        const pathPart = d === 0 ? (hsA !== null ? hsA : baseR) : (hsB !== null ? hsB : baseR);
        for (const s of y.rtt) { /* acks sent by x for y's data handled in the other iteration */ }
        for (const s of x.rtt) {
          if (!s.pure || s.n !== 1 || s.segLen >= mssOf(1 - d) || s.next === null) continue;
          const extra = s.v - Math.min(baseR, pathPart);
          const near40 = Math.abs(extra - th('delAck40Ms') / 1000) <= tol;
          const near200 = Math.abs(extra - th('delAck200Ms') / 1000) <= 2 * tol;
          if ((near40 || near200) && s.next <= Math.max(0.003, 1.5 * Math.min(baseR, pathPart) + 0.003) && s.nextLen > 0) ev.push({ s, timer: near40 ? 40 : 200 });
        }
        if (ev.length >= th('delAckMinCount')) {
          const timer = ev.filter((e) => e.timer === 200).length > ev.length / 2 ? 200 : 40;
          add({ id: 'tcp.delack_nagle', sev: 'warning', conf: ev.length >= 3 ? 'high' : 'medium', cat: sender, side: sender, dir: d, pkts: limitList(ev.flatMap((e) => [e.s.seg, e.s.ack, e.s.nextI]), 30).map(P), m: { sender, receiver, n: ev.length, timer, wait: ms(median(ev.map((e) => e.s.v - Math.min(baseR, pathPart)))), total: ms(ev.reduce((a, e) => a + e.s.v, 0)) }, t: S.ts[ev[0].s.seg] });
        }
      }
      // bufferbloat: RTT rises with bytes in flight
      const smp = x.rtt;
      if (smp.length >= th('bloatMinSamples')) {
        const v = smp.map((s) => s.v), inf = smp.map((s) => s.inflight);
        const minV = minOf(v);
        const p75 = pct(inf, 0.75);
        const hiV = smp.filter((s) => s.inflight >= p75).map((s) => s.v);
        const p90 = pct(hiV, 0.9);
        const rho = spearman(inf, v);
        x.bloat = { minV, p90, rho };
        if (p90 >= th('bloatFactor') * minV && (p90 - minV) * 1000 >= th('bloatMinMs') && rho >= th('bloatMinCorr')) {
          const top = smp.reduce((a, b) => (b.v > a.v ? b : a));
          const lowS = smp.reduce((a, b) => (b.v < a.v ? b : a));
          add({ id: 'net.bufferbloat', sev: 'warning', conf: rho >= 0.75 ? 'high' : 'medium', cat: 'network', side: 'path', dir: d, pkts: [P(lowS.seg), P(lowS.ack), P(top.seg), P(top.ack)], m: { sender, min: ms(minV), p90: ms(p90), rho: Math.round(rho * 100) / 100, inflight: Math.round(maxOf(inf) / 1024) }, t: top.t });
        }
      }
    }
    // a full window under a growing queue means the bottleneck link, not the receiver, limits the flow
    for (let d = 0; d < 2; d++) if (out.some((q) => q.id === 'net.bufferbloat' && q.dir === d)) {
      for (let k = out.length - 1; k >= 0; k--) if ((out[k].id === 'tcp.window_limited' || out[k].id === 'tcp.no_wscale') && out[k].dir === 1 - d) out.splice(k, 1);
    }
    // MSS asymmetry
    if (hs.mss[0] && hs.mss[1] && Math.abs(hs.mss[0] - hs.mss[1]) >= th('mssDiffBytes')) {
      const small = hs.mss[0] < hs.mss[1] ? 0 : 1;
      add({ id: 'mtu.mss_mismatch', sev: 'info', conf: 'medium', cat: 'network', side: 'path', pkts: [P(hs.syn[0]), P(hs.synack[0])], m: { c: hs.mss[0], s: hs.mss[1], small: sideName(small), mtu: Math.min(hs.mss[0], hs.mss[1]) + (f.l3 === 6 ? 60 : 40) }, t: S.ts[hs.syn[0]], filterExtra: 'tcp.option_kind==2' });
    }
    // server response time
    const srvSide = rttEst !== null ? (hsA !== null ? hsA : rttEst) : 0;
    const slow = exchanges.map((e) => Object.assign(e, { srv: e.delay - srvSide })).filter((e) => e.srv * 1000 >= th('serverDelayWarnMs') && e.delay >= th('delayVsRttFactor') * (rttEst || 0));
    if (slow.length) {
      const max = maxOf(slow.map((e) => e.srv));
      const acked = slow.filter((e) => e.srvAck >= 0 && S.ts[e.srvAck] - S.ts[e.req] < Math.max(0.25 * e.delay, 2 * (rttEst || 0) + 0.05)).length;
      add({ id: 'app.server_delay', sev: max * 1000 >= th('serverDelayCritMs') ? 'critical' : 'warning', conf: rttEst !== null ? 'high' : 'medium', cat: 'server', side: 'server', pkts: limitList(slow.flatMap((e) => (e.srvAck >= 0 ? [e.req, e.srvAck, e.resp] : [e.req, e.resp])), 30).map(P), m: { n: slow.length, of: exchanges.length, max: ms(max), median: ms(median(slow.map((e) => e.srv))), rtt: rttEst !== null ? ms(rttEst) : null, acked }, t: S.ts[slow[0].req] });
    }
    // connection end
    for (const r of rsts) {
      const x = st[r.d];
      if (!hs.synack.length && hs.syn.length) continue; // handled as RST on SYN
      const ttlMode = modeOf(x.ttl);
      const delta = ttlMode >= 0 ? Math.abs(ttlMode - r.ttl) : 0;
      if (ttlMode >= 0 && x.ttl.size && delta >= th('rstTtlDelta')) {
        add({ id: 'end.rst_middlebox', sev: 'warning', conf: 'medium', cat: 'network', side: 'path', dir: r.d, pkts: [P(r.i)], m: { from: sideName(r.d), ttl: r.ttl, normal: ttlMode, delta, hopsR: initialTtl(r.ttl) - r.ttl, hopsN: initialTtl(ttlMode) - ttlMode }, t: r.t, filterExtra: 'tcp.flags.reset==1' });
        ctx.needSecond.add('rst');
        continue;
      }
      const gaveUp = x.rto.length >= 3 || out.some((q) => q.id === 'mtu.blackhole');
      if (gaveUp) { add({ id: 'end.rst_gaveup', sev: 'info', conf: 'high', cat: 'none', side: sideName(r.d), dir: r.d, pkts: [P(r.i)], m: { from: sideName(r.d), rto: x.rto.length }, t: r.t, filterExtra: 'tcp.flags.reset==1' }); break; }
      const afterFin = f.fin[0] || f.fin[1] ? finBefore(S, f, r.i) : false;
      const midTransfer = !afterFin && (r.outstanding > 0 || (st[0].lastDataT >= 0 && r.t - Math.max(st[0].lastDataT, st[1].lastDataT) < Math.max(0.5, 3 * (rttEst || 0))));
      add({ id: midTransfer ? 'end.rst_abort' : 'end.rst', sev: midTransfer ? 'warning' : 'info', conf: 'high', cat: midTransfer ? sideName(r.d) : 'none', side: sideName(r.d), dir: r.d, pkts: [P(r.i)], m: { from: sideName(r.d), ttl: r.ttl, outstanding: r.outstanding }, t: r.t, filterExtra: 'tcp.flags.reset==1' });
      break;
    }
    // silent end with unacknowledged data
    if (!f.fin[0] && !f.fin[1] && !f.rst[0] && !f.rst[1]) {
      for (let d = 0; d < 2; d++) {
        const x = st[d], y = st[1 - d];
        if (x.maxEnd > 0 && y.highAck >= 0 && x.maxEnd > y.highAck && x.dataSegs > 0 && capEnd - S.ts[f.last] >= Math.max(3, 10 * (rttEst || 0.3))) {
          add({ id: 'end.silent', sev: 'warning', conf: 'low', cat: 'network', side: 'path', dir: d, pkts: [P(f.last)], m: { sender: sideName(d), bytes: x.maxEnd - y.highAck, idle: ms(capEnd - S.ts[f.last]) }, t: S.ts[f.last] });
        }
      }
    }
    // capture-point evidence for this connection
    if (hsA !== null && hsB !== null && hsA + hsB > 0) ctx.point.push({ conn: f.id, a: hsA, b: hsB, basis: 'handshake' });
    else if (minRtt[0] !== null && minRtt[1] !== null && minRtt[0] + minRtt[1] > 0) ctx.point.push({ conn: f.id, a: minRtt[0], b: minRtt[1], basis: 'data' });
    for (let d = 0; d < 2; d++) { const m = modeOf(st[d].ttl); if (m > 0) ctx.ttl.push({ side: d, ttl: m, conn: f.id }); }
    if (!f.synSeen && !f.synAckSeen && (st[0].dataSegs + st[1].dataSegs) > 0) ctx.noHandshake.push(f.id);
    if ((f.pkts[0] === 0 || f.pkts[1] === 0) && (f.pkts[0] + f.pkts[1]) >= 10) ctx.oneWay.push(f.id);
    return out;
  }
  function hadFin() { return false; }
  function finBefore(S, f, idx) { for (let i = f.head; i !== -1 && i < idx; i = S.next[i]) if (S.tfl[i] & 1) return true; return false; }
  function prevPktTime(S, f, idx, d) { let last = S.ts[f.first]; for (let i = f.head; i !== -1 && i < idx; i = S.next[i]) if (S.dir[i] === d) last = S.ts[i]; return last; }
  function relOf(S, f, i, d) { return ((S.seq[i] - f.base[d]) | 0) >>> 0; }

  // ---------- capture point ----------
  function estimatePoint(ctx) {
    const pts = ctx.point;
    if (!pts.length) {
      const local = ctx.ttl.filter((e) => e.ttl === 64 || e.ttl === 128 || e.ttl === 255);
      return { pos: 'unknown', conf: 'low', n: 0, basis: 'none', share: null };
    }
    const shares = pts.map((p) => p.a / (p.a + p.b)); // share of the RTT between capture point and server
    const s = median(shares);
    const spread = pct(shares, 0.9) - pct(shares, 0.1);
    const clear = th('pointClear');
    let pos = s >= clear ? 'client' : s <= 1 - clear ? 'server' : 'middle';
    const hsN = pts.filter((p) => p.basis === 'handshake').length;
    let conf = hsN >= 3 && spread < 0.2 ? 'high' : hsN >= 1 ? 'medium' : 'low';
    // TTL check: packets from the side next to the capture point keep their initial TTL
    const sideTtl = (sd) => ctx.ttl.filter((e) => e.side === sd).map((e) => e.ttl);
    const untouched = (arr) => arr.length && arr.every((v) => v === 64 || v === 128 || v === 255);
    const ttlHint = untouched(sideTtl(0)) && !untouched(sideTtl(1)) ? 'client' : untouched(sideTtl(1)) && !untouched(sideTtl(0)) ? 'server' : null;
    if (ttlHint && ttlHint === pos && conf === 'medium') conf = 'high';
    if (ttlHint && pos !== 'middle' && ttlHint !== pos) conf = 'low';
    return { pos, conf, n: pts.length, basis: hsN ? 'handshake' : 'data', share: Math.round(s * 100) / 100, spread: Math.round(spread * 100) / 100, ttlHint };
  }

  // ---------- whole-capture analysis ----------
  function analyze(store, info) {
    const S = store.S;
    const findings = [];
    const P = (i) => i + 1;
    const capStart = 0, capEnd = S.n ? S.ts[S.n - 1] : 0;
    const icmpByFlow = new Map();
    for (const e of S.icmp) if (e.flow >= 0) { if (!icmpByFlow.has(e.flow)) icmpByFlow.set(e.flow, []); icmpByFlow.get(e.flow).push(e); }
    const ctx = { capEnd, icmpByFlow, notes: new Set(), needSecond: new Set(), point: [], ttl: [], capLoss: [], keepalives: [], zwps: [], overMss: [], noHandshake: [], oneWay: [], lossWhere: [], icmpUsed: new Set(), hsRtt: null };
    const tcp = S.flows.filter((f) => f.proto === 'tcp');
    const udp = S.flows.filter((f) => f.proto === 'udp');
    for (const f of tcp) {
      const fs = analyzeTcp(S, f, ctx);
      pushAll(findings, fs);
    }
    // ----- DNS -----
    const dns = S.dns.filter((q) => q.q >= 0);
    const answered = dns.filter((q) => q.resp >= 0);
    for (const q of answered) q.rt = q.tr - q.t;
    const slowQ = answered.filter((q) => q.rt * 1000 >= th('dnsSlowMs'));
    if (slowQ.length) {
      findings.push({ id: 'dns.slow', sev: 'warning', conf: answered.length >= 3 ? 'high' : 'medium', cat: 'server', side: 'server', pkts: limitList(slowQ.flatMap((q) => [P(q.q), P(q.resp)]), 30), m: { n: slowQ.length, of: answered.length, max: ms(maxOf(slowQ.map((q) => q.rt))), median: ms(median(answered.map((q) => q.rt))), server: slowQ[0].server, name: slowQ[0].name }, t: S.ts[slowQ[0].q], filter: 'dns.time >= ' + th('dnsSlowMs') / 1000, frames: framesFilter(slowQ.flatMap((q) => [P(q.q), P(q.resp)])) });
    }
    const unans = dns.filter((q) => q.resp < 0 && capEnd - q.t >= th('dnsTimeoutS'));
    if (unans.length) {
      const pk = unans.flatMap((q) => [P(q.q)].concat(q.retries.map(P)));
      findings.push({ id: 'dns.unanswered', sev: 'warning', conf: 'medium', cat: 'network', side: 'path', pkts: limitList(pk, 30), m: { n: unans.length, of: dns.length, server: unans[0].server, name: unans[0].name, retries: unans.reduce((a, q) => a + q.retries.length, 0) }, t: unans[0].t, filter: 'dns.flags.response==0 && !dns.response_in', frames: framesFilter(pk) });
    }
    const unansShort = dns.filter((q) => q.resp < 0 && capEnd - q.t < th('dnsTimeoutS'));
    if (unansShort.length) ctx.notes.add('dnsTooShort');
    const byRc = (rc) => answered.filter((q) => q.rcode === rc);
    const sf = byRc(2).concat(byRc(5));
    if (sf.length) findings.push({ id: 'dns.servfail', sev: 'warning', conf: 'high', cat: 'server', side: 'server', pkts: limitList(sf.map((q) => P(q.resp)), 30), m: { n: sf.length, rc: sf[0].rc, name: sf[0].name, server: sf[0].server }, t: S.ts[sf[0].resp], filter: 'dns.flags.rcode==2 || dns.flags.rcode==5', frames: framesFilter(sf.map((q) => P(q.resp))) });
    const nx = byRc(3);
    if (nx.length) findings.push({ id: 'dns.nxdomain', sev: 'info', conf: 'high', cat: 'client', side: 'client', pkts: limitList(nx.map((q) => P(q.resp)), 30), m: { n: nx.length, name: nx[0].name, names: Array.from(new Set(nx.map((q) => q.name))).slice(0, 5).join(', ') }, t: S.ts[nx[0].resp], filter: 'dns.flags.rcode==3', frames: framesFilter(nx.map((q) => P(q.resp))) });
    // ----- TLS -----
    for (const f of tcp) {
      const tl = f.tls;
      if (!tl) continue;
      const rtt = f.analysis.rttEst || 0;
      if (tl.ch !== undefined && tl.appC !== undefined) {
        tl.dur = S.ts[tl.appC] - tl.chT;
        if (tl.dur * 1000 >= th('tlsSlowMs') && tl.dur >= 4 * rtt) {
          findings.push({ conn: f.id, id: 'tls.slow', sev: 'warning', conf: 'medium', cat: 'server', side: 'server', pkts: [P(tl.ch), tl.sh !== undefined ? P(tl.sh) : null, P(tl.appC)].filter(Boolean), m: { dur: ms(tl.dur), sh: tl.sh !== undefined ? ms(tl.shT - tl.chT) : null, rtt: rtt ? ms(rtt) : null, sni: tl.sni || '' }, t: tl.chT, filter: '(' + connFilter(S, f) + ') && tls.handshake', frames: framesFilter([P(tl.ch), P(tl.appC)]) });
        }
      } else if (tl.ch !== undefined && tl.sh !== undefined) tl.dur = tl.shT - tl.chT;
      const fatal = tl.alerts.filter((a) => !a.enc && a.level === 2);
      if (fatal.length) {
        const a = fatal[0];
        findings.push({ conn: f.id, id: 'tls.alert', sev: 'critical', conf: 'high', cat: a.dir === 1 ? 'server' : 'client', side: sideName(a.dir), pkts: fatal.map((x) => P(x.pkt)).concat(tl.ch !== undefined ? [P(tl.ch)] : []), m: { from: sideName(a.dir), alert: a.name, code: a.desc, sni: tl.sni || '', offered: tl.offered || '' }, t: S.ts[a.pkt], filter: '(' + connFilter(S, f) + ') && tls.alert_message', frames: framesFilter(fatal.map((x) => P(x.pkt))) });
      }
    }
    // ----- ICMP -----
    const icmpGroups = new Map();
    for (const e of S.icmp) {
      if (e.used) continue;
      const isUnreach = e.v6 ? e.type === 1 : e.type === 3 && e.code !== 4;
      const isTtl = e.v6 ? e.type === 3 : e.type === 11;
      const isPtb = e.mtu !== undefined;
      if (!isUnreach && !isTtl && !isPtb) continue;
      const k = (isTtl ? 'ttl' : isPtb ? 'ptb' : 'un') + '|' + e.type + '|' + e.code + '|' + e.from;
      if (!icmpGroups.has(k)) icmpGroups.set(k, []);
      icmpGroups.get(k).push(e);
    }
    for (const [k, list] of icmpGroups) {
      const e = list[0];
      const kind = k.split('|')[0];
      const flows = Array.from(new Set(list.map((x) => x.flow).filter((x) => x >= 0)));
      const fromDst = e.inner && e.from === e.inner.dst; // the destination host itself answered
      const portUn = (e.v6 && e.type === 1 && e.code === 4) || (!e.v6 && e.type === 3 && e.code === 3);
      const id = kind === 'ttl' ? 'icmp.ttl' : kind === 'ptb' ? 'mtu.icmp_ptb' : 'icmp.unreach';
      const cat = portUn && fromDst ? 'server' : 'network';
      const desc = PA.analyze && false ? '' : (S.info.get(e.pkt) || '');
      findings.push({ conn: flows.length === 1 ? flows[0] : undefined, id, sev: 'warning', conf: flows.length ? 'high' : 'medium', cat, side: cat === 'server' ? 'server' : 'path', pkts: limitList(list.map((x) => P(x.pkt)), 30), m: { n: list.length, from: e.from, type: e.type, code: e.code, v6: e.v6 ? 1 : 0, desc: desc.replace(/ for .*$/, ''), target: e.inner ? e.inner.dst + (e.inner.dport !== undefined ? ':' + e.inner.dport : '') : '', flows: flows.length, mtu: e.mtu, portUn: portUn ? 1 : 0, fromDst: fromDst ? 1 : 0 }, t: e.t, filter: e.v6 ? 'icmpv6.type==' + e.type : 'icmp.type==' + e.type + ' && icmp.code==' + e.code, frames: framesFilter(list.map((x) => P(x.pkt))) });
    }
    // ----- UDP / QUIC -----
    const quic = udp.filter((f) => f.quic);
    if (quic.length) findings.push({ id: 'udp.quic', sev: 'info', conf: 'high', cat: 'none', side: 'none', pkts: quic.slice(0, 10).map((f) => P(f.head)), m: { n: quic.length, pkts: quic.reduce((a, f) => a + f.pkts[0] + f.pkts[1], 0) }, t: S.ts[quic[0].head], filter: 'quic', frames: '' });
    const otherUdp = udp.filter((f) => !f.quic && f.app !== 'DNS' && f.app !== 'mDNS');
    if (otherUdp.length) findings.push({ id: 'udp.other', sev: 'info', conf: 'high', cat: 'none', side: 'none', pkts: otherUdp.slice(0, 10).map((f) => P(f.head)), m: { n: otherUdp.length, apps: Array.from(new Set(otherUdp.map((f) => f.app || 'UDP/' + f.sp))).slice(0, 6).join(', ') }, t: S.ts[otherUdp[0].head], filter: 'udp && !dns && !quic', frames: '' });
    // ----- capture caveats -----
    if (ctx.capLoss.length) {
      const bytes = ctx.capLoss.reduce((a, c) => a + c.bytes, 0);
      const pk = ctx.capLoss.flatMap((c) => c.pkts).map(P);
      findings.push({ id: 'capture.loss', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: limitList(pk, 30), m: { bytes, conns: ctx.capLoss.length, gaps: pk.length }, t: 0, filter: 'tcp.analysis.ack_lost_segment || tcp.analysis.lost_segment', frames: framesFilter(pk) });
    }
    if (ctx.overMss.length) {
      const n = ctx.overMss.reduce((a, c) => a + c.n, 0);
      findings.push({ id: 'capture.offload_tso', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: limitList(ctx.overMss.flatMap((c) => c.pkts), 20).map(P), m: { n, max: maxOf(ctx.overMss.map((c) => c.max)), mss: ctx.overMss[0].mss || '?' }, t: 0, filter: 'tcp.len > ' + (ctx.overMss[0].mss || 1460), frames: '' });
    }
    if (S.stats.badCsum) {
      const hosts = new Map();
      for (let i = 0; i < S.n; i++) if (S.marks[i] & M.BADCSUM) { const a = S.addrs[S.srcA[i]]; hosts.set(a, (hosts.get(a) || 0) + 1); }
      const list = Array.from(hosts.keys());
      const pk = []; for (let i = 0; i < S.n && pk.length < 20; i++) if (S.marks[i] & M.BADCSUM) pk.push(P(i));
      findings.push({ id: 'capture.offload_csum', sev: 'info', conf: list.length === 1 ? 'high' : 'medium', cat: 'capture', side: 'capture', pkts: pk, m: { n: S.stats.badCsum, hosts: list.length, host: list[0] }, t: 0, filter: 'tcp.checksum.status==2 || udp.checksum.status==2', frames: '' });
    }
    if (S.stats.snap) findings.push({ id: 'capture.snaplen', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: [1], m: { n: S.stats.snap, snaplen: info.snaplen }, t: 0, filter: 'frame.cap_len < frame.len', frames: '' });
    if (ctx.noHandshake.length) findings.push({ id: 'capture.no_handshake', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: ctx.noHandshake.slice(0, 10).map((id) => P(S.flows[id].head)), m: { n: ctx.noHandshake.length, of: tcp.length }, t: 0, filter: 'tcp.flags.syn==1', frames: '' });
    if (ctx.keepalives.length || ctx.zwps.length) findings.push({ id: 'capture.keepalive', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: limitList(ctx.keepalives.concat(ctx.zwps), 20).map(P), m: { ka: ctx.keepalives.length, zwp: ctx.zwps.length }, t: 0, filter: 'tcp.analysis.keep_alive || tcp.analysis.zero_window_probe', frames: '' });
    if (ctx.oneWay.length) findings.push({ id: 'capture.one_way', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: ctx.oneWay.slice(0, 10).map((id) => P(S.flows[id].head)), m: { n: ctx.oneWay.length }, t: 0, filter: '', frames: '' });
    if (S.stats.frags) findings.push({ id: 'capture.fragments', sev: 'info', conf: 'high', cat: 'none', side: 'none', pkts: firstMarked(S, M.FRAG, 10).map(P), m: { n: S.stats.frags, reasm: S.stats.reasm }, t: 0, filter: 'ip.flags.mf==1 || ip.frag_offset>0 || ipv6.fragment', frames: '' });
    for (const w of info.warnings) findings.push({ id: 'capture.parse', sev: 'info', conf: 'high', cat: 'capture', side: 'capture', pkts: w.params.packet ? [w.params.packet] : [], m: Object.assign({ code: w.code }, w.params), t: 0, filter: '', frames: '' });

    // ----- capture point and verdict -----
    const point = estimatePoint(ctx);
    const result = { findings: [], verdict: null, point };
    const SEVO = { critical: 0, warning: 1, info: 2 };
    const CONFO = { high: 0, medium: 1, low: 2 };
    findings.forEach((f, k) => { f.n = k; });
    findings.sort((a, b) => SEVO[a.sev] - SEVO[b.sev] || CONFO[a.conf] - CONFO[b.conf] || a.t - b.t);
    findings.forEach((f, k) => { f.n = k; f.pkts = (f.pkts || []).filter((p) => p !== null && p !== undefined); });
    result.findings = findings;

    const score = { network: 0, client: 0, server: 0 };
    for (const f of findings) if (f.sev !== 'info' && score[f.cat] !== undefined) score[f.cat] += C.SEV[f.sev] * C.CONF[f.conf];
    const ranked = Object.entries(score).sort((a, b) => b[1] - a[1]);
    const tcpData = tcp.reduce((a, f) => a + (f.analysis ? f.analysis.st[0].dataSegs + f.analysis.st[1].dataSegs : 0), 0);
    const missing = [];
    if (S.n < th('minPacketsForVerdict')) missing.push('fewPackets');
    if (info.duration < th('minDurationS')) missing.push('short');
    if (!tcp.length && !dns.length) missing.push('noTcp');
    else if (tcp.length && !tcpData && !dns.length) missing.push('noData');
    if (tcp.length && ctx.noHandshake.length === tcp.length) missing.push('noHandshake');
    if (ctx.oneWay.length && ctx.oneWay.length === tcp.filter((f) => f.pkts[0] + f.pkts[1] >= 10).length) missing.push('oneWay');
    if (point.pos === 'unknown' && tcp.length) missing.push('point');
    if (ctx.notes.has('synTooShort')) missing.push('synTooShort');
    if (ctx.notes.has('dnsTooShort')) missing.push('dnsTooShort');
    const problems = findings.filter((f) => f.sev !== 'info' && score[f.cat] !== undefined);
    let verdict;
    const thin = missing.includes('fewPackets') || missing.includes('noTcp') || missing.includes('noData') || missing.includes('oneWay') || missing.includes('short');
    if (!problems.length) {
      verdict = thin ? 'inconclusive' : 'clean';
    } else if (ranked[0][1] < C.verdict.minScore) {
      verdict = 'inconclusive';
      missing.push('weakEvidence');
    } else if (ranked[1][1] > 0 && ranked[0][1] < C.verdict.dominance * ranked[1][1]) {
      verdict = 'mixed';
    } else verdict = ranked[0][0];
    let vconf = 'medium';
    if (verdict === 'network' || verdict === 'client' || verdict === 'server') {
      const top = problems.filter((f) => f.cat === verdict);
      vconf = top.some((f) => f.conf === 'high') ? 'high' : 'medium';
      if (thin) vconf = 'low';
      if (verdict === 'network' && point.pos === 'unknown' && top.every((f) => f.id !== 'mtu.blackhole' && f.id !== 'hs.syn_unanswered')) vconf = vconf === 'high' ? 'medium' : vconf;
    } else if (verdict === 'clean') vconf = missing.length ? 'medium' : 'high';
    else if (verdict === 'inconclusive') vconf = 'low';
    // second capture advice
    const second = [];
    if (ctx.needSecond.has('syn')) second.push('syn');
    if (ctx.needSecond.has('rst')) second.push('rst');
    if (problems.some((f) => f.id === 'tcp.loss') && (point.pos === 'middle' || point.pos === 'unknown')) second.push('loss');
    if (verdict === 'mixed' || verdict === 'inconclusive') second.push('general');
    const checks = checksRun(tcp, dns, S);
    result.verdict = { v: verdict, conf: vconf, score: { network: r2(score.network), client: r2(score.client), server: r2(score.server) }, missing: Array.from(new Set(missing)), second: Array.from(new Set(second)), checks, lossWhere: ctx.lossWhere };

    // ----- connection summaries -----
    const byConn = new Map();
    for (const x of findings) if (x.conn !== undefined) { if (!byConn.has(x.conn)) byConn.set(x.conn, []); byConn.get(x.conn).push(x); }
    const conns = S.flows.map((f) => connSummary(S, f, byConn.get(f.id) || []));
    result.conns = conns;
    result.summary = {
      packets: S.n, bytes: info.bytes, duration: info.duration, format: info.format, linktypes: Object.keys(info.linktypes).map((k) => ({ lt: +k, name: PA.parser.LINK_NAMES[k] || 'DLT ' + k, n: info.linktypes[k] })),
      snaplen: info.snaplen, tsPrecision: info.tsPrecision, firstTs: info.firstTs,
      tcpConns: tcp.length, udpFlows: udp.length, dnsQueries: dns.length, tlsConns: tcp.filter((f) => f.tls).length, quic: quic.length,
      stats: S.stats, kinds: S.stats.kinds, icmp: S.icmp.length,
    };
    result.dns = { queries: dns.length, answered: answered.length, median: answered.length ? ms(median(answered.map((q) => q.rt))) : null, list: dns.slice(0, 500).map((q) => ({ name: q.name, type: q.qtype, server: q.server, q: P(q.q), r: q.resp >= 0 ? P(q.resp) : null, rt: q.resp >= 0 ? ms(q.rt) : null, rc: q.resp >= 0 ? q.rc : null })) };
    result.tls = tcp.filter((f) => f.tls).slice(0, 500).map((f) => ({ conn: f.id, sni: f.tls.sni || null, version: f.tls.version || null, dur: f.tls.dur !== undefined ? ms(f.tls.dur) : null, alerts: f.tls.alerts.map((a) => a.name) }));
    // names for anonymisation
    result.anon = { addrs: S.addrs.slice(), macs: Array.from(S.macs.keys()), names: Array.from(S.names) };
    result.thresholds = Object.fromEntries(Object.entries(C.T).map(([k, v]) => [k, v.v]));
    return result;
  }
  const r2 = (v) => Math.round(v * 100) / 100;
  function firstMarked(S, bit, n) { const out = []; for (let i = 0; i < S.n && out.length < n; i++) if (S.marks[i] & bit) out.push(i); return out; }
  function checksRun(tcp, dns, S) {
    const c = [];
    if (tcp.length) c.push('handshake', 'loss', 'window', 'app', 'rtt', 'mtu', 'end');
    if (dns.length) c.push('dns');
    if (tcp.some((f) => f.tls)) c.push('tls');
    if (S.icmp.length) c.push('icmp');
    return c;
  }
  function connSummary(S, f, findings) {
    const fs = findings; // already the findings of this connection
    const SEVR = { critical: 3, warning: 2, info: 1 };
    const worst = fs.reduce((a, x) => Math.max(a, SEVR[x.sev]), 0);
    const a = f.analysis;
    return {
      id: f.id, proto: f.proto, l3: f.l3, client: S.addrs[f.c], cport: f.cp, server: S.addrs[f.s], sport: f.sp,
      app: f.app || (f.proto === 'tcp' ? 'TCP' : 'UDP'), sni: f.tls ? f.tls.sni : null, host: f.http ? f.http.host : null,
      pkts: f.pkts[0] + f.pkts[1], bytes: f.bytes[0] + f.bytes[1], payload: f.payload.slice(), start: S.ts[f.first], end: S.ts[f.last],
      first: f.first + 1, last: f.last + 1,
      hsRtt: a && a.hsRtt !== null ? ms(a.hsRtt) : null, rtt: a && a.rttEst ? ms(a.rttEst) : null,
      retrans: a ? a.st[0].retrans.length + a.st[1].retrans.length : 0,
      syn: f.synSeen, ws: f.wsKnown ? (f.wsActive ? f.hs.ws.slice() : 'off') : null, mss: f.hs ? f.hs.mss.slice() : null,
      sev: worst === 3 ? 'critical' : worst === 2 ? 'warning' : worst === 1 ? 'info' : 'ok',
      findings: fs.map((x) => x.n), filter: connFilter(S, f), tcpStream: f.tcpIndex, udpStream: f.udpIndex,
      vlan: f.vlan,
    };
  }

  // ---------- packet list ----------
  const FL = ['FIN', 'SYN', 'RST', 'PSH', 'ACK', 'URG', 'ECE', 'CWR'];
  const MARK_TXT = [[M.SPURIOUS, 'Spurious Retransmission'], [M.FAST, 'Fast Retransmission'], [M.TAIL, 'Tail-loss RTO Retransmission'], [M.RTO, 'RTO Retransmission'], [M.RETRANS, 'Retransmission'], [M.OOO, 'Out-Of-Order'], [M.DUPACK, 'Dup ACK'], [M.ZEROWIN, 'ZeroWindow'], [M.ZWP, 'ZeroWindowProbe'], [M.WINFULL, 'Window Full'], [M.WINUPD, 'Window Update'], [M.KEEPALIVE, 'Keep-Alive'], [M.PREVLOST, 'Previous segment not captured'], [M.ACKUNSEEN, 'ACKed unseen segment'], [M.OVERMSS, 'Larger than MSS (TSO/GRO)'], [M.BADCSUM, 'Bad checksum (offload?)'], [M.SNAP, 'Truncated by snaplen']];
  function protoLabel(S, i) {
    const k = S.kind[i];
    const fid = S.flow[i];
    const f = fid >= 0 ? S.flows[fid] : null;
    if (k === KIND.TCP) { if (f && f.app === 'TLS' && S.plen[i] > 0) return 'TLS'; if (f && f.app === 'HTTP' && S.plen[i] > 0) return 'HTTP'; return 'TCP'; }
    if (k === KIND.UDP) return f && f.app ? f.app : 'UDP';
    return ['Other', 'TCP', 'UDP', 'ICMP', 'ICMPv6', 'ARP', 'IP frag'][k];
  }
  function sevClass(mk) {
    if (mk & (M.RETRANS | M.ZEROWIN)) return 'bad';
    if (mk & (M.DUPACK | M.OOO | M.WINFULL | M.PREVLOST | M.ZWP)) return 'warn';
    if (mk & (M.KEY)) return 'key';
    if (mk & (M.ACKUNSEEN | M.OVERMSS | M.BADCSUM | M.SNAP | M.KEEPALIVE | M.WINUPD | M.LOSTCAP)) return 'note';
    return '';
  }
  function rowOf(S, i) {
    const k = S.kind[i];
    let info = S.info.get(i) || '';
    const fid = S.flow[i];
    const mk = S.marks[i];
    if (k === KIND.TCP && fid >= 0) {
      const f = S.flows[fid];
      const d = S.dir[i];
      const fl = S.tfl[i];
      const names = []; for (let b = 0; b < 8; b++) if (fl & (1 << b)) names.push(FL[b]);
      const base = f.base ? f.base[d] : null, abase = f.base ? f.base[1 - d] : null;
      const sq = base !== null ? ((S.seq[i] - base) >>> 0) : S.seq[i];
      const ak = abase !== null ? ((S.ack[i] - abase) >>> 0) : S.ack[i];
      const tags = []; for (const [bit, txt] of MARK_TXT) if (mk & bit) { if (bit === M.RETRANS && (mk & (M.FAST | M.RTO | M.SPURIOUS))) continue; if (bit === M.RTO && (mk & M.TAIL)) continue; tags.push(txt); }
      const tcpTxt = S.sport[i] + ' → ' + S.dport[i] + ' [' + names.join(', ') + '] Seq=' + sq + ((fl & 16) ? ' Ack=' + ak : '') + ' Win=' + S.win[i] + ' Len=' + S.plen[i];
      info = (tags.length ? '[' + tags.join('] [') + '] ' : '') + (info ? info + '  ·  ' : '') + tcpTxt;
    } else if (k === KIND.UDP && !info) info = S.sport[i] + ' → ' + S.dport[i] + ' Len=' + S.plen[i];
    if (!info && S.kind[i] === KIND.OTHER) info = 'Not decoded';
    return { no: i + 1, t: S.ts[i], src: S.srcA[i] >= 0 ? S.addrs[S.srcA[i]] : '', dst: S.dstA[i] >= 0 ? S.addrs[S.dstA[i]] : '', proto: protoLabel(S, i), len: S.len[i], info, cls: sevClass(mk), conn: fid };
  }
  // index of packets for a filter: { conn } or null = all
  function packetIndex(S, conn) {
    if (conn === null || conn === undefined || conn < 0) return null;
    const f = S.flows[conn];
    const out = [];
    for (let i = f.head; i !== -1; i = S.next[i]) out.push(i);
    // ICMP errors that refer to this flow
    for (const e of S.icmp) if (e.flow === conn) out.push(e.pkt);
    out.sort((a, b) => a - b);
    return Int32Array.from(out);
  }

  // ---------- chart series ----------
  function series(S, conn) {
    const f = S.flows[conn];
    if (!f || f.proto !== 'tcp') return null;
    const a = f.analysis;
    const dirs = [0, 1].map(() => ({ seg: [], ack: [], win: [], tput: [], rtt: [] }));
    const unw = [{ last: null, rel: 0 }, { last: null, rel: 0 }];
    const ua = [{ last: null, rel: 0 }, { last: null, rel: 0 }];
    const rel = (u, raw, base) => { if (u.last === null) { u.last = raw; u.rel = ((raw - base) | 0); return u.rel; } const d = (raw - u.last) | 0; u.last = raw; u.rel += d; return u.rel; };
    const t0 = S.ts[f.first], t1 = S.ts[f.last];
    const bins = 120, bw = Math.max((t1 - t0) / bins, 1e-3);
    const tp = [new Float64Array(bins + 1), new Float64Array(bins + 1)];
    const scale = (d) => (f.wsActive ? f.hs.ws[d] : 0);
    const keys = [];
    for (let i = f.head; i !== -1; i = S.next[i]) {
      if (S.kind[i] !== KIND.TCP) continue;
      const d = S.dir[i], t = S.ts[i], mk = S.marks[i], fl = S.tfl[i];
      const base = f.base[d], abase = f.base[1 - d];
      if (base !== null) {
        const s = rel(unw[d], S.seq[i], base);
        if (S.plen[i] > 0) { dirs[d].seg.push(t, s, s + S.plen[i], mk, i + 1); tp[d][Math.min(bins, Math.floor((t - t0) / bw))] += S.plen[i]; }
      }
      if ((fl & 16) && abase !== null) {
        const ak = rel(ua[1 - d], S.ack[i], abase);
        const w = (fl & 2) ? S.win[i] : S.win[i] * Math.pow(2, scale(d));
        // ack line and window edge belong to the data direction they acknowledge
        dirs[1 - d].ack.push(t, ak, ak + w, mk, i + 1);
        dirs[1 - d].win.push(t, w, mk, i + 1);
      }
      if (mk & (M.RETRANS | M.ZEROWIN | M.KEY | M.OOO) || (fl & 4) || ((fl & 2) && !(fl & 16))) {
        if (keys.length < 400) keys.push({ t, no: i + 1, d, k: (fl & 4) ? 'rst' : (fl & 2) ? 'syn' : (mk & M.RETRANS) ? 'retrans' : (mk & M.ZEROWIN) ? 'zw' : (mk & M.OOO) ? 'ooo' : 'key' });
      }
    }
    for (let d = 0; d < 2; d++) {
      for (let b = 0; b <= bins; b++) dirs[d].tput.push(t0 + b * bw, tp[d][b] * 8 / bw);
      for (const s of (f.rttSamples || [[], []])[d]) dirs[d].rtt.push(s.t, s.v, s.seg + 1);
    }
    // thin out very large series for drawing; keep marked points
    for (const D of dirs) {
      if (D.seg.length / 5 > 40000) D.seg = thin(D.seg, 5, 40000);
      if (D.ack.length / 5 > 40000) D.ack = thin(D.ack, 5, 40000);
      if (D.win.length / 4 > 20000) D.win = thin(D.win, 4, 20000);
      if (D.rtt.length / 3 > 20000) D.rtt = thin(D.rtt, 3, 20000);
    }
    return { conn, t0, t1, dirs, keys, ws: f.wsKnown ? (f.wsActive ? f.hs.ws : 'off') : null, mss: f.hs ? f.hs.mss : null };
  }
  function thin(arr, stride, max) {
    const n = arr.length / stride;
    const step = Math.ceil(n / max);
    const out = [];
    for (let k = 0; k < n; k++) {
      const marked = stride >= 4 && (arr[k * stride + (stride === 5 ? 3 : 2)] & (M.RETRANS | M.ZEROWIN | M.OOO | M.DUPACK));
      if (k % step === 0 || marked) for (let j = 0; j < stride; j++) out.push(arr[k * stride + j]);
    }
    return out;
  }

  PA.analyze = { analyze, rowOf, packetIndex, series, connFilter, estimatePoint, spearman };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.analyze;
})(typeof globalThis !== 'undefined' ? globalThis : self);
