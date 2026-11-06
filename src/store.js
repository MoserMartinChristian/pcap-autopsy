/*
 * PCAP Autopsy – packet store.
 * Keeps one compact row per packet in typed arrays (about 60 bytes per packet), groups packets
 * into flows, and extracts the few application facts the analysis needs (DNS, TLS, HTTP, QUIC).
 * Payload bytes are never kept.
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  const KIND = { OTHER: 0, TCP: 1, UDP: 2, ICMP: 3, ICMP6: 4, ARP: 5, FRAG: 6 };
  // per-packet marks (bit flags), set by the store (parse facts) and by the analysis (TCP events)
  const M = {
    SNAP: 1 << 0, BADCSUM: 1 << 1, FRAG: 1 << 2, RETRANS: 1 << 3, FAST: 1 << 4, RTO: 1 << 5, SPURIOUS: 1 << 6,
    DUPACK: 1 << 7, OOO: 1 << 8, ZEROWIN: 1 << 9, WINFULL: 1 << 10, ZWP: 1 << 11, KEEPALIVE: 1 << 12,
    WINUPD: 1 << 13, PREVLOST: 1 << 14, ACKUNSEEN: 1 << 15, SACK: 1 << 16, OVERMSS: 1 << 17, TAIL: 1 << 18,
    KEY: 1 << 19, REASM: 1 << 20, DECODEERR: 1 << 21, IPV6: 1 << 22, VLAN: 1 << 23, KAACK: 1 << 24, LOSTCAP: 1 << 25,
  };

  function growF64(a, n) { const b = new Float64Array(n); b.set(a); return b; }
  function grow(a, n) { const b = new a.constructor(n); b.set(a); return b; }

  function createStore() {
    let cap = 1 << 14;
    const S = {
      n: 0,
      ts: new Float64Array(cap), len: new Uint32Array(cap), caplen: new Uint32Array(cap),
      flow: new Int32Array(cap), dir: new Uint8Array(cap), kind: new Uint8Array(cap),
      tfl: new Uint16Array(cap), seq: new Uint32Array(cap), ack: new Uint32Array(cap), win: new Uint32Array(cap),
      plen: new Uint32Array(cap), ttl: new Uint8Array(cap), marks: new Uint32Array(cap), next: new Int32Array(cap),
      srcA: new Int32Array(cap), dstA: new Int32Array(cap), sport: new Uint16Array(cap), dport: new Uint16Array(cap),
      info: new Map(), sack: new Map(), opts: new Map(),
      addrs: [], addrMap: new Map(), macs: new Map(),
      flows: [], flowMap: new Map(),
      dns: [], dnsPending: new Map(), icmp: [], names: new Set(),
      stats: { kinds: [0, 0, 0, 0, 0, 0, 0], ipv4: 0, ipv6: 0, vlan: 0, frags: 0, reasm: 0, snap: 0, badCsum: 0, decodeErr: 0, nonIp: 0, tcpConns: 0, udpFlows: 0 },
    };
    function ensure() {
      if (S.n < cap) return;
      cap *= 2;
      S.ts = growF64(S.ts, cap);
      for (const k of ['len', 'caplen', 'flow', 'dir', 'kind', 'tfl', 'seq', 'ack', 'win', 'plen', 'ttl', 'marks', 'next', 'srcA', 'dstA', 'sport', 'dport']) S[k] = grow(S[k], cap);
    }
    function addr(a) {
      if (a === undefined) return -1;
      let i = S.addrMap.get(a);
      if (i === undefined) { i = S.addrs.length; S.addrs.push(a); S.addrMap.set(a, i); }
      return i;
    }

    function newFlow(proto, key, cIdx, cPort, sIdx, sPort, i) {
      const f = {
        id: S.flows.length, proto, key, c: cIdx, cp: cPort, s: sIdx, sp: sPort,
        first: i, last: i, head: i, tail: i, pkts: [0, 0], bytes: [0, 0], payload: [0, 0],
        synSeen: false, synAckSeen: false, isn: [null, null], macs: [null, null], vlan: null,
        app: null, tls: null, http: null, quic: false, fin: [false, false], rst: [false, false], dnsN: 0,
        tcpIndex: proto === 'tcp' ? S.stats.tcpConns++ : -1, udpIndex: proto === 'udp' ? S.stats.udpFlows++ : -1,
        l3: 4, stream: { buf: [null, null], next: [null, null], done: [false, false] },
      };
      S.flows.push(f);
      S.flowMap.set(key, f.id);
      return f;
    }

    // ---------- application parsing ----------
    function readName(d, o, depth) {
      const parts = [];
      let jumps = 0;
      while (o < d.length) {
        const l = d[o];
        if (l === 0) return [parts.join('.'), o + 1];
        if ((l & 0xc0) === 0xc0) {
          if (o + 1 >= d.length || ++jumps > 10) return [parts.join('.'), -1];
          const p = ((l & 0x3f) << 8) | d[o + 1];
          const [rest] = readName(d, p, (depth || 0) + 1);
          if (rest) parts.push(rest);
          return [parts.join('.'), o + 2];
        }
        if (o + 1 + l > d.length) return [parts.join('.'), -1];
        let s = '';
        for (let k = 0; k < l; k++) { const c = d[o + 1 + k]; s += c >= 33 && c < 127 ? String.fromCharCode(c) : '?'; }
        parts.push(s);
        o += 1 + l;
        if (depth > 5) break;
      }
      return [parts.join('.'), -1];
    }
    const QT = { 1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 64: 'SVCB', 65: 'HTTPS' };
    const RC = { 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' };
    function dns(i, pkt, d, toServer) {
      if (d.length < 12) return;
      const id = (d[0] << 8) | d[1];
      const qr = d[2] >> 7, rcode = d[3] & 15, qd = (d[4] << 8) | d[5], an = (d[6] << 8) | d[7];
      let name = '', qtype = 0;
      if (qd >= 1) { const r = readName(d, 12, 0); name = r[0]; if (r[1] > 0 && r[1] + 2 <= d.length) qtype = (d[r[1]] << 8) | d[r[1] + 1]; }
      if (name) S.names.add(name);
      const cl = qr ? pkt.dst + '|' + pkt.dport : pkt.src + '|' + pkt.sport;
      const key = cl + '|' + id + '|' + name.toLowerCase() + '|' + qtype;
      const qt = QT[qtype] || ('TYPE' + qtype);
      if (!qr) {
        let q = S.dnsPending.get(key);
        if (q && q.resp < 0) { q.retries.push(i); S.info.set(i, 'DNS query (retry) ' + qt + ' ' + name + ' id=0x' + id.toString(16)); return; }
        q = { id, name, qtype: qt, client: pkt.src, server: pkt.dst, q: i, t: S.ts[i], resp: -1, tr: 0, rcode: -1, an: 0, retries: [] };
        S.dnsPending.set(key, q); S.dns.push(q);
        S.info.set(i, 'DNS query ' + qt + ' ' + name + ' id=0x' + id.toString(16));
      } else {
        const q = S.dnsPending.get(key);
        const rc = RC[rcode] || ('RCODE' + rcode);
        S.info.set(i, 'DNS response ' + qt + ' ' + name + ' ' + rc + (an ? ' (' + an + ' answers)' : '') + ' id=0x' + id.toString(16));
        if (q && q.resp < 0) { q.resp = i; q.tr = S.ts[i]; q.rcode = rcode; q.rc = rc; q.an = an; }
        else if (!q) S.dns.push({ id, name, qtype: qt, client: pkt.dst, server: pkt.src, q: -1, t: S.ts[i], resp: i, tr: S.ts[i], rcode, rc, an, retries: [], orphan: true });
      }
    }
    const TLSV = { 0x0300: 'SSL 3.0', 0x0301: 'TLS 1.0', 0x0302: 'TLS 1.1', 0x0303: 'TLS 1.2', 0x0304: 'TLS 1.3' };
    const ALERTS = { 0: 'close_notify', 10: 'unexpected_message', 20: 'bad_record_mac', 40: 'handshake_failure', 42: 'bad_certificate', 43: 'unsupported_certificate', 44: 'certificate_revoked', 45: 'certificate_expired', 46: 'certificate_unknown', 47: 'illegal_parameter', 48: 'unknown_ca', 50: 'decode_error', 51: 'decrypt_error', 70: 'protocol_version', 71: 'insufficient_security', 80: 'internal_error', 86: 'inappropriate_fallback', 90: 'user_canceled', 109: 'missing_extension', 110: 'unsupported_extension', 112: 'unrecognized_name', 116: 'certificate_required', 120: 'no_application_protocol' };
    function parseHello(b, f, dir, i) {
      // b starts at a handshake message
      const type = b[0];
      const len = (b[1] << 16) | (b[2] << 8) | b[3];
      if (b.length < 4 + Math.min(len, 40)) return false;
      const end = Math.min(b.length, 4 + len);
      let o = 4;
      const legacy = (b[o] << 8) | b[o + 1]; o += 2 + 32;
      if (o >= end) return true;
      o += 1 + b[o]; // session id
      if (type === 1) { if (o + 2 > end) return true; o += 2 + ((b[o] << 8) | b[o + 1]); if (o >= end) return true; o += 1 + b[o]; }
      else { o += 3; }
      const t = f.tls;
      let ver = legacy, sni = null, alpn = null;
      if (o + 2 <= end) {
        const elen = (b[o] << 8) | b[o + 1]; o += 2;
        const eEnd = Math.min(end, o + elen);
        while (o + 4 <= eEnd) {
          const et = (b[o] << 8) | b[o + 1], el = (b[o + 2] << 8) | b[o + 3];
          const p = o + 4;
          if (et === 0 && type === 1 && p + 5 <= eEnd) {
            const nl = (b[p + 3] << 8) | b[p + 4];
            let s = ''; for (let k = 0; k < nl && p + 5 + k < eEnd; k++) s += String.fromCharCode(b[p + 5 + k]);
            sni = s;
          } else if (et === 43) {
            if (type === 2 && el === 2) ver = (b[p] << 8) | b[p + 1];
            else if (type === 1) { for (let k = 1; k + 1 < el + 1 && p + k + 1 < eEnd; k += 2) { const v = (b[p + k] << 8) | b[p + k + 1]; if (v === 0x0304) ver = Math.max(ver, v); } }
          } else if (et === 16 && p + 3 <= eEnd) {
            const l = b[p + 2]; let s = ''; for (let k = 0; k < l && p + 3 + k < eEnd; k++) s += String.fromCharCode(b[p + 3 + k]); alpn = s;
          }
          o = p + el;
        }
      }
      if (type === 1) {
        t.ch = i; t.chT = S.ts[i]; t.sni = sni; t.offered = TLSV[ver] || '0x' + ver.toString(16); t.alpn = alpn;
        if (sni) S.names.add(sni);
        S.info.set(i, 'TLS ClientHello' + (sni ? ' SNI=' + sni : ''));
      } else {
        t.sh = i; t.shT = S.ts[i]; t.version = TLSV[ver] || '0x' + ver.toString(16);
        S.info.set(i, 'TLS ServerHello ' + t.version);
      }
      return true;
    }
    // scan TLS records in a reassembled start-of-stream buffer
    function scanTls(f, dir, buf, i) {
      let o = 0;
      while (o + 5 <= buf.length) {
        const ct = buf[o], rl = (buf[o + 3] << 8) | buf[o + 4];
        if (ct < 20 || ct > 24 || buf[o + 1] !== 3) return 'bad';
        const body = buf.subarray(o + 5, Math.min(buf.length, o + 5 + rl));
        if (ct === 22 && (body[0] === 1 || body[0] === 2) && !(body[0] === 1 ? f.tls.ch !== undefined : f.tls.sh !== undefined)) {
          if (body.length < Math.min(rl, 4 + ((body[1] << 16) | (body[2] << 8) | body[3]))) return 'more';
          parseHello(body, f, dir, i);
        }
        if (o + 5 + rl > buf.length) return 'more';
        o += 5 + rl;
      }
      return 'ok';
    }
    function tlsSegment(i, f, dir, payload) {
      if (!payload || !payload.length) return;
      const t = f.tls;
      // alerts: plaintext alert records (TLS 1.2, or TLS 1.3 before encryption)
      if (payload[0] === 21 && payload.length >= 7 && payload[1] === 3) {
        const rl = (payload[3] << 8) | payload[4];
        const a = { pkt: i, dir, enc: rl !== 2, level: rl === 2 ? payload[5] : null, desc: rl === 2 ? payload[6] : null };
        a.name = a.enc ? 'encrypted alert' : (ALERTS[a.desc] || 'alert ' + a.desc);
        t.alerts.push(a);
        S.info.set(i, 'TLS Alert ' + (a.enc ? '(encrypted)' : (a.level === 2 ? 'fatal ' : 'warning ') + a.name));
        S.marks[i] |= M.KEY;
        return;
      }
      if ((payload[0] === 23 && payload[1] === 3) || (payload[0] === 20 && payload[1] === 3 && payload.length > 6 && payload[6] === 23)) {
        if (dir === 0 && t.sh !== undefined && t.appC === undefined) { t.appC = i; t.appCT = S.ts[i]; S.info.set(i, S.info.get(i) || 'TLS Application Data (handshake complete)'); }
        if (dir === 1 && t.appS === undefined && t.sh !== undefined) t.appS = i;
        if (!S.info.has(i)) S.info.set(i, 'TLS Application Data');
        return;
      }
      if (payload[0] === 20 && payload[1] === 3 && !S.info.has(i)) S.info.set(i, 'TLS ChangeCipherSpec');
    }
    function stream(i, f, dir, pkt) {
      const t = pkt.tcp;
      const p = t.payload;
      if (!p || !p.length) return;
      const st = f.stream;
      if (st.done[dir]) { if (f.tls) tlsSegment(i, f, dir, p); return; }
      // first payload of this direction decides the protocol
      if (!st.buf[dir]) {
        if (dir === 0 && !f.app) {
          if (p[0] === 22 && p[1] === 3 && p.length >= 6 && p[5] === 1) { f.app = 'TLS'; f.tls = { alerts: [] }; }
          else {
            let s = ''; for (let k = 0; k < Math.min(p.length, 200); k++) s += String.fromCharCode(p[k]);
            const m = /^(GET|POST|PUT|HEAD|DELETE|OPTIONS|PATCH|CONNECT) (\S+) HTTP\/1\.[01]\r?\n/.exec(s);
            if (m) {
              f.app = 'HTTP';
              const h = /\r?\nHost: *([^\r\n]+)/i.exec(s);
              f.http = { method: m[1], path: m[2], host: h ? h[1].trim() : null };
              if (f.http.host) S.names.add(f.http.host.replace(/:\d+$/, ''));
              S.info.set(i, 'HTTP ' + m[1] + ' ' + m[2]);
            }
            st.done[0] = true;
            return;
          }
        }
        if (!f.tls) { if (dir === 1 && f.app === 'HTTP') { let s = ''; for (let k = 0; k < Math.min(p.length, 40); k++) s += String.fromCharCode(p[k]); const m = /^HTTP\/1\.[01] (\d{3})[^\r\n]*/.exec(s); if (m) { S.info.set(i, m[0]); f.http.status = +m[1]; } } st.done[dir] = true; return; }
        st.buf[dir] = []; st.next[dir] = t.seq;
      }
      if (t.seq !== st.next[dir]) { if (((t.seq - st.next[dir]) | 0) < 0) return; st.done[dir] = true; tlsSegment(i, f, dir, p); return; }
      st.buf[dir].push(p.slice());
      st.next[dir] = (st.next[dir] + p.length) >>> 0;
      let tot = 0; for (const b of st.buf[dir]) tot += b.length;
      const buf = new Uint8Array(tot); let o = 0; for (const b of st.buf[dir]) { buf.set(b, o); o += b.length; }
      const r = scanTls(f, dir, buf, i);
      if (r !== 'more' || tot > 32768) { st.done[dir] = true; st.buf[dir] = null; if (st.buf[0] === null && st.buf[1] === null) {} tlsSegment(i, f, dir, p); }
    }

    // ---------- packet ingest ----------
    function add(pkt) {
      ensure();
      const i = S.n++;
      S.ts[i] = pkt.ts; S.len[i] = pkt.origLen; S.caplen[i] = pkt.capLen;
      S.flow[i] = -1; S.next[i] = -1; S.dir[i] = 0;
      S.ttl[i] = pkt.ttl || 0;
      let mk = 0;
      if (pkt.snap) { mk |= M.SNAP; S.stats.snap++; }
      if (pkt.csumBad) { mk |= M.BADCSUM; S.stats.badCsum++; }
      if (pkt.decodeError || pkt.l3bad || pkt.l4bad) { mk |= M.DECODEERR; S.stats.decodeErr++; }
      if (pkt.vlan) { mk |= M.VLAN; S.stats.vlan++; }
      if (pkt.l3 === 6) { mk |= M.IPV6; S.stats.ipv6++; } else if (pkt.l3 === 4) S.stats.ipv4++;
      else S.stats.nonIp++;
      if (pkt.reassembled) { mk |= M.REASM; S.stats.reasm++; }
      S.srcA[i] = addr(pkt.src); S.dstA[i] = addr(pkt.dst);
      S.sport[i] = pkt.sport || 0; S.dport[i] = pkt.dport || 0;
      if (pkt.macSrc && pkt.src) S.macs.set(pkt.macSrc, pkt.src);
      if (pkt.macDst && pkt.dst && !S.macs.has(pkt.macDst)) S.macs.set(pkt.macDst, pkt.dst);
      let kind = KIND.OTHER;
      if (pkt.l4 === 'tcp') kind = KIND.TCP; else if (pkt.l4 === 'udp') kind = KIND.UDP;
      else if (pkt.l4 === 'icmp') kind = KIND.ICMP; else if (pkt.l4 === 'icmp6') kind = KIND.ICMP6;
      else if (pkt.l4 === 'arp') kind = KIND.ARP; else if (pkt.l4 === 'frag') { kind = KIND.FRAG; mk |= M.FRAG; S.stats.frags++; }
      S.kind[i] = kind; S.stats.kinds[kind]++;
      S.marks[i] = mk;
      if (pkt.desc) S.info.set(i, pkt.desc);
      if (kind === KIND.FRAG) S.info.set(i, 'IPv' + pkt.l3 + ' fragment (offset ' + pkt.frag.off + (pkt.frag.mf ? ', more' : ', last') + ')');
      if (pkt.unsupportedLink) S.info.set(i, 'Unsupported link type ' + pkt.link);
      if ((kind === KIND.TCP && pkt.tcp) || (kind === KIND.UDP && pkt.udp)) flowPacket(i, pkt, kind);
      else if (kind === KIND.ICMP || kind === KIND.ICMP6) icmpPacket(i, pkt);
      else if (kind === KIND.TCP || kind === KIND.UDP) S.info.set(i, (kind === KIND.TCP ? 'TCP' : 'UDP') + ' header truncated');
    }

    function flowPacket(i, pkt, kind) {
      const proto = kind === KIND.TCP ? 'tcp' : 'udp';
      const sA = S.srcA[i], dA = S.dstA[i], sp = pkt.sport, dp = pkt.dport;
      const key = sA < dA || (sA === dA && sp <= dp) ? proto + sA + ':' + sp + '-' + dA + ':' + dp : proto + dA + ':' + dp + '-' + sA + ':' + sp;
      let fid = S.flowMap.get(key);
      let f = fid !== undefined ? S.flows[fid] : null;
      const t = pkt.tcp;
      if (t) {
        S.tfl[i] = t.flags; S.seq[i] = t.seq; S.ack[i] = t.ack; S.win[i] = t.win; S.plen[i] = t.payLen;
        const syn = (t.flags & 2) !== 0, ackf = (t.flags & 16) !== 0;
        if (t.opts.sack) { S.sack.set(i, t.opts.sack); S.marks[i] |= M.SACK; }
        if (syn) S.opts.set(i, { mss: t.opts.mss, ws: t.opts.ws, sackOk: !!t.opts.sackOk, ts: !!t.opts.ts });
        // a new SYN on a finished or different connection starts a new flow (port reuse)
        if (f && syn && !ackf) {
          const srcIsC = f.c === sA && f.cp === sp;
          const old = f.isn[0];
          if (!srcIsC || (old !== null && old !== t.seq) || (old === null && (f.pkts[0] + f.pkts[1]) > 0 && (f.fin[0] || f.fin[1] || f.rst[0] || f.rst[1] || S.ts[i] - S.ts[f.last] > 30))) f = null;
        }
        if (!f) {
          let cA = sA, cP = sp, sAd = dA, sP = dp;
          if (syn && ackf) { cA = dA; cP = dp; sAd = sA; sP = sp; }
          else if (!syn) {
            // no handshake: the lower / well-known port is the server
            const srcServer = (sp < 1024 && dp >= 1024) || (sp < dp && !(dp < 1024));
            if (srcServer) { cA = dA; cP = dp; sAd = sA; sP = sp; }
          }
          f = newFlow('tcp', key, cA, cP, sAd, sP, i);
          f.l3 = pkt.l3;
        }
        const dir = (sA === f.c && sp === f.cp) ? 0 : 1;
        S.dir[i] = dir;
        if (syn && !ackf) { f.synSeen = true; if (f.isn[0] === null) f.isn[0] = t.seq; }
        if (syn && ackf) { f.synAckSeen = true; if (f.isn[1] === null) f.isn[1] = t.seq; }
        if (t.flags & 1) f.fin[dir] = true;
        if (t.flags & 4) f.rst[dir] = true;
        f.payload[dir] += t.payLen;
        link(f, i, dir, pkt);
        stream(i, f, dir, pkt);
      } else {
        const u = pkt.udp;
        S.plen[i] = u.len;
        if (!f) {
          let cA = sA, cP = sp, sAd = dA, sP = dp;
          const srcServer = sp === 53 || sp === 443 || sp === 123 || (sp < 1024 && dp >= 1024);
          if (srcServer) { cA = dA; cP = dp; sAd = sA; sP = sp; }
          f = newFlow('udp', key, cA, cP, sAd, sP, i);
          f.l3 = pkt.l3;
        }
        const dir = (sA === f.c && sp === f.cp) ? 0 : 1;
        S.dir[i] = dir;
        f.payload[dir] += u.len;
        link(f, i, dir, pkt);
        if ((sp === 53 || dp === 53 || sp === 5353 || dp === 5353) && u.payload.length >= 12) { f.app = sp === 5353 || dp === 5353 ? 'mDNS' : 'DNS'; dns(i, pkt, u.payload, dp === 53); f.dnsN++; }
        else if ((sp === 443 || dp === 443 || sp === 80 || dp === 80) && u.payload.length >= 5) {
          const b0 = u.payload[0];
          if ((b0 & 0xc0) === 0xc0) {
            const ver = ((u.payload[1] << 24) | (u.payload[2] << 16) | (u.payload[3] << 8) | u.payload[4]) >>> 0;
            f.quic = true; f.app = 'QUIC';
            S.info.set(i, 'QUIC long header' + (ver === 1 ? ' v1' : ver === 0x6b3343cf ? ' v2' : ver === 0 ? ' (version negotiation)' : ' 0x' + ver.toString(16)));
          } else if (f.quic) S.info.set(i, 'QUIC short header (encrypted)');
        } else if (!f.app) {
          f.app = { 123: 'NTP', 67: 'DHCP', 68: 'DHCP', 161: 'SNMP', 162: 'SNMP trap', 514: 'Syslog', 1900: 'SSDP', 5060: 'SIP', 4789: 'VXLAN', 4500: 'IPsec NAT-T', 500: 'IKE', 51820: 'WireGuard', 3478: 'STUN' }[Math.min(sp, dp)] || { 123: 'NTP', 4789: 'VXLAN', 4500: 'IPsec NAT-T', 500: 'IKE', 51820: 'WireGuard', 3478: 'STUN', 5060: 'SIP' }[Math.max(sp, dp)] || null;
        }
      }
    }
    function link(f, i, dir, pkt) {
      S.flow[i] = f.id;
      if (f.tail !== i) { S.next[f.tail] = i; f.tail = i; }
      f.last = i;
      f.pkts[dir]++; f.bytes[dir] += pkt.origLen;
      if (pkt.macSrc && !f.macs[dir]) f.macs[dir] = pkt.macSrc;
      if (pkt.vlan && !f.vlan) f.vlan = pkt.vlan.slice();
    }
    const ICMP4 = { 0: 'Echo reply', 3: 'Destination unreachable', 4: 'Source quench', 5: 'Redirect', 8: 'Echo request', 11: 'Time exceeded', 12: 'Parameter problem' };
    const UN4 = { 0: 'net unreachable', 1: 'host unreachable', 2: 'protocol unreachable', 3: 'port unreachable', 4: 'fragmentation needed', 9: 'net prohibited', 10: 'host prohibited', 13: 'communication administratively prohibited' };
    const ICMP6 = { 1: 'Destination unreachable', 2: 'Packet too big', 3: 'Time exceeded', 4: 'Parameter problem', 128: 'Echo request', 129: 'Echo reply', 133: 'Router solicitation', 134: 'Router advertisement', 135: 'Neighbor solicitation', 136: 'Neighbor advertisement', 137: 'Redirect' };
    const UN6 = { 0: 'no route', 1: 'administratively prohibited', 3: 'address unreachable', 4: 'port unreachable', 5: 'source address failed policy', 6: 'reject route' };
    function icmpPacket(i, pkt) {
      const ic = pkt.icmp;
      if (!ic) return;
      const v6 = pkt.l4 === 'icmp6';
      let txt = (v6 ? 'ICMPv6 ' + (ICMP6[ic.type] || 'type ' + ic.type) : 'ICMP ' + (ICMP4[ic.type] || 'type ' + ic.type));
      if (!v6 && ic.type === 3) txt += ' (' + (UN4[ic.code] || 'code ' + ic.code) + ')';
      if (v6 && ic.type === 1) txt += ' (' + (UN6[ic.code] || 'code ' + ic.code) + ')';
      if (ic.mtu !== undefined) txt += ', MTU ' + ic.mtu;
      if (ic.id !== undefined) txt += ' id=' + ic.id + ' seq=' + ic.seqn;
      const err = ic.inner;
      if (err) {
        const ip = err.proto === 6 ? 'TCP' : err.proto === 17 ? 'UDP' : 'proto ' + err.proto;
        txt += ' for ' + ip + ' ' + err.src + (err.sport !== undefined ? ':' + err.sport : '') + ' → ' + err.dst + (err.dport !== undefined ? ':' + err.dport : '');
        let fid = -1;
        if (err.sport !== undefined && (err.proto === 6 || err.proto === 17)) {
          const pr = err.proto === 6 ? 'tcp' : 'udp';
          const a = addr(err.src), b = addr(err.dst);
          const key = a < b || (a === b && err.sport <= err.dport) ? pr + a + ':' + err.sport + '-' + b + ':' + err.dport : pr + b + ':' + err.dport + '-' + a + ':' + err.sport;
          const id = S.flowMap.get(key);
          if (id !== undefined) fid = id;
        }
        S.icmp.push({ pkt: i, v6, type: ic.type, code: ic.code, mtu: ic.mtu, from: pkt.src, to: pkt.dst, inner: err, flow: fid, t: S.ts[i] });
        S.marks[i] |= M.KEY;
      }
      S.info.set(i, txt);
    }

    return { S, add, M, KIND };
  }

  PA.store = { createStore, M, KIND };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.store;
})(typeof globalThis !== 'undefined' ? globalThis : self);
