/*
 * PCAP Autopsy – capture parser.
 * Streaming reader for pcap (both byte orders, µs/ns) and pcapng, plus link/IP/L4 decoding.
 * Pure JS, no DOM: runs in the Web Worker and in Node tests.
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  const LINK = { NULL: 0, ETHERNET: 1, RAW: 101, LOOP: 108, SLL: 113, SLL2: 276, IPV4: 228, IPV6: 229, RAW_ALT: 12, RAW_ALT2: 14 };
  const LINK_NAMES = { 0: 'Loopback (BSD NULL)', 1: 'Ethernet', 12: 'Raw IP', 14: 'Raw IP', 101: 'Raw IP', 108: 'Loopback (OpenBSD LOOP)', 113: 'Linux cooked (SLL)', 276: 'Linux cooked v2 (SLL2)', 228: 'Raw IPv4', 229: 'Raw IPv6' };

  class CaptureError extends Error {
    constructor(code, params) { super(code); this.code = code; this.params = params || {}; }
  }

  // ---------- helpers ----------
  const hex2 = (b) => (b < 16 ? '0' : '') + b.toString(16);
  function mac(d, o) {
    return hex2(d[o]) + ':' + hex2(d[o + 1]) + ':' + hex2(d[o + 2]) + ':' + hex2(d[o + 3]) + ':' + hex2(d[o + 4]) + ':' + hex2(d[o + 5]);
  }
  function ip4(d, o) { return d[o] + '.' + d[o + 1] + '.' + d[o + 2] + '.' + d[o + 3]; }
  function ip6(d, o) {
    const w = [];
    for (let i = 0; i < 8; i++) w.push((d[o + 2 * i] << 8) | d[o + 2 * i + 1]);
    // IPv4-mapped
    if (w[0] === 0 && w[1] === 0 && w[2] === 0 && w[3] === 0 && w[4] === 0 && w[5] === 0xffff) return '::ffff:' + ip4(d, o + 12);
    let bs = -1, bl = 0;
    for (let i = 0; i < 8;) {
      if (w[i] !== 0) { i++; continue; }
      let j = i; while (j < 8 && w[j] === 0) j++;
      if (j - i > bl && j - i > 1) { bs = i; bl = j - i; }
      i = j;
    }
    const h = w.map((x) => x.toString(16));
    if (bs < 0) return h.join(':');
    return h.slice(0, bs).join(':') + '::' + h.slice(bs + bl).join(':');
  }
  const u16 = (d, o) => (d[o] << 8) | d[o + 1];
  const u32 = (d, o) => ((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0;

  // Internet checksum over pseudo header + segment. Returns true when valid.
  function l4ChecksumOk(d, l3, ipOff, l4Off, l4Len, proto) {
    let s = 0;
    if (l3 === 4) {
      s += u16(d, ipOff + 12) + u16(d, ipOff + 14) + u16(d, ipOff + 16) + u16(d, ipOff + 18);
    } else {
      for (let i = 0; i < 16; i++) s += u16(d, ipOff + 8 + 2 * i);
    }
    s += proto + l4Len;
    const end = l4Off + l4Len;
    let i = l4Off;
    for (; i + 1 < end; i += 2) s += (d[i] << 8) | d[i + 1];
    if (i < end) s += d[i] << 8;
    while (s > 0xffff) s = (s & 0xffff) + (s >>> 16);
    return s === 0xffff;
  }

  // ---------- L3/L4 decoding ----------
  function decodeTcpOptions(d, o, end) {
    const opts = {};
    while (o < end) {
      const k = d[o];
      if (k === 0) break;
      if (k === 1) { o++; continue; }
      if (o + 1 >= end) break;
      const l = d[o + 1];
      if (l < 2 || o + l > end) break;
      if (k === 2 && l === 4) opts.mss = u16(d, o + 2);
      else if (k === 3 && l === 3) opts.ws = d[o + 2];
      else if (k === 4) opts.sackOk = true;
      else if (k === 5) { opts.sack = []; for (let p = o + 2; p + 8 <= o + l; p += 8) opts.sack.push([u32(d, p), u32(d, p + 4)]); }
      else if (k === 8 && l === 10) opts.ts = [u32(d, o + 2), u32(d, o + 6)];
      o += l;
    }
    return opts;
  }

  // decode transport header starting at off (data may be a reassembled buffer).
  // pkt gets l4 fields. avail = bytes present, l4Len = length according to IP.
  function decodeL4(pkt, d, proto, off, l4Len, avail, ipOff, verifyCsum) {
    const capL4 = Math.min(l4Len, avail);
    if (proto === 6) {
      pkt.l4 = 'tcp';
      if (capL4 < 20) { pkt.l4trunc = true; if (capL4 >= 4) { pkt.sport = u16(d, off); pkt.dport = u16(d, off + 2); } return; }
      const hl = (d[off + 12] >> 4) * 4;
      pkt.sport = u16(d, off); pkt.dport = u16(d, off + 2);
      const t = {
        seq: u32(d, off + 4), ack: u32(d, off + 8), flags: ((d[off + 12] & 1) << 8) | d[off + 13],
        win: u16(d, off + 14), hl, opts: hl > 20 ? decodeTcpOptions(d, off + 20, Math.min(off + hl, off + capL4)) : {},
        payLen: Math.max(0, l4Len - hl), payload: null,
      };
      if (hl < 20) { pkt.l4bad = true; t.payLen = 0; }
      const pStart = off + hl;
      const pAvail = Math.max(0, Math.min(off + capL4, d.length) - pStart);
      t.payload = pAvail > 0 ? d.subarray(pStart, pStart + Math.min(pAvail, t.payLen)) : null;
      pkt.tcp = t;
      if (verifyCsum && capL4 === l4Len) pkt.csumBad = !l4ChecksumOk(d, pkt.l3, ipOff, off, l4Len, 6);
    } else if (proto === 17) {
      pkt.l4 = 'udp';
      if (capL4 < 8) { pkt.l4trunc = true; return; }
      pkt.sport = u16(d, off); pkt.dport = u16(d, off + 2);
      const ulen = u16(d, off + 4);
      const plen = Math.max(0, Math.min(ulen, l4Len) - 8);
      const pAvail = Math.max(0, Math.min(capL4 - 8, plen));
      pkt.udp = { len: plen, payload: d.subarray(off + 8, off + 8 + pAvail) };
      if (verifyCsum && capL4 === l4Len && !(pkt.l3 === 4 && u16(d, off + 6) === 0)) pkt.csumBad = !l4ChecksumOk(d, pkt.l3, ipOff, off, l4Len, 17);
    } else if (proto === 1 || proto === 58) {
      pkt.l4 = proto === 1 ? 'icmp' : 'icmp6';
      if (capL4 < 4) { pkt.l4trunc = true; return; }
      const ic = { type: d[off], code: d[off + 1] };
      const v6 = proto === 58;
      const isErr = v6 ? (ic.type >= 1 && ic.type <= 4) : (ic.type === 3 || ic.type === 11 || ic.type === 12 || ic.type === 4);
      if (!v6 && ic.type === 3 && ic.code === 4 && capL4 >= 8) ic.mtu = u16(d, off + 6);
      if (v6 && ic.type === 2 && capL4 >= 8) ic.mtu = u32(d, off + 4);
      if ((ic.type === 0 || ic.type === 8 || ic.type === 128 || ic.type === 129) && capL4 >= 8) { ic.id = u16(d, off + 4); ic.seqn = u16(d, off + 6); }
      if (isErr && capL4 >= 8 + 20) {
        const inner = {};
        const io = off + 8;
        const iEnd = off + capL4;
        const ver = d[io] >> 4;
        let ipo, ip, ipp;
        if (ver === 4) {
          const ihl = (d[io] & 15) * 4;
          inner.l3 = 4; inner.src = ip4(d, io + 12); inner.dst = ip4(d, io + 16); inner.proto = d[io + 9]; inner.ttl = d[io + 8];
          ipo = io + ihl;
        } else if (ver === 6 && capL4 >= 8 + 40) {
          inner.l3 = 6; inner.src = ip6(d, io + 8); inner.dst = ip6(d, io + 24); inner.proto = d[io + 6]; ipo = io + 40;
        }
        ipp = inner.proto; ip = ipo;
        if (ip !== undefined && ip + 4 <= iEnd && (ipp === 6 || ipp === 17)) {
          inner.sport = u16(d, ip); inner.dport = u16(d, ip + 2);
          if (ipp === 6 && ip + 8 <= iEnd) inner.seq = u32(d, ip + 4);
        }
        if (inner.l3) ic.inner = inner;
      }
      pkt.icmp = ic;
    } else {
      pkt.l4 = 'ip-' + proto;
    }
  }

  const V6_EXT = { 0: 1, 43: 1, 60: 1, 51: 1, 135: 1, 139: 1, 140: 1 };

  function decodeIp(pkt, d, o, end, frag) {
    if (o >= end) { pkt.l3trunc = true; return; }
    const ver = d[o] >> 4;
    if (ver === 4) {
      if (end - o < 20) { pkt.l3 = 4; pkt.l3trunc = true; return; }
      const ihl = (d[o] & 15) * 4;
      const tot = u16(d, o + 2);
      pkt.l3 = 4; pkt.src = ip4(d, o + 12); pkt.dst = ip4(d, o + 16);
      pkt.ttl = d[o + 8]; pkt.ipId = u16(d, o + 4);
      const ff = u16(d, o + 6);
      const mf = (ff & 0x2000) !== 0, foff = (ff & 0x1fff) * 8;
      pkt.df = (ff & 0x4000) !== 0;
      const proto = d[o + 9];
      if (ihl < 20 || tot < ihl) { pkt.l3bad = true; return; }
      pkt.ipLen = tot;
      const l4Off = o + ihl;
      const l4Len = tot - ihl;
      const avail = Math.max(0, end - l4Off);
      if (avail < l4Len) pkt.trunc = true;
      if (mf || foff > 0) {
        pkt.frag = { key: '4|' + pkt.src + '|' + pkt.dst + '|' + pkt.ipId + '|' + proto, off: foff, mf, proto, data: avail >= l4Len ? d.slice(l4Off, l4Off + l4Len) : null, ipOff: o, l3: 4 };
        frag.add(pkt);
        return;
      }
      decodeL4(pkt, d, proto, l4Off, l4Len, avail, o, true);
    } else if (ver === 6) {
      if (end - o < 40) { pkt.l3 = 6; pkt.l3trunc = true; return; }
      pkt.l3 = 6; pkt.src = ip6(d, o + 8); pkt.dst = ip6(d, o + 24);
      pkt.ttl = d[o + 7];
      const plen = u16(d, o + 4);
      pkt.ipLen = plen + 40;
      let nh = d[o + 6], p = o + 40, rem = plen;
      let fragHdr = null;
      while (V6_EXT[nh] || nh === 44) {
        if (p + 8 > end) { pkt.l3trunc = true; pkt.trunc = true; return; }
        if (nh === 44) {
          const fo = u16(d, p + 2);
          fragHdr = { off: fo & 0xfff8, mf: (fo & 1) === 1, id: u32(d, p + 4) };
          nh = d[p]; p += 8; rem -= 8;
          break;
        }
        const l = nh === 51 ? (d[p + 1] + 2) * 4 : (d[p + 1] + 1) * 8;
        nh = d[p]; p += l; rem -= l;
      }
      if (rem < 0) { pkt.l3bad = true; return; }
      const avail = Math.max(0, end - p);
      if (avail < rem) pkt.trunc = true;
      if (fragHdr) {
        if (fragHdr.off === 0 && !fragHdr.mf) { /* atomic fragment */ }
        else {
          pkt.frag = { key: '6|' + pkt.src + '|' + pkt.dst + '|' + fragHdr.id, off: fragHdr.off, mf: fragHdr.mf, proto: nh, data: avail >= rem ? d.slice(p, p + rem) : null, ipOff: o, l3: 6 };
          frag.add(pkt);
          return;
        }
      }
      decodeL4(pkt, d, nh, p, rem, avail, o, true);
    } else {
      pkt.l3bad = true;
    }
  }

  // IP fragment reassembly (RFC 791 / 8200). Completed datagrams are decoded on the last fragment.
  function Reassembler() {
    const pending = new Map();
    let incomplete = 0;
    return {
      add(pkt) {
        const f = pkt.frag;
        pkt.l4 = 'frag';
        let e = pending.get(f.key);
        if (!e) {
          if (pending.size > 4096) { const k = pending.keys().next().value; pending.delete(k); incomplete++; }
          e = { parts: [], total: -1, bad: false, first: pkt.no, ipOff: 0, hdr: null };
          pending.set(f.key, e);
        }
        if (!f.data) e.bad = true;
        else e.parts.push({ off: f.off, data: f.data });
        if (!f.mf) e.total = f.off + (f.data ? f.data.length : 0);
        pkt.fragOf = e.first;
        if (e.total < 0 || e.bad) return;
        // check coverage
        e.parts.sort((a, b) => a.off - b.off);
        let cov = 0;
        for (const p of e.parts) { if (p.off > cov) return; cov = Math.max(cov, p.off + p.data.length); }
        if (cov < e.total) return;
        const buf = new Uint8Array(e.total);
        for (const p of e.parts) buf.set(p.data.subarray(0, Math.min(p.data.length, e.total - p.off)), p.off);
        pending.delete(f.key);
        pkt.reassembled = { frames: e.parts.length, len: e.total };
        delete pkt.l4;
        decodeL4(pkt, buf, f.proto, 0, e.total, e.total, -1, false);
      },
      get incomplete() { return incomplete + pending.size; },
    };
  }

  function decodeLink(pkt, d, linktype) {
    const end = d.length;
    let o = 0, et = -1;
    switch (linktype) {
      case LINK.ETHERNET: {
        if (end < 14) { pkt.l2trunc = true; return -1; }
        pkt.macDst = mac(d, 0); pkt.macSrc = mac(d, 6);
        et = u16(d, 12); o = 14;
        break;
      }
      case LINK.SLL: {
        if (end < 16) { pkt.l2trunc = true; return -1; }
        const alen = u16(d, 4);
        if (alen === 6) pkt.macSrc = mac(d, 6);
        et = u16(d, 14); o = 16;
        break;
      }
      case LINK.SLL2: {
        if (end < 20) { pkt.l2trunc = true; return -1; }
        if (d[11] === 6) pkt.macSrc = mac(d, 12);
        et = u16(d, 0); o = 20;
        break;
      }
      case LINK.NULL: case LINK.LOOP: {
        if (end < 4) { pkt.l2trunc = true; return -1; }
        const be = u32(d, 0), le = (d[0] | (d[1] << 8) | (d[2] << 16) | (d[3] << 24)) >>> 0;
        const fam = linktype === LINK.LOOP ? be : (be < 256 ? be : le);
        o = 4;
        if (fam === 2) et = 0x0800; else if (fam === 24 || fam === 28 || fam === 30 || fam === 10) et = 0x86dd; else { pkt.desc = 'Loopback family ' + fam; return -1; }
        break;
      }
      case LINK.RAW: case LINK.RAW_ALT: case LINK.RAW_ALT2: case LINK.IPV4: case LINK.IPV6: {
        if (end < 1) return -1;
        et = (d[0] >> 4) === 6 ? 0x86dd : 0x0800;
        break;
      }
      default:
        pkt.unsupportedLink = true;
        return -1;
    }
    // VLAN tags (802.1Q, 802.1ad QinQ, legacy 0x9100)
    while ((et === 0x8100 || et === 0x88a8 || et === 0x9100) && o + 4 <= end) {
      (pkt.vlan || (pkt.vlan = [])).push(u16(d, o) & 0x0fff);
      et = u16(d, o + 2); o += 4;
    }
    pkt.ethertype = et;
    if (et === 0x0800 || et === 0x86dd) return o;
    if (et === 0x0806) {
      pkt.l4 = 'arp';
      if (o + 28 <= end) {
        const op = u16(d, o + 6);
        pkt.src = ip4(d, o + 14); pkt.dst = ip4(d, o + 24);
        pkt.desc = op === 1 ? 'ARP who-has ' + pkt.dst + ' tell ' + pkt.src : op === 2 ? 'ARP ' + pkt.src + ' is-at ' + mac(d, o + 8) : 'ARP op ' + op;
      } else pkt.desc = 'ARP';
      return -1;
    }
    if (et < 0x0600) { pkt.l4 = 'llc'; pkt.desc = '802.3 / LLC'; return -1; }
    pkt.l4 = 'eth-' + et.toString(16).padStart(4, '0');
    pkt.desc = 'EtherType 0x' + et.toString(16).padStart(4, '0');
    return -1;
  }

  // ---------- container parsing ----------
  /*
   * createReader(onPacket): returns { push(Uint8Array), end(), info }
   * onPacket(pkt) is called for every record. Errors that make the rest of the file unreadable
   * stop the reader and are listed in info.warnings; a wrong format throws CaptureError.
   */
  function createReader(onPacket) {
    let pending = null; // leftover bytes from previous chunk
    let consumed = 0; // file offset of pending[0]
    let fmt = null; // 'pcap' | 'pcapng'
    let le = true, nsec = false, linktype = -1, snaplen = 0;
    let ifaces = [];
    let no = 0, stopped = false;
    let base = null; // first timestamp (integer seconds, fraction)
    const frag = Reassembler();
    const info = { format: null, linktypes: {}, warnings: [], snaplen: 0, truncatedRecords: 0, unsupportedLink: 0, packets: 0, firstTs: null, lastTs: null, bytes: 0, tsPrecision: null, sections: 0 };

    const warn = (code, params) => { info.warnings.push({ code, params: params || {} }); };

    function emit(d, sec, frac, capLen, origLen, lt) {
      no++;
      if (base === null) { base = sec; info.firstTs = sec + frac; }
      const pkt = { no, ts: (sec - base) + frac, capLen, origLen, link: lt };
      info.lastTs = sec + frac;
      info.linktypes[lt] = (info.linktypes[lt] || 0) + 1;
      if (capLen < origLen) { pkt.snap = true; info.truncatedRecords++; }
      try {
        const o = decodeLink(pkt, d, lt);
        if (o >= 0) decodeIp(pkt, d, o, d.length, frag);
        if (pkt.unsupportedLink) info.unsupportedLink++;
      } catch (e) {
        pkt.decodeError = true;
      }
      info.packets = no;
      info.bytes += origLen;
      onPacket(pkt);
    }

    function rd16(d, o) { return le ? (d[o] | (d[o + 1] << 8)) : ((d[o] << 8) | d[o + 1]); }
    function rd32(d, o) { return le ? ((d[o] | (d[o + 1] << 8) | (d[o + 2] << 16) | (d[o + 3] << 24)) >>> 0) : (((d[o] << 24) | (d[o + 1] << 16) | (d[o + 2] << 8) | d[o + 3]) >>> 0); }

    function detect(d) {
      if (d.length < 4) return false;
      const m = u32(d, 0);
      if (m === 0xa1b2c3d4) { fmt = 'pcap'; le = false; nsec = false; }
      else if (m === 0xd4c3b2a1) { fmt = 'pcap'; le = true; nsec = false; }
      else if (m === 0xa1b23c4d) { fmt = 'pcap'; le = false; nsec = true; }
      else if (m === 0x4d3cb2a1) { fmt = 'pcap'; le = true; nsec = true; }
      else if (m === 0x0a0d0d0a) { fmt = 'pcapng'; }
      else if (m === 0x1f8b0800 || (d[0] === 0x1f && d[1] === 0x8b)) throw new CaptureError('err.gzip');
      else if (d[0] === 0x50 && d[1] === 0x4b) throw new CaptureError('err.zip');
      else if (m === 0x34cdb2a1 || m === 0xa1b2cd34) throw new CaptureError('err.unsupported', { what: 'Kuznetzov/modified pcap' });
      else if (d.length >= 8 && String.fromCharCode(d[0], d[1], d[2], d[3], d[4], d[5]) === 'XCP\0\0\0') throw new CaptureError('err.unsupported', { what: 'NetMon' });
      else throw new CaptureError('err.notCapture', { magic: m.toString(16).padStart(8, '0') });
      info.format = fmt + (fmt === 'pcap' ? (le ? ' (little-endian' : ' (big-endian') + (nsec ? ', ns)' : ', µs)') : '');
      info.tsPrecision = fmt === 'pcap' ? (nsec ? 'ns' : 'µs') : null;
      return true;
    }

    // parse as many complete units from d as possible, returns bytes consumed
    function parse(d, isEnd) {
      let o = 0;
      if (!fmt) {
        if (d.length < 4) return 0;
        detect(d);
      }
      if (fmt === 'pcap') {
        if (linktype < 0) {
          if (d.length < 24) { if (isEnd) throw new CaptureError('err.truncatedHeader'); return 0; }
          const vmaj = rd16(d, 4);
          if (vmaj !== 2) warn('w.pcapVersion', { v: vmaj + '.' + rd16(d, 6) });
          snaplen = rd32(d, 16); info.snaplen = snaplen;
          linktype = rd32(d, 20) & 0x0fffffff & 0xffff;
          o = 24;
        }
        const lim = PA.config ? PA.config.limits.maxRecordBytes : 262144;
        while (o + 16 <= d.length) {
          const sec = rd32(d, o), sub = rd32(d, o + 4), cap = rd32(d, o + 8), orig = rd32(d, o + 12);
          if (cap > lim || (snaplen > 0 && cap > Math.max(snaplen, 65535) + 65535) || sub >= (nsec ? 1e9 : 1e6) * 1.0001 + 1) {
            warn('w.corruptRecord', { offset: consumed + o, packet: no + 1 });
            stopped = true; return o;
          }
          if (o + 16 + cap > d.length) break;
          emit(d.subarray(o + 16, o + 16 + cap), sec, sub / (nsec ? 1e9 : 1e6), cap, Math.max(orig, cap), linktype);
          o += 16 + cap;
        }
        return o;
      }
      // pcapng
      while (o + 12 <= d.length) {
        let btype = rd32(d, o);
        if (btype === 0x0a0d0d0a) {
          // section header – determine byte order
          const bom = u32(d, o + 8);
          if (bom === 0x1a2b3c4d) le = false; else if (bom === 0x4d3c2b1a) le = true;
          else { warn('w.corruptBlock', { offset: consumed + o }); stopped = true; return o; }
          info.sections++;
          ifaces = [];
          btype = 0x0a0d0d0a;
        }
        const blen = rd32(d, o + 4);
        if (blen < 12 || blen % 4 !== 0 || blen > 64 * 1024 * 1024) { warn('w.corruptBlock', { offset: consumed + o, packet: no + 1 }); stopped = true; return o; }
        if (o + blen > d.length) break;
        const trail = rd32(d, o + blen - 4);
        if (trail !== blen) { warn('w.corruptBlock', { offset: consumed + o, packet: no + 1 }); stopped = true; return o; }
        const b = d.subarray(o, o + blen);
        if (btype === 1) { // IDB
          const iface = { linktype: rd16(b, 8), snaplen: rd32(b, 12), tsres: 1e-6, tsoff: 0 };
          let p = 16;
          while (p + 4 <= blen - 4) {
            const code = rd16(b, p), len = rd16(b, p + 2);
            if (code === 0) break;
            if (code === 9 && len >= 1) { const v = b[p + 4]; iface.tsres = (v & 0x80) ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v); }
            if (code === 14 && len >= 8) { iface.tsoff = rd32(b, p + 4) * (le ? 1 : 4294967296) + rd32(b, p + 8) * (le ? 4294967296 : 1); }
            p += 4 + ((len + 3) & ~3);
          }
          ifaces.push(iface);
          if (!info.snaplen || iface.snaplen < info.snaplen) info.snaplen = iface.snaplen;
          if (!info.tsPrecision) info.tsPrecision = iface.tsres <= 1e-9 ? 'ns' : iface.tsres <= 1e-6 ? 'µs' : 'ms';
        } else if (btype === 6 || btype === 2) { // EPB / obsolete PB
          const ifid = btype === 6 ? rd32(b, 8) : rd16(b, 8);
          const iface = ifaces[ifid];
          if (!iface) { warn('w.noInterface', { packet: no + 1 }); }
          else {
            const hi = rd32(b, 12), lo = rd32(b, 16), cap = rd32(b, 20), orig = rd32(b, 24);
            if (28 + cap > blen - 4) { warn('w.corruptBlock', { offset: consumed + o, packet: no + 1 }); stopped = true; return o; }
            const units = hi * 4294967296 + lo;
            let sec, frac;
            if (iface.tsres === 1e-6) { sec = Math.floor(units / 1e6); frac = (units - sec * 1e6) / 1e6; }
            else if (iface.tsres === 1e-9) { sec = Math.floor(units / 1e9); frac = (units - sec * 1e9) / 1e9; }
            else { const t = units * iface.tsres; sec = Math.floor(t); frac = t - sec; }
            emit(b.subarray(28, 28 + cap), sec + iface.tsoff, frac, cap, Math.max(orig, cap), iface.linktype);
          }
        } else if (btype === 3) { // SPB
          const iface = ifaces[0];
          if (iface) {
            const orig = rd32(b, 8);
            const cap = Math.min(orig, blen - 16, iface.snaplen || orig);
            // SPB has no timestamp – reuse the last one
            const last = info.lastTs !== null ? info.lastTs : 0;
            const sec = Math.floor(last);
            emit(b.subarray(12, 12 + cap), sec, last - sec, cap, orig, iface.linktype);
            if (!info.spbNoTs) { info.spbNoTs = true; warn('w.spbNoTimestamp'); }
          }
        }
        o += blen;
      }
      return o;
    }

    return {
      info,
      push(chunk) {
        if (stopped) return;
        let d;
        if (pending && pending.length) { d = new Uint8Array(pending.length + chunk.length); d.set(pending, 0); d.set(chunk, pending.length); }
        else d = chunk;
        const used = parse(d, false);
        consumed += used;
        pending = used < d.length ? d.slice(used) : null;
        if (stopped) pending = null;
      },
      end() {
        if (!fmt) {
          if (!pending || pending.length === 0) throw new CaptureError('err.empty');
          parse(pending, true);
        }
        if (!stopped && pending && pending.length) {
          const used = parse(pending, true);
          if (used < pending.length) warn('w.truncatedFile', { bytes: pending.length - used, packet: no + 1 });
        }
        if (fmt === 'pcap' && linktype < 0) throw new CaptureError('err.truncatedHeader');
        if (fmt === 'pcapng' && info.sections === 0) throw new CaptureError('err.notCapture', { magic: '' });
        if (frag.incomplete) warn('w.incompleteFragments', { n: frag.incomplete });
        if (no === 0) throw new CaptureError(info.warnings.length ? 'err.corruptStart' : 'err.noPackets');
        if (info.unsupportedLink === no) {
          throw new CaptureError('err.linktype', { lt: Object.keys(info.linktypes).join(', ') });
        }
        if (info.unsupportedLink) warn('w.unsupportedLink', { n: info.unsupportedLink, lt: Object.keys(info.linktypes).filter((k) => !LINK_NAMES[k]).join(', ') });
        info.duration = info.lastTs !== null ? info.lastTs - info.firstTs : 0;
        return info;
      },
    };
  }

  PA.parser = { createReader, CaptureError, LINK, LINK_NAMES, ip4, ip6, u16, u32 };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.parser;
})(typeof globalThis !== 'undefined' ? globalThis : self);
