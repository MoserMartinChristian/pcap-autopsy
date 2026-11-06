#!/usr/bin/env node
/*
 * Writes a large pcap for the size test by stitching synthetic scenarios together:
 *   node scripts/make-big.js <out.pcap> <megabytes> [small]
 * Each copy is shifted in time and gets new client ports (checksums are updated per RFC 1624),
 * so the result looks like many separate connections. "small" uses DNS-heavy traffic with
 * short packets, the worst case for packets per megabyte.
 */
'use strict';
const fs = require('fs');
const PA = require('./load.js');
const [out, mbArg, mode] = process.argv.slice(2);
if (!out || !mbArg) { console.error('usage: make-big.js out.pcap MB [small]'); process.exit(1); }
const target = Number(mbArg) * 1024 * 1024;
const mix = mode === 'small' ? ['dns', 'syn-timeout', 'rst-on-syn', 'dns'] : ['healthy', 'loss', 'server-delay', 'healthy', 'zero-window', 'healthy', 'bufferbloat', 'healthy'];

function records(id) {
  const b = Buffer.from(PA.scenarios.build('fmt-pcap-le-us-eth' === id ? id : id).bytes);
  if (b.readUInt32LE(0) !== 0xa1b2c3d4) throw new Error(id + ' is not LE µs pcap');
  const recs = [];
  for (let o = 24; o + 16 <= b.length;) { const incl = b.readUInt32LE(o + 8); recs.push(b.subarray(o, o + 16 + incl)); o += 16 + incl; }
  const t0 = recs[0].readUInt32LE(0) + recs[0].readUInt32LE(4) / 1e6;
  const t1 = recs[recs.length - 1].readUInt32LE(0);
  return { recs, t0, dur: t1 - t0 + 1, hdr: b.subarray(0, 24) };
}
const src = mix.map(records);
function csumAdd(c, oldW, newW) { // RFC 1624: HC' = ~(~HC + ~m + m')
  let s = (~c & 0xffff) + (~oldW & 0xffff) + newW;
  s = (s & 0xffff) + (s >>> 16); s = (s & 0xffff) + (s >>> 16);
  return ~s & 0xffff;
}
const fd = fs.openSync(out, 'w');
fs.writeSync(fd, src[0].hdr);
let written = 24, copy = 0, tBase = 1.7e9, pkts = 0;
const buf = Buffer.alloc(1 << 22); let bo = 0;
const flush = () => { fs.writeSync(fd, buf, 0, bo); bo = 0; };
while (written < target) {
  const S = src[copy % src.length];
  const shift = (tBase - S.t0);
  for (const r0 of S.recs) {
    if (bo + r0.length > buf.length) flush();
    const r = buf.subarray(bo, bo + r0.length); r0.copy(r); bo += r0.length;
    let t = r.readUInt32LE(0) + r.readUInt32LE(4) / 1e6 + shift;
    const sec = Math.floor(t); let us = Math.round((t - sec) * 1e6); r.writeUInt32LE(us >= 1e6 ? sec + 1 : sec, 0); r.writeUInt32LE(us >= 1e6 ? 0 : us, 4);
    // Ethernet + IPv4 + TCP/UDP: rewrite the ephemeral port
    const e = 16;
    if (r.length > e + 34 && r.readUInt16BE(e + 12) === 0x0800) {
      const ihl = (r[e + 14] & 15) * 4, proto = r[e + 23], l4 = e + 14 + ihl;
      const fragOff = r.readUInt16BE(e + 20) & 0x1fff;
      if ((proto === 6 || proto === 17) && fragOff === 0 && r.length >= l4 + 8) {
        const cOff = proto === 6 ? 16 : 6;
        for (const po of [0, 2]) {
          const p = r.readUInt16BE(l4 + po);
          if (p >= 10000) {
            const np = 10000 + ((p - 10000 + copy * 977) % 55000);
            if (r.length >= l4 + cOff + 2) { const c = r.readUInt16BE(l4 + cOff); if (!(proto === 17 && c === 0)) r.writeUInt16BE(csumAdd(c, p, np), l4 + cOff); }
            r.writeUInt16BE(np, l4 + po);
          }
        }
      }
    }
    written += r0.length; pkts++;
  }
  tBase += S.dur + 0.5; copy++;
}
flush(); fs.closeSync(fd);
console.log(out, (written / 1048576).toFixed(0) + ' MiB', pkts + ' packets', copy + ' scenario copies');
