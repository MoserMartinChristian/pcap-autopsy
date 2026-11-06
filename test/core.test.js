// Core tests: parser, analysis, verdicts against generator ground truth, traps, robustness, report.
// Run: npm test   (Node.js ≥ 18, no dependencies)
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const PA = require('../scripts/load.js');

const cache = new Map();
function run(id) {
  if (!cache.has(id)) {
    const { bytes, truth } = PA.scenarios.build(id);
    const r = PA.pipeline.analyzeBytes(bytes, 7919); // odd chunk size exercises record splitting
    cache.set(id, { bytes, truth, r });
  }
  return cache.get(id);
}
const brief = (r) => r.findings.map((f) => `${f.id}(${f.sev},${f.cat})`).join(' ');

test.describe('verdict and evidence match the generator ground truth', () => {
  for (const s of PA.scenarios.list) {
    test.it(s.id + ': ' + s.en, () => {
      const { truth, r } = run(s.id);
      assert.equal(r.verdict.v, truth.verdict, 'verdict; findings: ' + brief(r));
      assert.equal(r.summary.packets, truth.frames, 'every generated frame is parsed');
      for (const e of truth.expect) {
        const f = r.findings.find((x) => x.id === e.id);
        assert.ok(f, 'expected finding ' + e.id + ' – got: ' + brief(r));
        for (const p of e.pkts) assert.ok(f.pkts.includes(p), `${e.id} cites packet ${p} (cited: ${f.pkts.slice(0, 12)})`);
        assert.ok(f.filter !== undefined, 'has a Wireshark filter');
      }
      for (const id of truth.forbid || []) assert.ok(!r.findings.some((x) => x.id === id), 'must not report ' + id + ' – got: ' + brief(r));
      for (const sev of truth.forbidSev || []) assert.ok(!r.findings.some((x) => x.sev === sev), 'must not have ' + sev + ' findings – got: ' + brief(r));
    });
  }
});

test.describe('traps never produce a network diagnosis', () => {
  for (const id of ['healthy', 'trap-offload', 'trap-caploss', 'trap-snaplen', 'trap-midstream', 'trap-keepalive', 'trap-short']) {
    test.it(id, () => {
      const { r } = run(id);
      assert.notEqual(r.verdict.v, 'network');
      assert.ok(!r.findings.some((f) => f.cat === 'network' && f.sev !== 'info'), brief(r));
      assert.ok(!r.findings.some((f) => f.id === 'tcp.loss'), 'no loss finding');
    });
  }
  test.it('capture loss is reported as a capture artefact', () => {
    const f = run('trap-caploss').r.findings.find((x) => x.id === 'capture.loss');
    assert.equal(f.cat, 'capture');
    assert.ok(f.m.bytes >= 5 * 1000);
  });
  test.it('TSO and checksum offload are notes only', () => {
    const { r, truth } = run('trap-offload');
    assert.ok(truth.merged > 0);
    for (const id of ['capture.offload_tso', 'capture.offload_csum']) assert.equal(r.findings.find((f) => f.id === id).sev, 'info');
  });
  test.it('missing handshake: window values are not trusted', () => {
    const { r } = run('trap-midstream');
    assert.ok(r.verdict.missing.includes('noHandshake'));
    assert.ok(!r.findings.some((f) => /window_limited|no_wscale/.test(f.id)));
  });
  test.it('short capture says what is missing', () => {
    const { r } = run('trap-short');
    assert.equal(r.verdict.v, 'inconclusive');
    assert.ok(r.verdict.missing.includes('fewPackets'));
  });
});

test.describe('capture formats and link types', () => {
  for (const id of PA.scenarios.variants) {
    test.it(id, () => {
      const { r, truth } = run(id);
      assert.equal(r.summary.packets, truth.frames);
      assert.equal(r.summary.tcpConns, 2);
      assert.equal(r.verdict.v, 'clean', brief(r));
      assert.equal(r.store.S.stats.reasm, 2, 'IPv4 and IPv6 fragments reassembled');
      assert.ok(r.dns.list.some((q) => q.name === 'big.example.com' && q.r), 'fragmented DNS answer matched');
      assert.ok(r.dns.list.some((q) => q.name === 'big6.example.com' && q.r), 'fragmented IPv6 DNS answer matched');
      assert.ok(r.tls.some((t) => t.sni === 'fmt6.example.com'), 'SNI over IPv6');
      assert.equal(r.store.S.stats.decodeErr, 0);
    });
  }
  test.it('VLAN / QinQ tags are recognised', () => {
    const { r } = run('fmt-pcapng-qinq');
    assert.equal(r.store.S.stats.vlan, r.summary.packets);
  });
  test.it('nanosecond timestamps keep their precision', () => {
    const { r } = run('fmt-pcap-be-ns-raw');
    const ref = run('fmt-pcap-le-us-eth').r;
    assert.equal(r.parse.tsPrecision, 'ns');
    for (let i = 0; i < 50; i++) assert.ok(Math.abs(r.store.S.ts[i] - ref.store.S.ts[i]) < 2e-6);
  });
  test.it('IPv6 addresses are printed in compressed form', () => {
    assert.equal(PA.parser.ip6(PA.gen.parseIp('2001:db8:0:0:0:0:0:1'), 0), '2001:db8::1');
    assert.equal(PA.parser.ip6(PA.gen.parseIp('2001:db8:10::40'), 0), '2001:db8:10::40');
  });
});

test.describe('damaged and unsupported files never crash', () => {
  const base = () => run('healthy').bytes;
  const analyse = (b) => { try { return { r: PA.pipeline.analyzeBytes(b) }; } catch (e) { if (e instanceof PA.parser.CaptureError) return { err: e.code }; throw e; } };
  test.it('empty file', () => assert.equal(analyse(new Uint8Array(0)).err, 'err.empty'));
  test.it('not a capture', () => assert.equal(analyse(new TextEncoder().encode('hello world, this is text')).err, 'err.notCapture'));
  test.it('gzip file', () => assert.equal(analyse(Uint8Array.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0])).err, 'err.gzip'));
  test.it('header only', () => assert.equal(analyse(base().slice(0, 24)).err, 'err.noPackets'));
  test.it('truncated header', () => assert.equal(analyse(base().slice(0, 10)).err, 'err.truncatedHeader'));
  test.it('file cut in the middle of a packet', () => {
    const b = base();
    const { r } = analyse(b.slice(0, Math.floor(b.length / 2) + 7));
    assert.ok(r.summary.packets > 100);
    assert.ok(r.findings.some((f) => f.id === 'capture.parse' && f.m.code === 'w.truncatedFile'));
  });
  test.it('corrupt record header in the middle', () => {
    const b = base().slice();
    // find the 200th record and give it an absurd length
    let o = 24; for (let k = 0; k < 200; k++) { const cap = b[o + 8] | (b[o + 9] << 8) | (b[o + 10] << 16) | (b[o + 11] << 24); o += 16 + cap; }
    b[o + 8] = 0xff; b[o + 9] = 0xff; b[o + 10] = 0xff; b[o + 11] = 0x7f;
    const { r } = analyse(b);
    assert.equal(r.summary.packets, 200);
    assert.ok(r.findings.some((f) => f.m.code === 'w.corruptRecord'));
  });
  test.it('broken pcapng block', () => {
    const b = run('fmt-pcapng-sll').bytes.slice();
    b[28 + 32 + 4] = 3; // block length of the first EPB not a multiple of 4
    const out = analyse(b);
    assert.ok(out.err || out.r.findings.some((f) => f.m.code === 'w.corruptBlock'));
  });
  test.it('unsupported link type', () => {
    const b = run('fmt-pcap-le-us-eth').bytes.slice();
    b[20] = 147; // DLT_USER0
    assert.equal(analyse(b).err, 'err.linktype');
  });
  test.it('random byte mutations (300 runs) give a result or a clear error', () => {
    const rnd = PA.gen.rng(4242);
    const src = run('loss').bytes;
    for (let k = 0; k < 300; k++) {
      const b = src.slice(0, 20000 + Math.floor(rnd() * 60000));
      const n = 1 + Math.floor(rnd() * 40);
      for (let j = 0; j < n; j++) b[Math.floor(rnd() * b.length)] = Math.floor(rnd() * 256);
      const out = analyse(b);
      assert.ok(out.err || out.r.verdict, 'run ' + k);
    }
  });
  test.it('random garbage after a valid header', () => {
    const rnd = PA.gen.rng(99);
    const b = new Uint8Array(50000); b.set(base().slice(0, 24));
    for (let i = 24; i < b.length; i++) b[i] = Math.floor(rnd() * 256);
    const out = analyse(b);
    assert.ok(out.err || out.r);
  });
});

test.describe('report export and anonymisation', () => {
  const { r } = run('loss');
  test.it('anonymisation is consistent and complete', () => {
    const md = PA.report.markdown(r, 'en', { anon: true, fileName: 'x.pcap' });
    const html = PA.report.html(r, 'de', { anon: true });
    const tk = PA.report.ticket(r, 'en', { anon: true });
    for (const a of r.anon.addrs) for (const s of [md, html, tk]) assert.ok(!s.includes(a), 'address ' + a + ' leaked');
    for (const n of r.anon.names) for (const s of [md, html]) assert.ok(!s.toLowerCase().includes(n.toLowerCase()), 'name ' + n + ' leaked');
    const A = PA.report.createAnonymizer(r.anon);
    const p1 = A.apply('10.20.30.40'), p2 = A.apply('from 10.20.30.40:443');
    assert.equal(p1, '[ip-1]'); assert.ok(p2.includes(p1));
    assert.equal(A.apply('downloads.example.com'), A.apply('DOWNLOADS.example.com'));
    assert.ok(md.includes('[ip-'));
    assert.match(A.apply('02:00:5e:10:00:01 and 2001:db8:10::40'), /\[mac-\d+\] and \[ip6-\d+\]/);
  });
  test.it('HTML report is self-contained and blocks network access', () => {
    const html = PA.report.html(r, 'en', {});
    assert.match(html, /Content-Security-Policy" content="default-src 'none'/);
    assert.ok(!/\b(src|href)=["']?https?:/i.test(html));
    assert.ok(html.includes('Packet loss'));
  });
  test.it('ticket text is short', () => {
    const t = PA.report.ticket(r, 'de', {});
    assert.ok(t.split('\n').length <= 12);
    assert.ok(t.startsWith('PCAP Autopsy: Es ist das Netzwerk'));
  });
});

test.describe('texts and thresholds', () => {
  test.it('every finding has English and German text without gaps', () => {
    const ids = new Set();
    for (const id of PA.scenarios.list.map((s) => s.id).concat(PA.scenarios.variants)) for (const f of run(id).r.findings) {
      ids.add(f.id);
      for (const lang of ['en', 'de']) {
        const t = PA.i18n.text(lang, f);
        for (const k of ['t', 'd', 'n']) assert.ok(t[k] && !/undefined|NaN|\[object/.test(t[k]), `${lang} ${f.id}.${k}: ${t[k]}`);
      }
    }
    for (const id of Object.keys(PA.i18n.en.f)) assert.ok(PA.i18n.de.f[id], 'German text for ' + id);
    assert.ok(ids.size >= 35, 'scenarios cover ' + ids.size + ' finding types');
  });
  test.it('every threshold has a value and a reason in both languages', () => {
    for (const [k, v] of Object.entries(PA.config.T)) assert.ok(typeof v.v === 'number' && v.en.length > 20 && v.de.length > 20, k);
  });
  test.it('every finding names severity, confidence, side and evidence', () => {
    for (const id of PA.scenarios.list.map((s) => s.id)) for (const f of run(id).r.findings) {
      assert.ok(['critical', 'warning', 'info'].includes(f.sev));
      assert.ok(['high', 'medium', 'low'].includes(f.conf));
      assert.ok(f.side && f.cat);
      if (f.sev !== 'info') assert.ok(f.pkts.length > 0, f.id + ' cites packets');
    }
  });
});

test('index.html is up to date with src/ (run `node build.js` after editing src/)', () => {
  const fs = require('fs');
  const path = require('path');
  const { build } = require('../build.js');
  const disk = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
  assert.ok(disk === build(), 'index.html differs from a fresh build');
});
