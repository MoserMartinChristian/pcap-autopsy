#!/usr/bin/env node
/*
 * Browser end-to-end test for index.html (file://, headless Chromium via Playwright).
 * Checks: every demo gives the expected verdict, evidence jump, charts, exports (+anonymisation),
 * file picker and drag & drop, cancel, corrupt file message, DE/EN, dark/light, mobile,
 * no console errors and no request that is not file:, blob: or data:.
 * Writes docs/e2e-results.txt. Screenshots go to $SHOTS if set.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { chromium } = require('playwright');
const PA = require('../scripts/load.js');

const ROOT = path.join(__dirname, '..');
const URL_ = 'file://' + path.join(ROOT, 'index.html');
const SHOTS = process.env.SHOTS || '';
const results = [];
let failed = 0;
function ok(name, cond, extra) { results.push((cond ? 'PASS ' : 'FAIL ') + name + (extra ? '  (' + extra + ')' : '')); if (!cond) failed++; }

(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: 1400, height: 900 }, acceptDownloads: true });
  const page = await ctx.newPage();
  const problems = [];
  const offsite = [];
  page.on('console', (m) => { if (m.type() === 'error' || m.type() === 'warning') problems.push(m.type() + ': ' + m.text()); });
  page.on('pageerror', (e) => problems.push('pageerror: ' + e.message));
  ctx.on('request', (r) => { if (!/^(file|blob|data):/.test(r.url())) offsite.push(r.url()); });
  page.on('worker', (w) => w.on('console', (m) => { if (m.type() === 'error') problems.push('worker: ' + m.text()); }));
  const shot = async (n) => { if (SHOTS) await page.screenshot({ path: path.join(SHOTS, n + '.png') }); };
  const waitResult = () => page.waitForSelector('#view-result:not([hidden])', { timeout: 30000 });
  const back = async () => { await page.click('#btn-new'); await page.waitForSelector('#view-intake:not([hidden])'); };

  await page.goto(URL_);
  const csp = await page.$eval('meta[http-equiv="Content-Security-Policy"]', (m) => m.content);
  ok('CSP present with connect-src none', /connect-src 'none'/.test(csp) && /default-src 'none'/.test(csp));
  // the CSP must actually block network calls
  const blocked = await page.evaluate(async () => { try { await fetch('https://example.com/x'); return false; } catch (e) { return true; } });
  ok('fetch() to the internet is blocked by CSP', blocked);
  await page.waitForTimeout(100);
  const probeMsgs = problems.splice(0).filter((m) => !/example\.com/.test(m));
  problems.push(...probeMsgs); // keep only messages unrelated to the deliberate probe
  await shot('01-intake');

  // ---- all demos ----
  const ids = PA.scenarios.list.map((s) => s.id);
  for (const id of ids) {
    const truth = PA.scenarios.build(id).truth;
    await page.click(`#demos button[data-demo="${id}"]`);
    await waitResult();
    const v = await page.evaluate(() => window.__paState.result.verdict.v);
    const fids = await page.evaluate(() => window.__paState.result.findings.map((f) => f.id));
    const exp = Array.isArray(truth.verdict) ? truth.verdict : [truth.verdict];
    const missing = (truth.expect || []).filter((e) => !fids.includes(e.id)).map((e) => e.id);
    ok('demo ' + id + ' → ' + v, exp.includes(v) && !missing.length, missing.length ? 'missing ' + missing.join(',') : '');
    if (id === 'loss' && SHOTS) { await page.waitForTimeout(1500); await shot('02-verdict-loss'); }
    if (id === 'zero-window') await shot('03-verdict-zero-window');
    if (id !== ids[ids.length - 1]) await back();
  }
  await back();

  // ---- evidence jump on the loss demo ----
  await page.click('#demos button[data-demo="loss"]');
  await waitResult();
  const btn = await page.$('#panel-findings button.pkt');
  const no = Number(await btn.getAttribute('data-pkt'));
  await btn.click();
  await page.waitForSelector('#panel-packets:not([hidden]) .pk-row.hit', { timeout: 8000 }).catch(() => {});
  const hitNo = await page.$eval('.pk-row.hit', (r) => r.dataset.no).catch(() => null);
  ok('evidence button jumps to packet #' + no, Number(hitNo) === no, 'highlighted ' + hitNo);
  const vis = await page.$eval('.pk-row.hit', (r) => { const a = r.getBoundingClientRect(), b = document.querySelector('#pk-list').getBoundingClientRect(); return a.top >= b.top && a.bottom <= b.bottom; }).catch(() => false);
  ok('jumped packet is visible in the list', vis);
  await shot('04-packets-jump');
  // scroll the virtual list to the end
  await page.$eval('#pk-list', (l) => { l.scrollTop = l.scrollHeight; });
  await page.waitForTimeout(400);
  const lastRows = await page.$$eval('#pk-list .pk-row', (rs) => rs.length);
  ok('virtual packet list renders rows after scrolling', lastRows > 5, lastRows + ' rows');

  // ---- connections ----
  await page.click('#tab-conns');
  await page.waitForTimeout(200);
  const nconn = await page.$$eval('#panel-conns [data-c]', (r) => r.length);
  ok('connection table lists connections', nconn > 0, String(nconn));
  await shot('05-connections');

  // ---- charts ----
  await page.click('#tab-charts');
  await page.waitForTimeout(1200);
  const painted = await page.$$eval('#panel-charts canvas', (cs) => cs.map((c) => { const x = c.getContext('2d').getImageData(0, 0, c.width, c.height).data; let n = 0; for (let i = 3; i < x.length; i += 4 * 7) if (x[i]) n++; return n; }));
  ok('four charts drawn', painted.length === 4 && painted.every((n) => n > 50), painted.join('/'));
  const moments = await page.$$eval('#moments li', (l) => l.length);
  ok('key moments listed', moments > 0, String(moments));
  await shot('06-charts');
  // drag-zoom on the first chart then double-click reset
  const cv = await page.$('#panel-charts canvas');
  const bb = await cv.boundingBox();
  await page.mouse.move(bb.x + bb.width * 0.3, bb.y + bb.height / 2); await page.mouse.down();
  await page.mouse.move(bb.x + bb.width * 0.6, bb.y + bb.height / 2, { steps: 5 }); await page.mouse.up();
  await page.waitForTimeout(150);
  await cv.dblclick();
  ok('chart zoom and reset without errors', problems.length === 0, problems.join(' | '));

  // ---- report + exports ----
  await page.click('#tab-report');
  await page.waitForTimeout(200);
  const ticket = await page.$eval('#ticket', (t) => t.value);
  ok('ticket text present', ticket.length > 80);
  const dl = async (sel) => { const [d] = await Promise.all([page.waitForEvent('download'), page.click(sel)]); const p = await d.path(); return { name: d.suggestedFilename(), text: fs.readFileSync(p, 'utf8') }; };
  const md = await dl('#exp-md');
  ok('Markdown export downloads', /\.md$/.test(md.name) && /# /.test(md.text), md.name);
  const html = await dl('#exp-html');
  ok('HTML export downloads with own CSP', /\.html$/.test(html.name) && /Content-Security-Policy/.test(html.text) && !/https?:\/\/(?!www\.w3\.org)/.test(html.text.replace(/https:\/\/(github\.com|www\.rfc-editor\.org|datatracker\.ietf\.org|www\.wireshark\.org)[^\s"'<)]*/g, '')), html.name);
  const realIps = [...new Set((md.text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || []))];
  await page.check('#anon');
  await page.waitForTimeout(150);
  const mdA = await dl('#exp-md');
  const htmlA = await dl('#exp-html');
  const ticketA = await page.$eval('#ticket', (t) => t.value);
  const leak = realIps.filter((ip) => mdA.text.includes(ip) || htmlA.text.includes(ip) || ticketA.includes(ip));
  ok('anonymised exports contain none of the ' + realIps.length + ' real IPs', realIps.length > 0 && leak.length === 0 && /\[ip-1\]/.test(mdA.text), leak.join(','));
  if (SHOTS) fs.writeFileSync(path.join(SHOTS, 'export-sample.html'), html.text);
  await shot('07-report');
  await page.uncheck('#anon');

  // ---- open the exported HTML report (offline) ----
  const rp = await ctx.newPage();
  const rpErr = [];
  rp.on('pageerror', (e) => rpErr.push(e.message));
  rp.on('console', (m) => { if (m.type() === 'error') rpErr.push(m.text()); });
  const tmpHtml = path.join(require('os').tmpdir(), 'pa-export-test.html');
  fs.writeFileSync(tmpHtml, html.text);
  await rp.goto('file://' + tmpHtml);
  ok('exported HTML report opens without errors', rpErr.length === 0, rpErr.join(' | '));
  await rp.close();

  // ---- thresholds ----
  await page.click('#tab-thresholds');
  const nth = await page.$$eval('#panel-thresholds tbody tr', (r) => r.length);
  ok('threshold table lists all thresholds', nth === Object.keys(PA.config.T).length, nth + ' rows');

  // ---- keyboard: tabs with arrow keys ----
  await page.focus('#tab-thresholds');
  await page.keyboard.press('ArrowLeft');
  const sel = await page.$eval('[role=tab][aria-selected=true]', (t) => t.id);
  ok('arrow keys move between tabs', sel === 'tab-report', sel);

  // ---- language + theme ----
  await page.click('#lang-de');
  await page.click('#tab-findings');
  const deText = await page.$eval('#verdict', (v) => v.textContent);
  ok('German UI switches verdict text', /Netzwerk|Befund|Urteil|Verlust/.test(deText));
  await shot('08-de');
  await page.click('#btn-theme');
  const theme = await page.evaluate(() => document.documentElement.dataset.theme);
  await shot('09-theme-' + theme);
  await page.click('#btn-theme');
  const theme2 = await page.evaluate(() => document.documentElement.dataset.theme);
  ok('theme toggle switches dark/light', theme !== theme2 && ['dark', 'light'].includes(theme) && ['dark', 'light'].includes(theme2), theme + '→' + theme2);
  await page.click('#lang-en');
  await back();

  // ---- file picker with a pcapng variant ----
  const tmp = require('os').tmpdir();
  const fpath = path.join(tmp, 'variant-qinq.pcapng');
  fs.writeFileSync(fpath, Buffer.from(PA.scenarios.build('fmt-pcapng-qinq').bytes));
  await page.setInputFiles('#file-input', fpath);
  await waitResult();
  const fmt = await page.evaluate(() => window.__paState.result.summary);
  ok('file picker loads pcapng (QinQ)', /pcapng/i.test(JSON.stringify(fmt)));
  await back();

  // ---- drag & drop ----
  const bytes = Array.from(PA.scenarios.build('server-delay').bytes);
  await page.evaluate(async (arr) => {
    const dt = new DataTransfer();
    dt.items.add(new File([new Uint8Array(arr)], 'dropped.pcap', { type: 'application/octet-stream' }));
    const t = document.querySelector('#dropzone');
    for (const type of ['dragenter', 'dragover', 'drop']) t.dispatchEvent(new DragEvent(type, { dataTransfer: dt, bubbles: true, cancelable: true }));
  }, bytes);
  await waitResult();
  const dv = await page.evaluate(() => [window.__paState.file, window.__paState.result.verdict.v]);
  ok('drag & drop analyses the dropped file', dv[0].startsWith('dropped.pcap') && dv[1] === 'server', dv.join(' '));
  await back();

  // ---- many repeated findings are grouped, and a folded finding can still be opened ----
  const many = path.join(tmp, 'many-conns.pcap');
  require('child_process').execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'make-big.js'), many, '3', 'small']);
  await page.setInputFiles('#file-input', many);
  await waitResult();
  const grp = await page.evaluate(() => ({ cards: document.querySelectorAll('#panel-findings .finding').length, total: window.__paState.result.findings.length, folds: document.querySelectorAll('#panel-findings details.more-same').length }));
  ok('repeated findings are grouped (' + grp.total + ' findings, ' + grp.cards + ' cards)', grp.folds > 0 && grp.cards < grp.total / 3 && grp.total > 50, JSON.stringify(grp));
  const hidden = await page.evaluate(() => { const st = window.__paState; const shown = new Set([...document.querySelectorAll('#panel-findings .finding')].map((e) => Number(e.dataset.f))); const f = st.result.findings.find((x) => !shown.has(x.n) && x.conn !== undefined); return f ? f.conn : null; });
  await page.click('#tab-conns');
  await page.evaluate((c) => { const st = window.__paState; st.conn = c; }, hidden);
  await page.evaluate(() => document.querySelector('[data-sort="sev"]').click());
  await page.waitForTimeout(150);
  const gof = await page.$('#panel-conns a[data-gof]');
  if (gof) { await gof.click(); await page.waitForTimeout(300); }
  const revealed = await page.evaluate(() => { const el = document.querySelector('.finding.sel'); return !!el && !!el.closest('details.more-same[open]'); });
  ok('link to a folded finding opens its group', revealed);
  await back();

  // ---- corrupt and unsupported files ----
  const bad = path.join(tmp, 'not-a-capture.pcap');
  fs.writeFileSync(bad, 'hello this is not a capture file at all '.repeat(10));
  await page.setInputFiles('#file-input', bad);
  await page.waitForSelector('#view-error:not([hidden])', { timeout: 10000 });
  const et = await page.$eval('#error-text', (e) => e.textContent);
  ok('non-capture file shows clear message', et.length > 20, et.slice(0, 70));
  await shot('10-error');
  await page.click('#btn-error-back');
  const trunc = path.join(tmp, 'truncated.pcap');
  const full = PA.scenarios.build('loss').bytes;
  fs.writeFileSync(trunc, Buffer.from(full.subarray(0, Math.floor(full.length * 0.6) + 7)));
  await page.setInputFiles('#file-input', trunc);
  await waitResult();
  const warn = await page.evaluate(() => JSON.stringify(window.__paState.result.findings.map((f) => f.id)));
  ok('truncated file is analysed with a parse warning', /capture\.parse/.test(warn));
  await back();

  // ---- cancel during a larger analysis ----
  const big = path.join(tmp, 'cancel-test.pcap');
  if (!fs.existsSync(big) || fs.statSync(big).size < 60e6) {
    const one = Buffer.from(PA.scenarios.build('healthy').bytes);
    const hdr = one.subarray(0, 24), body = one.subarray(24);
    const fd = fs.openSync(big, 'w'); fs.writeSync(fd, hdr);
    for (let i = 0; i < Math.ceil(60e6 / body.length); i++) fs.writeSync(fd, body);
    fs.closeSync(fd);
  }
  await page.setInputFiles('#file-input', big);
  await page.waitForSelector('#view-busy:not([hidden])');
  await page.waitForTimeout(150);
  await page.click('#btn-cancel');
  await page.waitForSelector('#view-intake:not([hidden])', { timeout: 5000 }).catch(() => {});
  const intake = await page.$eval('#view-intake', (v) => !v.hidden);
  ok('cancel stops the analysis and returns to the start', intake);

  // ---- mobile layout ----
  await page.setViewportSize({ width: 390, height: 844 });
  await page.click('#demos button[data-demo="mixed"]');
  await waitResult();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  ok('no horizontal scroll on a 390 px phone', overflow <= 1, overflow + ' px');
  await page.waitForTimeout(1800);
  await shot('11-mobile');
  await page.click('#tab-report');
  await shot('12-mobile-report');

  ok('no console errors or warnings', problems.length === 0, problems.slice(0, 5).join(' | '));
  ok('no request left the browser (only file:, blob:, data:)', offsite.length === 0, offsite.slice(0, 3).join(' '));
  await browser.close();

  const head = `PCAP Autopsy – browser end-to-end test\n${new Date().toISOString()}  Chromium ${browser.version()}  file://index.html\n\n`;
  const body = results.join('\n') + `\n\n${results.length - failed}/${results.length} passed\n`;
  fs.mkdirSync(path.join(ROOT, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'docs', 'e2e-results.txt'), head + body);
  console.log(head + body);
  process.exit(failed ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(2); });
