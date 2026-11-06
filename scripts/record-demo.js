#!/usr/bin/env node
/*
 * Records docs/demo.gif (and docs/demo.mp4) plus README screenshots from index.html.
 *   node build.js && node scripts/record-demo.js
 * Needs Playwright (Chromium) and ffmpeg. A fake cursor and a fake file icon are drawn into the
 * page for the recording only; nothing in the tool itself changes.
 */
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { chromium } = require('playwright');
const PA = require('./load.js');

const ROOT = path.join(__dirname, '..');
const DOCS = path.join(ROOT, 'docs');
const URL_ = 'file://' + path.join(ROOT, 'index.html');
const W = 1280, H = 760;

async function cursor(page) {
  await page.evaluate(() => {
    const c = document.createElement('div');
    c.id = '__cursor';
    c.innerHTML = '<svg width="22" height="22" viewBox="0 0 22 22"><path d="M3 2l15 9-6.5 1.5L8.5 19z" fill="#fff" stroke="#111" stroke-width="1.4" stroke-linejoin="round"/></svg>';
    Object.assign(c.style, { position: 'fixed', left: '0', top: '0', zIndex: 99999, pointerEvents: 'none', transition: 'transform .05s linear' });
    document.body.appendChild(c);
    document.addEventListener('mousemove', (e) => { c.style.transform = `translate(${e.clientX - 3}px, ${e.clientY - 2}px)`; }, true);
  });
}
async function glide(page, x, y, ms) {
  const steps = Math.max(8, Math.round(ms / 16));
  await page.mouse.move(x, y, { steps });
}

(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pa-rec-'));
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, colorScheme: 'dark', recordVideo: { dir: tmp, size: { width: W, height: H } } });
  const page = await ctx.newPage();
  await page.goto(URL_);
  await page.evaluate(() => { document.documentElement.dataset.theme = 'dark'; });
  await cursor(page);
  await page.mouse.move(W - 160, H - 120);
  await page.waitForTimeout(900);

  // a file icon is "dragged" in from the corner
  const bytes = Array.from(PA.scenarios.build('server-delay').bytes);
  await page.evaluate(() => {
    const f = document.createElement('div');
    f.id = '__file';
    f.innerHTML = '<svg width="54" height="64" viewBox="0 0 54 64"><path d="M4 2h32l14 14v44a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2z" fill="#1b232c" stroke="#33d6c4" stroke-width="2"/><path d="M10 38h7l3-8 5 15 4-11 2 4h7" fill="none" stroke="#33d6c4" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/></svg><div style="font:600 12px/1.2 ui-monospace,monospace;color:#e6edf3;background:#0b0f14cc;padding:3px 6px;border-radius:4px;margin-top:4px;white-space:nowrap">checkout-slow.pcap</div>';
    Object.assign(f.style, { position: 'fixed', left: '0', top: '0', zIndex: 99998, pointerEvents: 'none', textAlign: 'center' });
    document.body.appendChild(f);
    document.addEventListener('mousemove', (e) => { f.style.transform = `translate(${e.clientX - 20}px, ${e.clientY - 10}px)`; }, true);
  });
  const dz = await page.$('#dropzone');
  const b = await dz.boundingBox();
  await glide(page, b.x + b.width * 0.7, b.y + b.height * 0.75, 500);
  // drag veil on
  await page.evaluate(() => {
    const dt = new DataTransfer(); dt.items.add(new File([new Uint8Array(1)], 'x.pcap'));
    window.dispatchEvent(new DragEvent('dragenter', { dataTransfer: dt, bubbles: true, cancelable: true }));
  });
  await glide(page, b.x + b.width / 2, b.y + b.height / 2, 700);
  await page.waitForTimeout(250);
  await page.evaluate(async (arr) => {
    document.getElementById('__file').remove();
    const dt = new DataTransfer();
    dt.items.add(new File([new Uint8Array(arr)], 'checkout-slow.pcap'));
    document.querySelector('#dropzone').dispatchEvent(new DragEvent('drop', { dataTransfer: dt, bubbles: true, cancelable: true }));
    window.dispatchEvent(new DragEvent('dragleave', { bubbles: true }));
  }, bytes);
  await page.waitForSelector('#view-result:not([hidden])');
  await page.waitForTimeout(2600); // verdict reveal

  // first finding, then its evidence
  const card = await page.$('#panel-findings .finding');
  const cb = await card.boundingBox();
  await glide(page, cb.x + 300, Math.min(H - 60, cb.y + 20), 600);
  await page.mouse.wheel(0, cb.y - 150);
  await page.waitForTimeout(1400);
  const pkt = await page.$('#panel-findings button.pkt');
  const pb = await pkt.boundingBox();
  await glide(page, pb.x + pb.width / 2, pb.y + pb.height / 2, 700);
  await page.waitForTimeout(300);
  await pkt.click();
  await page.waitForTimeout(1800);

  // charts
  const tab = await page.$('#tab-charts');
  const tb = await tab.boundingBox();
  await glide(page, tb.x + tb.width / 2, tb.y + tb.height / 2, 600);
  await tab.click();
  await page.waitForTimeout(600);
  await page.mouse.wheel(0, 380);
  await page.waitForTimeout(1900);

  await ctx.close();
  const vid = fs.readdirSync(tmp).find((f) => f.endsWith('.webm'));
  const webm = path.join(tmp, vid);
  fs.mkdirSync(DOCS, { recursive: true });
  const gif = path.join(DOCS, 'demo.gif'), mp4 = path.join(DOCS, 'demo.mp4'), pal = path.join(tmp, 'pal.png');
  const vf = 'fps=15,scale=960:-1:flags=lanczos';
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', '0.6', '-i', webm, '-vf', vf + ',palettegen=stats_mode=diff', pal]);
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', '0.6', '-i', webm, '-i', pal, '-lavfi', vf + ' [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle', gif]);
  execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-ss', '0.6', '-i', webm, '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '24', '-movflags', '+faststart', '-vf', 'scale=1280:-2', mp4]);
  console.log('docs/demo.gif', (fs.statSync(gif).size / 1048576).toFixed(1) + ' MB', ' docs/demo.mp4', (fs.statSync(mp4).size / 1048576).toFixed(1) + ' MB');

  // ---- screenshots for the README ----
  const shotCtx = async (scheme, vp, scale) => browser.newContext({ viewport: vp, colorScheme: scheme, deviceScaleFactor: scale });
  const shots = [
    ['screenshot-dark.png', 'dark', { width: 1400, height: 900 }, 'loss', null],
    ['screenshot-light.png', 'light', { width: 1400, height: 900 }, 'zero-window', null],
    ['screenshot-charts.png', 'dark', { width: 1400, height: 1000 }, 'loss', 'charts'],
    ['screenshot-mobile.png', 'dark', { width: 390, height: 844 }, 'mixed', null],
  ];
  for (const [name, scheme, vp, demo, tabName] of shots) {
    const c = await shotCtx(scheme, vp, 2);
    const p = await c.newPage();
    await p.goto(URL_);
    await p.evaluate((t) => { document.documentElement.dataset.theme = t; }, scheme);
    await p.click(`#demos button[data-demo="${demo}"]`);
    await p.waitForSelector('#view-result:not([hidden])');
    await p.waitForTimeout(2200);
    if (tabName) { await p.click('#tab-' + tabName); await p.waitForTimeout(800); await p.evaluate(() => window.scrollTo(0, document.querySelector('#tabs').offsetTop - 10)); await p.waitForTimeout(300); }
    await p.screenshot({ path: path.join(DOCS, name) });
    await c.close();
    console.log('docs/' + name);
  }
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
