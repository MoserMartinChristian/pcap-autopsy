#!/usr/bin/env node
/*
 * Measures how large a capture index.html can analyse in headless Chromium.
 *   node scripts/measure-size.js file1.pcap [file2.pcap ...]
 * Prints time to verdict, peak memory of all Chromium processes (RSS) and the verdict.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { chromium } = require('playwright');

function chromeRss() {
  try { return execSync("ps -eo rss,comm | grep -i -E 'chrom|headless' | awk '{s+=$1} END {print s}'").toString().trim() * 1024; } catch (e) { return 0; }
}
(async () => {
  const rows = [];
  for (const f of process.argv.slice(2)) {
    const browser = await chromium.launch();
    const page = await browser.newPage();
    const errs = [];
    page.on('pageerror', (e) => errs.push(e.message));
    await page.goto('file://' + path.join(__dirname, '..', 'index.html'));
    const base = chromeRss();
    let peak = base;
    const iv = setInterval(() => { peak = Math.max(peak, chromeRss()); }, 250);
    const t0 = Date.now();
    await page.setInputFiles('#file-input', f);
    const outcome = await Promise.race([
      page.waitForSelector('#view-result:not([hidden])', { timeout: 0 }).then(() => 'result'),
      page.waitForSelector('#view-error:not([hidden])', { timeout: 0 }).then(() => 'error'),
    ]);
    const ms = Date.now() - t0;
    clearInterval(iv);
    const info = outcome === 'result'
      ? await page.evaluate(() => { const r = window.__paState.result; return r.verdict.v + ', ' + r.summary.packets + ' packets, ' + r.connTotal + ' connections, analysis ' + r.analysisMs + ' ms'; })
      : await page.$eval('#error-text', (e) => e.textContent) + ' [' + await page.evaluate(() => window.__paLastError || '') + ']';
    // UI still responsive? switch tabs and scroll the packet list
    let ui = 'n/a';
    if (outcome === 'result') {
      const t1 = Date.now();
      await page.click('#tab-packets'); await page.waitForSelector('#pk-list .pk-row');
      await page.$eval('#pk-list', (l) => { l.scrollTop = l.scrollHeight / 2; }); await page.waitForTimeout(300);
      await page.click('#tab-charts'); await page.waitForTimeout(500);
      ui = (Date.now() - t1) + ' ms';
    }
    const row = { file: path.basename(f), mb: (fs.statSync(f).size / 1048576).toFixed(0), outcome, seconds: (ms / 1000).toFixed(1), peakMB: (peak / 1048576).toFixed(0), info, ui, errors: errs.join(' | ') };
    console.log(JSON.stringify(row));
    rows.push(row);
    await browser.close();
  }
})().catch((e) => { console.error(e); process.exit(2); });
