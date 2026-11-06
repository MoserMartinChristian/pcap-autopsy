#!/usr/bin/env node
/*
 * Builds index.html: one self-contained file with CSS, core, worker and UI inlined.
 * Computes the sha256 hashes of the executed inline scripts and writes them into a strict CSP.
 * Usage: node build.js   (no dependencies)
 */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.join(__dirname, 'src');
const read = (f) => fs.readFileSync(path.join(SRC, f), 'utf8');
const CORE_FILES = ['config', 'parser', 'store', 'analyze', 'pipeline', 'gen', 'scenarios', 'i18n', 'report'];
const APP_FILES = ['charts', 'app'];

function check(name, text) {
  if (/<\/script/i.test(text)) throw new Error(name + ' contains "</script"');
  if (/<!--/.test(text)) throw new Error(name + ' contains "<!--"');
  const ext = text.match(/\b(?:src|href)\s*=\s*["']https?:/i) || text.match(/\b(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon|importScripts)\s*\(/);
  if (ext) throw new Error(name + ' contains a network call: ' + ext[0]);
}

function build() {
const core = '\n' + CORE_FILES.map((f) => { const t = read(f + '.js'); check(f, t); return t; }).join('\n') + '\n';
const app = '\n' + APP_FILES.map((f) => { const t = read(f + '.js'); check(f, t); return t; }).join('\n') + '\n';
const worker = '\n' + read('worker.js') + '\n';
check('worker', worker);
const css = read('styles.css');
const hash = (s) => "'sha256-" + crypto.createHash('sha256').update(s, 'utf8').digest('base64') + "'";

const csp = [
  "default-src 'none'",
  'script-src ' + hash(core) + ' ' + hash(app),
  'worker-src blob:',
  "style-src 'unsafe-inline'",
  'img-src data: blob:',
  "connect-src 'none'",
  "font-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "form-action 'none'",
  "base-uri 'none'",
].join('; ');

let html = read('template.html');
// plain slice-replace: avoids String.replace $-patterns in the inlined source
function rep(marker, text) { const i = html.indexOf(marker); if (i < 0) throw new Error('marker missing: ' + marker); html = html.slice(0, i) + text + html.slice(i + marker.length); }
rep('/*CSP*/', csp);
rep('/*INLINE:styles.css*/', css);
rep('\n/*INLINE_CORE*/\n', core);
rep('\n/*INLINE:worker.js*/\n', worker);
rep('\n/*INLINE_APP*/\n', app);

// sanity: every executed inline script must be covered by a hash
const scripts = [...html.matchAll(/<script(?![^>]*type="text\/plain")[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);
const allowed = new Set([hash(core), hash(app)]);
for (const s of scripts) if (!allowed.has(hash(s))) throw new Error('inline script without CSP hash');
if (/(?:src|href)=["']https?:/i.test(html)) throw new Error('external reference in HTML');

  return html;
}

if (require.main === module) {
  const html = build();
  fs.writeFileSync(path.join(__dirname, 'index.html'), html);
  console.log('index.html', (html.length / 1024).toFixed(0) + ' KB, CSP hashes for 2 inline scripts');
}
module.exports = { build };
