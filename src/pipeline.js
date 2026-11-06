/*
 * PCAP Autopsy – pipeline: bytes → parser → store → analysis.
 * Used by the Web Worker (chunked File reads) and by the Node tests (whole buffers).
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  function createPipeline() {
    const store = PA.store.createStore();
    const reader = PA.parser.createReader((p) => store.add(p));
    return {
      store,
      reader,
      push(chunk) { reader.push(chunk); },
      finish() {
        const info = reader.end();
        const result = PA.analyze.analyze(store, info);
        result.parse = info;
        return result;
      },
    };
  }
  // convenience for tests: analyse a complete Uint8Array, in chunks to exercise the streaming code
  function analyzeBytes(bytes, chunk) {
    const p = createPipeline();
    const n = chunk || 65536;
    for (let o = 0; o < bytes.length; o += n) p.push(bytes.subarray(o, Math.min(bytes.length, o + n)));
    const r = p.finish();
    r.store = p.store;
    return r;
  }
  PA.pipeline = { createPipeline, analyzeBytes };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.pipeline;
})(typeof globalThis !== 'undefined' ? globalThis : self);
