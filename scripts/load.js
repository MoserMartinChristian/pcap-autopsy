// Loads the core modules into globalThis.PA for Node scripts and tests.
'use strict';
const path = require('path');
for (const f of ['config', 'parser', 'store', 'analyze', 'pipeline', 'gen', 'scenarios', 'i18n', 'report']) {
  try { require(path.join(__dirname, '..', 'src', f + '.js')); } catch (e) { if (!(e.code === 'MODULE_NOT_FOUND' && f === 'report')) throw e; }
}
module.exports = globalThis.PA;
