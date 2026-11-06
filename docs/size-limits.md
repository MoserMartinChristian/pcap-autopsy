# Size limits (measured)

Measured on 2026-11-05 with `scripts/make-big.js` + `scripts/measure-size.js`:
headless Chromium 153 on Linux, 4 vCPU, 16 GB RAM, no swap. The file is opened from `file://`
through the normal file picker, so the numbers include reading, parsing, analysis in the
worker, transfer of the result to the page, and rendering.

| File | Size | Packets | Connections | Time to verdict | Peak memory (all Chromium processes) | Result |
|---|---:|---:|---:|---:|---:|---|
| typical mix | 516 MiB | 524,692 | 1,672 | 4.0 s | 610 MB | ok |
| typical mix | 1,029 MiB | 1,046,012 | 3,301 | 7.7 s | 690 MB | ok |
| typical mix | 2,053 MiB | 2,086,093 | 6,471 | 13.2 s | 881 MB | ok |
| typical mix | 4,100 MiB | 4,166,255 | 12,403 | 23.6 s | 1,099 MB | ok |
| typical mix | 8,194 MiB | 8,326,579 | 23,047 | 44.2 s | 1,656 MB | ok |
| worst case (short connections) | 1,024 MiB | 1,599,264 | 102,804 | 11.7 s | 1,467 MB | ok |
| worst case (short connections) | 2,048 MiB | 3,198,422 | 154,950 | 23.5 s | 2,033 MB | ok |
| worst case (short connections) | 4,096 MiB | 6,396,854 | 195,674 | 45.8 s | 2,911 MB | ok |

"Typical mix" stitches the healthy, loss, server-delay, zero-window and bufferbloat scenarios
(mostly full-size segments). "Worst case" stitches DNS, SYN-timeout and RST-on-SYN scenarios:
many tiny connections, each with its own finding.

## What limits the tool

- **Memory grows with packets and connections, not with bytes.** Packet payloads are not kept.
  Each packet costs about 60 bytes in typed arrays (the arrays double, so expect up to twice that
  while growing). Each connection and finding costs a few hundred bytes more.
- The largest file tested was 8 GB. No failure was reached, so the hard limit is higher; it depends
  on the RAM of the machine. The tool shows a clear "out of memory" message instead of crashing
  if the browser refuses an allocation.
- One TCP connection that transfers more than 4 GB in one direction is analysed with sequence
  wrap-around unwrapping, but this has not been tested with real data.

## Bugs this measurement found (fixed)

1. A stack overflow ("Maximum call stack size exceeded") on files with many findings:
   `Math.max(...array)` and `push(...array)` over large arrays. Replaced with loops.
2. A quadratic step when building the connection summary (each connection scanned all findings):
   13 s → 1.8 s for 100,000 connections.
3. The UI rendered every finding card (16,659 "RST on SYN" cards). Repeated findings are now
   grouped: the first three are shown, the rest open on demand.

## Not measured

- Firefox and Safari (only Chromium is installed here). Firefox's worker memory limits differ.
- Windows and macOS. Chrome on a 8 GB laptop will reach its limit earlier than this 16 GB machine.
- Real captures. All numbers come from synthetic traffic.
