# Comparison with tshark

`node scripts/compare-tshark.js` runs every synthetic capture through PCAP Autopsy and through
TShark 4.2.2 (Wireshark's command-line tool) and compares the counts. The raw table is in
[tshark-comparison.raw.md](tshark-comparison.raw.md).

**Result:** packets and TCP connections are identical for all 30 captures, including all seven
format and link-type variants. Retransmissions, dup ACKs, zero windows and out-of-order agree for
26 of 30 captures. Four captures differ in 7 cells:

| Capture | Field | PCAP Autopsy | tshark | Ground truth (generator) |
|---|---|---:|---:|---:|
| loss | retransmissions / out-of-order | 11 / 2 | 7 / 6 | 11 retransmissions, 2 reordered segments |
| icmp-ptb | retransmissions / out-of-order | 5 / 0 | 3 / 2 | 5 resent after the ICMP message, no reordering |
| mixed | retransmissions / out-of-order | 7 / 0 | 4 / 3 | 7 retransmissions, no reordering |
| trap-keepalive | dup ACKs | 0 | 1 | keepalive ACK, not a dup ACK |

## Why they differ

**Retransmission vs. out-of-order.** When a segment is lost *before* the capture point, the capture
first shows a gap and later the segment that fills it. Wireshark calls the late segment
"out-of-order" if it arrives soon after the gap (its threshold is based on the RTT it has seen), and
"retransmission" otherwise. PCAP Autopsy calls it a retransmission when there is sender-side evidence
for one (duplicate ACKs or SACK blocks for the gap, or a delay of at least 0.9 × the minimum RTO),
and out-of-order only when the gap is filled within 3 ms without such evidence (threshold
`oooMaxMs`). In each of these captures the sum of both counts is the same in both tools; only the
labels differ. The generator knows the truth, and it matches PCAP Autopsy's labels.

This matters for the verdict: real reordering points to parallel paths or load balancing; loss
before the capture point points to the path upstream. Calling the second one "out-of-order" would
hide loss.

**Keepalive ACK.** In trap-keepalive the reply to a TCP keepalive repeats the previous ACK number.
Wireshark marks it as a dup ACK. PCAP Autopsy recognises it as the answer to a keepalive and does
not count it, so keepalives cannot start a fast-retransmit diagnosis.

## Limits of this comparison

- All captures are synthetic. A comparison on real captures has not been done.
- Only counts are compared, not individual packet numbers.
- tshark 4.2.2 only. Newer Wireshark versions may label edge cases differently.
