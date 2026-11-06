/*
 * PCAP Autopsy – central thresholds.
 * Every detector reads its limits from here. The UI and the README show this table,
 * so a value and its reason live in exactly one place.
 */
(function (G) {
  'use strict';
  const PA = G.PA || (G.PA = {});

  // value, unit, and a short rationale (EN / DE)
  const T = {
    minPacketsForVerdict: { v: 30, unit: 'packets', en: 'Below this many packets the capture is too thin for a cause verdict.', de: 'Unter dieser Paketzahl ist die Capture zu dünn für ein Urteil.' },
    minDurationS: { v: 2, unit: 's', en: 'Shorter captures rarely contain a full request/response cycle or a retransmission timeout.', de: 'Kürzere Captures enthalten selten einen vollständigen Request/Response-Zyklus oder einen RTO.' },
    synWaitS: { v: 1, unit: 's', en: 'A SYN counts as unanswered only if the capture continues this long afterwards (initial RTO is 1 s, RFC 6298).', de: 'Ein SYN gilt nur als unbeantwortet, wenn die Capture danach noch so lange läuft (initialer RTO 1 s, RFC 6298).' },
    handshakeRttWarnMs: { v: 300, unit: 'ms', en: 'Handshake RTT above this is unusual outside satellite or intercontinental paths.', de: 'Handshake-RTT darüber ist außerhalb von Satelliten- oder Interkontinentalstrecken ungewöhnlich.' },
    lossWarnPct: { v: 0.5, unit: '%', en: 'From about 0.5 % loss, TCP throughput drops noticeably (Mathis et al.: rate ∝ MSS / (RTT·√p)).', de: 'Ab etwa 0,5 % Verlust sinkt der TCP-Durchsatz spürbar (Mathis et al.: Rate ∝ MSS / (RTT·√p)).' },
    lossCritPct: { v: 2, unit: '%', en: 'At 2 % loss a single flow typically reaches only a fraction of the path capacity.', de: 'Bei 2 % Verlust erreicht ein Flow meist nur einen Bruchteil der Pfadkapazität.' },
    lossMinSegments: { v: 20, unit: 'segments', en: 'Loss rates from fewer data segments are not statistically meaningful; single events are still listed.', de: 'Verlustraten aus weniger Datensegmenten sind nicht aussagekräftig; Einzelereignisse werden trotzdem genannt.' },
    dupAckThreshold: { v: 2, unit: 'dup ACKs', en: 'RFC 5681 uses 3 duplicate ACKs; with SACK (RFC 6675) and Linux, 2 are common. Same rule as Wireshark.', de: 'RFC 5681 nutzt 3 Duplicate ACKs; mit SACK (RFC 6675) und Linux sind 2 üblich. Gleiche Regel wie Wireshark.' },
    rtoMinMs: { v: 200, unit: 'ms', en: 'Linux minimum RTO is 200 ms. A retransmission after a silent gap at least this long and without dup ACKs is classed as timeout.', de: 'Der minimale RTO unter Linux ist 200 ms. Eine Wiederholung nach einer stillen Pause dieser Länge ohne Dup-ACKs gilt als Timeout.' },
    oooMaxMs: { v: 3, unit: 'ms', en: 'A segment that fills a gap within this time and without dup-ACK or SACK evidence counts as reordering; otherwise as a retransmission. Wireshark uses 3 ms only when it has no RTT sample, else the first RTT, so it calls more gap fills out-of-order (see docs/tshark-comparison.md).', de: 'Ein Segment, das eine Lücke innerhalb dieser Zeit und ohne Hinweis durch Dup-ACKs oder SACK füllt, gilt als Reordering, sonst als Wiederholung. Wireshark nutzt 3 ms nur ohne RTT-Messung, sonst die erste RTT, und nennt daher mehr Lückenfüller „out-of-order“ (siehe docs/tshark-comparison.md).' },
    zeroWindowCritMs: { v: 1000, unit: 'ms', en: 'A receiver that stays at zero window this long blocks the sender for a user-visible time.', de: 'Bleibt der Empfänger so lange bei Fenster null, blockiert er den Sender spürbar.' },
    windowFullMin: { v: 3, unit: 'events', en: 'A few window-full events are normal at the start; repeated ones mean the receiver limits the flow.', de: 'Einzelne Window-Full-Ereignisse sind am Anfang normal; wiederholte zeigen, dass der Empfänger bremst.' },
    windowLimitedFraction: { v: 0.5, unit: 'share', en: 'If at least this share of window-sized rounds ends with the window exhausted, the receive window is the bottleneck.', de: 'Endet mindestens dieser Anteil der Runden (je ein Fenster voll Daten) mit ausgeschöpftem Fenster, ist das Empfangsfenster der Engpass.' },
    windowCapMbps: { v: 100, unit: 'Mbit/s', en: 'A window-limited flow is reported only if window ÷ RTT caps it below this rate; above it, the access link is usually the real limit.', de: 'Ein fensterbegrenzter Flow wird nur gemeldet, wenn Fenster ÷ RTT ihn unter diese Rate drückt; darüber ist meist die Zugangsleitung die eigentliche Grenze.' },
    serverDelayWarnMs: { v: 500, unit: 'ms', en: 'Time from request to first response byte; above this users notice. Must also exceed 5× the network RTT.', de: 'Zeit von Request bis zum ersten Antwortbyte; darüber merken es Nutzer. Muss zusätzlich das 5-Fache der Netz-RTT übersteigen.' },
    serverDelayCritMs: { v: 2000, unit: 'ms', en: 'Response delays above 2 s usually trigger client or proxy timeouts.', de: 'Antwortzeiten über 2 s lösen oft Timeouts bei Client oder Proxy aus.' },
    delayVsRttFactor: { v: 5, unit: '× RTT', en: 'A wait counts as host-side only if it is much longer than the network round trip.', de: 'Eine Wartezeit zählt nur dann als Host-seitig, wenn sie deutlich länger als die Netz-RTT ist.' },
    idleGapMs: { v: 500, unit: 'ms', en: 'A pause in an ongoing transfer, with all data acknowledged and the window open, comes from the sending application.', de: 'Eine Pause in einer laufenden Übertragung mit allen Daten bestätigt und offenem Fenster kommt von der sendenden Anwendung.' },
    delAck40Ms: { v: 40, unit: 'ms', en: 'Linux delayed-ACK minimum (TCP_DELACK_MIN).', de: 'Linux-Minimum für Delayed ACK (TCP_DELACK_MIN).' },
    delAck200Ms: { v: 200, unit: 'ms', en: 'Classic delayed-ACK timer (Windows, BSD, RFC 1122 upper bound 500 ms).', de: 'Klassischer Delayed-ACK-Timer (Windows, BSD; RFC 1122 erlaubt bis 500 ms).' },
    delAckToleranceMs: { v: 12, unit: 'ms', en: 'Timer jitter allowed around 40 ms / 200 ms (scaled ×2 for 200 ms).', de: 'Erlaubte Timer-Abweichung um 40 ms / 200 ms (für 200 ms doppelt).' },
    delAckMinCount: { v: 2, unit: 'events', en: 'One stall could be chance; a repeated stall at the same timer value is a pattern.', de: 'Ein einzelner Stau kann Zufall sein; wiederholte Staus mit gleichem Timerwert sind ein Muster.' },
    bloatFactor: { v: 3, unit: '× min RTT', en: 'RTT under load this many times the idle minimum points to a growing queue (bufferbloat).', de: 'RTT unter Last um diesen Faktor über dem Minimum deutet auf eine wachsende Queue hin (Bufferbloat).' },
    bloatMinMs: { v: 50, unit: 'ms', en: 'The increase must also be at least this large in absolute terms.', de: 'Der Anstieg muss zusätzlich absolut so groß sein.' },
    bloatMinSamples: { v: 30, unit: 'samples', en: 'Correlation needs enough RTT samples.', de: 'Die Korrelation braucht genug RTT-Messwerte.' },
    bloatMinCorr: { v: 0.5, unit: 'ρ', en: 'Spearman correlation between bytes in flight and RTT; RTT must rise with load, not randomly.', de: 'Spearman-Korrelation zwischen Bytes in Flight und RTT; die RTT muss mit der Last steigen, nicht zufällig.' },
    pmtudMinLen: { v: 1200, unit: 'bytes', en: 'Only segments at least this large are candidates for a PMTUD blackhole (smaller ones fit even tunnel MTUs).', de: 'Nur Segmente ab dieser Größe kommen für ein PMTUD-Blackhole in Frage (kleinere passen auch durch Tunnel).' },
    pmtudMinRetrans: { v: 2, unit: 'retransmissions', en: 'The same large segment must be repeated at least this often without an ACK.', de: 'Dasselbe große Segment muss mindestens so oft ohne ACK wiederholt werden.' },
    mssDiffBytes: { v: 40, unit: 'bytes', en: 'Different MSS values on the two sides suggest MSS clamping or a tunnel on one side.', de: 'Unterschiedliche MSS-Werte auf beiden Seiten deuten auf MSS-Clamping oder einen Tunnel hin.' },
    rstTtlDelta: { v: 3, unit: 'hops', en: 'A RST whose TTL/hop limit differs this much from the same peer’s other packets was likely sent by a device in the path.', de: 'Ein RST, dessen TTL/Hop Limit um so viel von den übrigen Paketen der Gegenstelle abweicht, kam wahrscheinlich von einem Gerät im Pfad.' },
    dnsSlowMs: { v: 300, unit: 'ms', en: 'A cached answer takes a few ms, a recursive one usually < 150 ms. Above this, name resolution adds visible delay.', de: 'Eine Antwort aus dem Cache dauert wenige ms, eine rekursive meist < 150 ms. Darüber verzögert DNS spürbar.' },
    dnsTimeoutS: { v: 2, unit: 's', en: 'A query counts as unanswered if the capture runs this long afterwards without a reply (typical resolver retry interval).', de: 'Eine Anfrage gilt als unbeantwortet, wenn die Capture danach so lange ohne Antwort läuft (übliches Retry-Intervall).' },
    tlsSlowMs: { v: 1000, unit: 'ms', en: 'A TLS handshake needs 1–2 RTTs plus crypto; above this and above 4× RTT the server or a middlebox is slow.', de: 'Ein TLS-Handshake braucht 1–2 RTTs plus Krypto; darüber und über 4× RTT ist Server oder Middlebox langsam.' },
    pointClear: { v: 0.8, unit: 'share', en: 'Share of the RTT on one side of the capture point needed to call the capture "near client" or "near server".', de: 'Anteil der RTT auf einer Seite des Messpunkts, ab dem die Capture als „nah am Client“ oder „nah am Server“ gilt.' },
  };

  const SEV = { critical: 3, warning: 2, info: 0 };
  const CONF = { high: 1, medium: 0.6, low: 0.3 };

  PA.config = {
    T,
    th: (k) => T[k].v,
    SEV,
    CONF,
    // verdict: top category must have at least this score and beat the runner-up by this factor
    verdict: { minScore: 1, dominance: 2 },
    // limits of what the tool accepts
    // testedMB / testedPackets: measured with scripts/measure-size.js, see README "Size limits"
    limits: { maxRecordBytes: 262144, chunkBytes: 16 * 1024 * 1024, testedMB: 8194, testedPackets: 8326579 },
    version: '1.0.0',
  };
  if (typeof module !== 'undefined' && module.exports) module.exports = PA.config;
})(typeof globalThis !== 'undefined' ? globalThis : self);
