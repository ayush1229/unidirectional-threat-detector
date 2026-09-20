# IDS benchmark sources and scope

Official references inspected on 2026-09-20:

- [Suricata offline command-line options](https://docs.suricata.io/en/suricata-7.0.17/command-line-options.html): `-r` reads captures without live network capture.
- [Zeek invocation](https://docs.zeek.org/en/master/tutorial/invoking-zeek.html): offline packet processing and checksum handling.
- [Snort Community rules](https://www.snort.org/faq/what-are-community-rules): public Talos-certified ruleset; downloaded separately from the packaged engine.
- [ET Open Suricata 7.0.3 rules announcement](https://forum.suricata.io/t/emerging-threats-pro-open-ruleset-for-suricata-7-0-3-now-available/4714): compatible public rules feed.
- [OSSEC documentation](https://www.ossec.net/docs/): host log analysis, file integrity, registry and rootkit monitoring. These inputs and their truth labels do not exist in this packet-only experiment. OSSEC receives N/A rather than an invented packet-detection score. Feeding it another IDS's alerts would measure downstream log processing, not independent detection.

No external dataset was downloaded. The new synthetic PCAPs total 4,129,288
bytes. Downloaded files are IDS software, runtime libraries, and signature
rules; hashes and sources are in the run's `tool_download_manifest.json`.

Public rule selection, custom behavioral rules, and the frozen learned model
are different configurations. Their results must retain those names. A custom
rule's success on these simple scenarios is not a claim about a product's
default coverage or external generalization. A new random seed prevents reuse
of previous predictions, but does not make synthetic traffic an independent
real-world dataset. The three repeats per profile provide only a small
functional test, not a precise estimate of deployment performance.

All comparisons use episode-level alert presence. A positive alert of the wrong
class still counts in the binary any-threat measure; individual head metrics
are necessary to assess classification. Uncertain model decisions are recorded
as abstentions, even where binary alert-presence counts report zero alerts.
