# Fresh unidirectional IDS benchmark

Run `python -m experiments.ids_benchmark --output NEW_DIRECTORY --stage all`.
Generation refuses to reuse its PCAP directory; inference refuses to overwrite
the event log. A cryptographically generated seed is recorded in the manifest.
`--stage generate` and `--stage infer` allow other tools to consume the PCAPs
while model inference runs. The default corpus contains 42 independent episodes
(three repetitions of fourteen profiles), with five attack labels supported by
the current pipeline and six benign profiles including close behavioral negatives.

Feed each `episodes.json` entry's `pcap` to each IDS with fresh tool state.
Ground truth is episode-level: one positive intent label or verified synthetic
benign intent. Aggregate detections by any alert across an episode. Other attack
episodes are negatives for a head, but report benign false positives separately.
All packets are one-way; generation audits serialized packet address pairs for
reverse traffic. No attack packets are transmitted to a network.

The model uses the current release pointer, frozen Agent 1 models and Agent 2
bundle, the actual PCAP reader, observation extractor, Publisher bridge and
DetectionPipeline. Missing configured paths can be relocated only to the same
basename alongside the current Agent 1 config; that exception and model hashes
are saved. `model_events.jsonl` contains all event decisions and model scores;
`model_episodes.json` contains three distinct outputs:

- `production_labels`: actual decisions with the existing approval and gates.
- `eligible_threshold_labels`: threshold crossings among runtime-eligible scores.
- `raw_threshold_labels`: diagnostic threshold crossings ignoring readiness,
  calibration and policy approval; these are **not deployed alerts**.

The current snapshot's release config references a missing old directory;
its policy is unapproved and the observer sets `window_complete=False` even
on final snapshots. The replay experiment records these failures rather than
changing deployment behavior to improve a benchmark. Separately trained
C2/botnet/encrypted specialists are not loaded by the current launcher/bundle;
they are outside this exact runtime comparison.

This is a synthetic functional benchmark with new bytes and seeds, **not an
external generalization result**. Different IDS products need explicit rules
or behavioral scripts, whose configuration must be reported. Do not equate
default log generation with an attack detector or present benchmark-specific
rules as vendor-maintained detection coverage. One-way synthetic TCP omits the
server handshake; established-stream signatures can therefore be inapplicable.
Exfiltration and benign bulk transfer deliberately have overlapping visible
behavior, and intent truth cannot establish actual data theft from those bytes.
