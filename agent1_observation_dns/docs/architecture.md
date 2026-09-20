# Agent 1 architecture

Agent 1 is a passive observation and DNS-evidence package. Its data path is:

`PCAP or operator-provisioned RX-only source -> frame normalization -> unidirectional flow -> bounded host/DNS/TLS state -> ObservationEnvelope v2 -> specialist evidence`.

The package never sends packets, performs scans, resolves names, completes handshakes, decrypts payloads, or chooses a global IDS verdict. It does not import Agent 2 or backend/dashboard modules.

Event time drives expiration. Flow, host, DNS, relation, and TLS state all have explicit count or TTL limits. Partial observations remain partial; missing values are null with availability and reason codes.
