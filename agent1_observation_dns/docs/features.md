# Features

Flow features use duration, packet/byte counts, rates, size and inter-arrival moments, TCP flag counts/ratios, TTL moments, burst counts, and active/idle time. Host windows are configurable (default 1s, 5s, 30s, 1m, 5m, 15m, 1h) and include rates, cardinalities, entropy/concentration, SYN/RST rates, new-destination ratio, and persistence.

Online moments are constant-memory. Window capacity loss makes affected values unavailable rather than zero.
