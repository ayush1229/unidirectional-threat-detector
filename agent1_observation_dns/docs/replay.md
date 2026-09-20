# Replay

`PcapSource` streams classic PCAP records with exact event timestamps and frame-size bounds. Offline replay and live capture feed the same `ObservationPipeline`. PCAPNG conversion belongs outside this package. The golden fixture is processed twice in tests to prove deterministic output.
