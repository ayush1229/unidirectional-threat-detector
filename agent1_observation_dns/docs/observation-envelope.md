# ObservationEnvelope v2

`ObservationEnvelope` is a Pydantic contract exported as JSON Schema. It carries an event ID, correlation-only entity keys, protocol, grouped flow/window/DNS/TLS measurements, visibility, bounded history, and route hints. IP and domain identities are retained only for correlation and are not emitted as generic predictive features.

Every measurement uses `value`, `available`, `applicable`, and `reason`. An observed zero is available with value `0`; unseen data is `null`.
