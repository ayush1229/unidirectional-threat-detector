# Testing

Run `python -m pytest agent1_observation_dns/tests -q -p no:cacheprovider`. The suite covers packet parsing, directional flow state, windows, DNS/TLS extraction, null semantics, bounds, deterministic replay, schema versions, split leakage, specialist routing/fusion, and static transmit-safety checks. The release manifest reports the current test count and explicitly makes no benchmark claim.
