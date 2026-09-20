from agent1_observation_dns.contracts import Features, Visibility


def visibility(features: Features, *, complete=False) -> Visibility:
    def available(group, name):
        field = group.get(name)
        return bool(field and field.available)
    masks = {
        "direction_reconstructable": available(features.dns, "is_response") or available(features.tls, "hello_type"),
        "dns_response_visible": available(features.dns, "response_count"),
        "nxdomain_ratio_available": available(features.dns, "nxdomain_ratio"),
        "tls_handshake_visible": available(features.tls, "hello_type"),
        "ja4_available": available(features.tls, "ja4"),
        "ja4s_available": available(features.tls, "ja4s"),
        "sni_available": available(features.tls, "sni"),
        "flow_completion_visible": complete,
    }
    fields = [m for group in (features.flow, features.window, features.dns, features.tls)
              for m in group.values() if m.applicable]
    return Visibility(**masks, feature_availability_ratio=sum(m.available for m in fields)/len(fields) if fields else 0,
                      reason_codes={k: "OBSERVED" if v else "NOT_OBSERVED" for k, v in masks.items()})
