from agent1_observation_dns.configs import Settings
from agent1_observation_dns.state_observation.dns import DNSHistory, extract_dns
from agent1_observation_dns.state_observation.tls import TLSBuffer, parse_hello
from agent1_observation_dns.dns_relation_state.graph import DNSGraph
from agent1_observation_dns.tests.fixtures import dns
from agent1_observation_dns.tests.test_replay import packet


def hello(name=b"example.test"):
    sni = (len(name)+3).to_bytes(2,"big") + b"\0" + len(name).to_bytes(2,"big") + name
    ext = b"\0\0" + len(sni).to_bytes(2,"big") + sni
    body = b"\x03\x03" + b"\0"*32 + b"\0\0\x02\x13\x01\x01\0" + len(ext).to_bytes(2,"big") + ext
    hs = b"\x01" + len(body).to_bytes(3,"big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2,"big") + hs


def test_missing_response_and_observed_zero():
    history = DNSHistory(Settings())
    p = packet(payload=dns())
    f = history.update(p, extract_dns(p))
    assert f["nxdomain_ratio"].value is None
    assert not f["response_count"].available
    p = packet(2*10**9, source="198.51.100.2", destination="192.0.2.1", sport=53, dport=12345,
               payload=dns(response=True, rcode=0))
    f = history.update(p, extract_dns(p))
    assert f["nxdomain_ratio"].value == 0 and f["nxdomain_ratio"].available


def test_dns_graph_bounds_and_expiry():
    config = Settings(max_dns_keys=2, max_dns_events=2, max_graph_nodes=3, max_graph_edges=2)
    history, graph = DNSHistory(config), DNSGraph(config)
    for i in range(10):
        p = packet((i+1)*10**9, payload=dns(f"x{i}.test"))
        record = extract_dns(p)
        history.update(p, record)
        graph.update(p, record)
    assert len(history.histories) <= 2 and len(graph.nodes) <= 3 and len(graph.edges) <= 2
    assert all(len(events) <= 2 for events in history.histories.values())
    assert "192.0.2.1" not in str(graph.structural_snapshot())
    history.expire(4000*10**9)
    graph.expire(4000*10**9)
    assert not history.histories and not graph.edges


def test_tls_split_hello_and_missing_fingerprint():
    data = hello()
    assert parse_hello(data)["sni"] == "example.test"
    buffer = TLSBuffer(Settings())
    a = buffer.update("f", packet(tcp=True, payload=data[:20], flags=16, sequence=100))
    assert a["hello_type"].value is None
    b = buffer.update("f", packet(2*10**9, tcp=True, payload=data[20:], flags=16, sequence=120))
    assert b["sni"].value == "example.test"
    assert b["ja4s"].value is None and not b["ja4s"].available
    assert len(buffer.sessions["f"].data) == 0


def test_tls_gap_is_not_fabricated():
    buffer = TLSBuffer(Settings())
    buffer.update("f", packet(tcp=True, payload=hello()[:20], sequence=0, flags=16))
    f = buffer.update("f", packet(2*10**9, tcp=True, payload=hello()[20:], sequence=200, flags=16))
    assert f["hello_type"].value is None
    assert f["hello_type"].reason == "TCP_GAP_OR_REORDER"
