import struct
import pytest

from agent1_observation_dns.capture.source import CapturedFrame
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.normalization.packet import normalize, PacketError
from agent1_observation_dns.replay.pcap import PcapSource, PcapError
from agent1_observation_dns.state_observation.flows import FlowTable
from agent1_observation_dns.tests.fixtures import frame, pcap


def packet(ns=10**9, **kwargs):
    data = frame(**kwargs)
    return normalize(CapturedFrame(ns, data, len(data)))


def test_parser_and_unidirectional_flow():
    table = FlowTable(Settings())
    f, _ = table.update(packet(tcp=True))
    f, _ = table.update(packet(2*10**9, tcp=True, flags=16))
    assert f.count == 2 and f.iats.count == 1 and f.iats.mean == 1
    assert f.features()["syn_count"].value == 1
    reverse, _ = table.update(packet(3*10**9, source="198.51.100.2", destination="192.0.2.1", sport=53, dport=12345))
    assert reverse.flow_id != f.flow_id


def test_ttl_capacity_and_fin():
    table = FlowTable(Settings(max_flows=1, flow_ttl_s=2))
    table.update(packet())
    _, expired = table.update(packet(4*10**9))
    assert expired[0][1] == "INACTIVITY_TIMEOUT"
    _, evicted = table.update(packet(5*10**9, sport=12))
    assert evicted[0][1] == "CAPACITY_EVICTION"
    f, _ = table.update(packet(6*10**9, tcp=True, flags=1))
    assert f.completion_visible and len(table.flows) == 0


def test_replay_exact_and_malformed(tmp_path):
    path = tmp_path / "sample.pcap"
    path.write_bytes(pcap([(1234567000, frame())]))
    assert list(PcapSource(path)) == list(PcapSource(path))
    assert list(PcapSource(path))[0].timestamp_ns == 1234567000
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(PcapError):
        list(PcapSource(path))
    with pytest.raises(PacketError):
        normalize(CapturedFrame(0, b"bad", 3))


def test_late_packets_rejected():
    table = FlowTable(Settings())
    table.update(packet(2*10**9))
    with pytest.raises(ValueError):
        table.update(packet(1*10**9))
