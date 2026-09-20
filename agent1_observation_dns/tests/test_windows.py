from pathlib import Path
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.pipeline import ObservationPipeline
from agent1_observation_dns.replay.pcap import PcapSource
from agent1_observation_dns.tests.test_replay import packet
from agent1_observation_dns.windows_generic.windows import HostWindows


def test_window_rates_and_bounds():
    windows = HostWindows(Settings(windows_s=(1, 5), max_window_events=2, max_hosts=2))
    for ns in (10**9, 2*10**9, 3*10**9):
        windows.update(packet(ns), new_flow=ns == 10**9)
    f = windows.features("source", "192.0.2.1", 3*10**9)
    assert f["source.1s.packet_rate"].value == 1
    assert f["source.5s.packet_rate"].value is None
    assert f["source.5s.packet_rate"].reason == "WINDOW_CAPACITY_LOSS"
    assert len(windows.hosts) <= 2
    windows.expire(10*10**9)
    assert not windows.hosts


def test_golden_pipeline_determinism():
    path = Path(__file__).parent / "golden/dns_tcp.pcap"
    def run():
        return [e.model_dump(mode="json") for e in ObservationPipeline().run(PcapSource(path))]
    assert run() == run()
    assert run()[-1]["snapshot_kind"] == "final"
    assert run()[0]["features"]["flow"]["pps"]["value"] is None


def test_no_identity_features():
    path = Path(__file__).parent / "golden/dns_tcp.pcap"
    envelope = next(ObservationPipeline().run(PcapSource(path)))
    assert "192.0.2.1" not in envelope.features.model_dump_json()
