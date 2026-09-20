"""Single event-time path for externally captured frames and offline replay."""
from collections.abc import Iterable, Iterator
from datetime import datetime, timezone, timedelta
import logging
from time import perf_counter

from agent1_observation_dns.capture.source import CapturedFrame
from agent1_observation_dns.configs import Settings
from agent1_observation_dns.contracts import EntityKeys, Features, History, ObservationEnvelope, RouteHints
from agent1_observation_dns.normalization.packet import normalize, PacketError
from agent1_observation_dns.state_observation.flows import Flow, FlowTable
from agent1_observation_dns.visibility.masks import visibility
from agent1_observation_dns.windows_generic.windows import HostWindows
from agent1_observation_dns.state_observation.dns import DNSHistory, extract_dns
from agent1_observation_dns.state_observation.tls import TLSBuffer
from agent1_observation_dns.dns_relation_state.graph import DNSGraph
from agent1_observation_dns.contracts import measured

log = logging.getLogger("agent1.pipeline")


class ObservationPipeline:
    """Single-owner pipeline; serialize live callbacks before entering it."""
    def __init__(self, config: Settings | None = None):
        self.config = config or Settings()
        self.flows = FlowTable(self.config)
        self.windows = HostWindows(self.config)
        self.rejected_packets = 0
        self.dns = DNSHistory(self.config)
        self.tls = TLSBuffer(self.config)
        self.graph = DNSGraph(self.config)

    def envelope(self, flow: Flow, *, final=False, reason="PACKET_UPDATE", dns=None, tls=None):
        window = {}
        for role, host in (("source", flow.key[0]), ("destination", flow.key[1])):
            window.update(self.windows.features(role, host, flow.last_ns))
        features = Features(flow=flow.features(), window=window, dns=dns or flow.dns_features, tls=tls or flow.tls_features)
        visible = visibility(features, complete=flow.completion_visible)
        protocol = "DNS" if features.dns else "TLS" if visible.tls_handshake_visible else flow.key[-1]
        return ObservationEnvelope(
            event_id=f"{flow.flow_id}:{flow.count}:{'final' if final else 'partial'}",
            sensor_id=self.config.sensor_id,
            event_time=datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=flow.last_ns//1000),
            entity_keys=EntityKeys(flow_id=flow.flow_id, source=flow.key[0], destination=flow.key[1]),
            protocol=protocol, features=features, visibility=visible,
            history=History(event_count=flow.count, duration_ms=(flow.last_ns-flow.first_ns)/1e6, window_complete=False),
            route_hints=RouteHints(dns=bool(features.dns.get("query_name") and features.dns["query_name"].available),
                                   tls=visible.tls_handshake_visible), snapshot_kind="final" if final else "partial",
            reason_codes=[reason], feature_schema_version=self.config.feature_version)

    def process(self, frame: CapturedFrame) -> list[ObservationEnvelope]:
        started = perf_counter()
        try:
            if len(frame.data) > self.config.max_frame_bytes:
                raise PacketError("capture frame exceeds configured allocation limit")
            packet = normalize(frame)
        except PacketError:
            self.rejected_packets += 1
            log.warning("normalization_rejected", extra={"reason_codes": ["MALFORMED_OR_UNSUPPORTED"]})
            return []
        flow, closed = self.flows.update(packet)
        result = [self.envelope(f, final=True, reason=r) for f, r in closed]
        self.dns.expire(packet.timestamp_ns)
        self.graph.expire(packet.timestamp_ns)
        record = extract_dns(packet)
        if record:
            flow.dns_features = self.dns.update(packet, record)
            self.graph.update(packet, record)
            # Graph tensor is requested on demand, not copied into every flow.
            flow.dns_features["relation_edge_count"] = measured(len(self.graph.edges))
            flow.dns_features["relation_sufficient"] = measured(len(self.graph.edges) >= self.config.graph_min_edges)
        flow.tls_features = self.tls.update(flow.flow_id, packet)
        self.windows.update(packet, domain=record.name if record else None, new_flow=flow.count == 1)
        result.append(self.envelope(flow, final=flow.completion_visible,
                                    reason="OBSERVED_FIN_OR_RST" if flow.completion_visible else "PACKET_UPDATE"))
        log.info("observation", extra={"event_id": result[-1].event_id,
                 "processing_ms": (perf_counter()-started)*1000, "state_size": len(self.flows.flows),
                 "feature_availability": result[-1].visibility.feature_availability_ratio,
                 "route_decision": result[-1].route_hints.model_dump()})
        return result

    def tick(self, timestamp_ns: int) -> list[ObservationEnvelope]:
        """Live receiver calls during silence using its monotonic event-time watermark."""
        if timestamp_ns < self.flows.watermark_ns:
            raise ValueError("watermark cannot move backward")
        self.flows.watermark_ns = timestamp_ns
        result = [self.envelope(f, final=True, reason=r) for f, r in self.flows.expire(timestamp_ns)]
        self.windows.expire(timestamp_ns)
        self.dns.expire(timestamp_ns)
        self.graph.expire(timestamp_ns)
        self.tls.expire(timestamp_ns)
        return result

    def run(self, frames: Iterable[CapturedFrame]) -> Iterator[ObservationEnvelope]:
        for frame in frames:
            yield from self.process(frame)
        for flow, reason in self.flows.flush():
            yield self.envelope(flow, final=True, reason=reason)
        self.tls.sessions.clear()
