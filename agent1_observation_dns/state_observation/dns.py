"""Passive DNS decoding and bounded source/parent-domain metadata history."""
from collections import Counter, OrderedDict, deque
from dataclasses import dataclass
from math import log2
import dpkt

from agent1_observation_dns.configs import Settings
from agent1_observation_dns.contracts import measured
from agent1_observation_dns.normalization.packet import Packet


def entropy(text: str) -> float:
    return -sum(n/len(text)*log2(n/len(text)) for n in Counter(text).values()) if text else 0.0


def parent_domain(name: str) -> str:
    """Last-two-label grouping, NOT a public-suffix/registrable-domain claim."""
    return ".".join(name.rstrip(".").lower().split(".")[-2:])


@dataclass(frozen=True, slots=True)
class DNSRecord:
    name: str
    qtype: int
    response: bool
    rcode: int | None
    transaction_id: int


def extract_dns(packet: Packet) -> DNSRecord | None:
    if 53 not in (packet.source_port, packet.destination_port):
        return None
    payload = packet.payload
    if packet.transport == "TCP":
        if len(payload) < 2:
            return None
        length = int.from_bytes(payload[:2], "big")
        if len(payload) < length + 2:
            return None
        payload = payload[2:length+2]
    try:
        message = dpkt.dns.DNS(payload)
        if message.opcode != 0 or not message.qd:
            return None
        question = message.qd[0]
        name = question.name.lower().rstrip(".")
        if not name or len(name) > 253 or any(len(label) > 63 for label in name.split(".")):
            return None
        return DNSRecord(name, question.type, bool(message.qr), message.rcode if message.qr else None, message.id)
    except (dpkt.UnpackError, ValueError, IndexError, UnicodeError):
        return None


@dataclass(frozen=True, slots=True)
class DNSEvent:
    ns: int
    name: str
    qtype: int
    size: int
    rcode: int | None


class DNSHistory:
    def __init__(self, config: Settings):
        self.config = config
        self.histories: OrderedDict[tuple, deque] = OrderedDict()

    def expire(self, ns: int):
        cutoff = ns - self.config.dns_ttl_s * 1e9
        for key in list(self.histories):
            events = self.histories[key]
            while events and events[0].ns <= cutoff:
                events.popleft()
            if not events:
                del self.histories[key]

    def update(self, packet: Packet, record: DNSRecord):
        self.expire(packet.timestamp_ns)
        client = packet.destination if record.response else packet.source
        key = client, parent_domain(record.name)
        if key not in self.histories:
            if len(self.histories) >= self.config.max_dns_keys:
                self.histories.popitem(last=False)
            self.histories[key] = deque(maxlen=self.config.max_dns_events)
        events = self.histories[key]
        events.append(DNSEvent(packet.timestamp_ns, record.name, record.qtype, packet.size, record.rcode))
        self.histories.move_to_end(key)
        return self.features(record, list(events))

    def features(self, record, events):
        queries = [e for e in events if e.rcode is None]
        responses = [e for e in events if e.rcode is not None]
        gaps = [(b.ns-a.ns)/1e9 for a, b in zip(queries, queries[1:])]
        duration = (queries[-1].ns-queries[0].ns)/1e9 if len(queries) > 1 else 0
        sizes = [e.size for e in queries]
        mean_size = sum(sizes)/len(sizes) if sizes else None
        # Counts/rates refer explicitly to the retained bounded history.
        values = {
            "query_name": record.name, "parent_domain": parent_domain(record.name),
            "query_length": len(record.name), "entropy": entropy(record.name),
            "max_label_length": max(map(len, record.name.split("."))),
            "digit_ratio": sum(c.isdigit() for c in record.name)/len(record.name),
            "is_response": record.response, "query_type": record.qtype,
            "query_count": len(queries) if queries else None,
            "response_count": len(responses) if responses else None,
            "nxdomain_ratio": sum(e.rcode == 3 for e in responses)/len(responses) if responses else None,
            "subdomain_churn": len({e.name for e in queries})/len(queries) if queries else None,
            "txt_ratio": sum(e.qtype == 16 for e in queries)/len(queries) if queries else None,
            "aaaa_ratio": sum(e.qtype == 28 for e in queries)/len(queries) if queries else None,
            "query_rate": len(queries)/duration if duration else None,
            "iat_mean_s": sum(gaps)/len(gaps) if gaps else None,
            "packet_size_mean": mean_size,
            "packet_size_std": (sum((s-mean_size)**2 for s in sizes)/len(sizes))**.5 if sizes else None,
            "history_count": len(events),
            "sequence": [[len(e.name), entropy(e.name), e.qtype, e.size,
                          (e.ns-events[i-1].ns)/1e9 if i else None, e.rcode]
                         for i, e in enumerate(events)],
        }
        values["sequence_availability"] = [[v is not None for v in row] for row in values["sequence"]]
        values["sequence_reason_codes"] = [["OBSERVED" if v is not None else
                                           "FIRST_EVENT" if k == 4 else "DNS_RESPONSE_NOT_VISIBLE"
                                           for k, v in enumerate(row)] for row in values["sequence"]]
        return {k: measured(v, "DNS_RESPONSE_NOT_VISIBLE" if k in ("response_count", "nxdomain_ratio")
                            else "INSUFFICIENT_HISTORY") for k, v in values.items()}
