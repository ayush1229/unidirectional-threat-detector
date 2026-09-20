"""Normalize Ethernet/raw-IP/Linux cooked frames without network I/O."""
from dataclasses import dataclass
from ipaddress import ip_address

import dpkt

from agent1_observation_dns.capture.source import CapturedFrame


@dataclass(frozen=True, slots=True)
class Packet:
    timestamp_ns: int
    source: str
    destination: str
    source_port: int
    destination_port: int
    transport: str
    size: int
    ttl: int
    flags: int | None
    payload: bytes
    tcp_sequence: int | None = None
    truncated: bool = False

    @property
    def key(self) -> tuple:
        return (self.source, self.destination, self.source_port, self.destination_port, self.transport)


class PacketError(ValueError):
    pass


def normalize(frame: CapturedFrame) -> Packet:
    try:
        if frame.timestamp_ns < 0 or frame.wire_length < len(frame.data):
            raise PacketError("invalid frame metadata")
        if frame.linktype == 1:
            ip = dpkt.ethernet.Ethernet(frame.data).data
        elif frame.linktype in (101, 228, 229):
            ip = dpkt.ip.IP(frame.data) if frame.data[0] >> 4 == 4 else dpkt.ip6.IP6(frame.data)
        elif frame.linktype == 113:
            ip = dpkt.sll.SLL(frame.data).data
        else:
            raise PacketError("unsupported link type")
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            raise PacketError("non-IP frame")
        if isinstance(ip, dpkt.ip.IP) and (ip.mf or ip.offset):
            raise PacketError("fragmented IP requires upstream reassembly")
        if isinstance(ip, dpkt.ip6.IP6) and 44 in ip.extension_hdrs:
            raise PacketError("fragmented IPv6 requires upstream reassembly")
        transport = ip.data
        tcp = isinstance(transport, dpkt.tcp.TCP)
        udp = isinstance(transport, dpkt.udp.UDP)
        return Packet(frame.timestamp_ns, str(ip_address(ip.src)), str(ip_address(ip.dst)),
                      transport.sport if tcp or udp else 0, transport.dport if tcp or udp else 0,
                      "TCP" if tcp else "UDP" if udp else "OTHER", frame.wire_length,
                      ip.ttl if isinstance(ip, dpkt.ip.IP) else ip.hlim,
                      int(transport.flags) if tcp else None,
                      bytes(transport.data) if tcp or udp else b"",
                      transport.seq if tcp else None, len(frame.data) < frame.wire_length)
    except (dpkt.UnpackError, ValueError, IndexError, AttributeError) as exc:
        raise PacketError("malformed or unsupported packet") from exc
