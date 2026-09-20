"""Optional Scapy receive-only capture on an operator-provisioned monitor interface."""
from collections.abc import Callable
from decimal import Decimal
from agent1_observation_dns.capture.source import CapturedFrame


def capture(interface: str, on_frame: Callable[[CapturedFrame], None], *, timeout_s: float, packet_limit: int = 0):
    """Bounded capture session. No interface configuration or active network operations.

    TAP/SPAN/data-diode Ethernet interface must already be configured by the
    operator. Hardware/network isolation enforces RX-only at the host boundary.
    """
    if not interface or timeout_s <= 0 or packet_limit < 0:
        raise ValueError("explicit interface and positive capture timeout required")
    from scapy.sendrecv import sniff

    def receive(packet):
        data = bytes(packet)
        wire_length = getattr(packet, "wirelen", None) or len(data)
        on_frame(CapturedFrame(int(Decimal(str(packet.time))*10**9), data, wire_length, 1))

    sniff(iface=interface, prn=receive, store=False, timeout=timeout_s, count=packet_limit,
          filter="ip or ip6")
