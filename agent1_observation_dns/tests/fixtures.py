"""Offline-only fixture construction. Never imports a networking API."""
import struct
from ipaddress import ip_address
import dpkt


def frame(*, source="192.0.2.1", destination="198.51.100.2", sport=12345, dport=53,
          payload=b"", tcp=False, flags=2, sequence=0):
    if tcp:
        transport = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=sequence, data=payload)
    else:
        transport = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
        transport.ulen = len(transport)
    ip = dpkt.ip.IP(src=ip_address(source).packed, dst=ip_address(destination).packed,
                    p=6 if tcp else 17, ttl=64, data=transport)
    ip.len = len(ip)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x01" * 6, dst=b"\x02" * 6, type=0x800, data=ip))


def dns(name="example.test", response=False, rcode=0):
    return bytes(dpkt.dns.DNS(id=42, qr=int(response), rcode=rcode,
                             qd=[dpkt.dns.DNS.Q(name=name, type=1)]))


def pcap(records):
    result = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    for ns, data in records:
        result += struct.pack("<IIII", ns // 10**9, (ns % 10**9) // 1000, len(data), len(data)) + data
    return result
