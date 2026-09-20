"""Streaming classic PCAP reader with allocation bounds and exact timestamps."""
import struct
from pathlib import Path
from collections.abc import Iterator

from agent1_observation_dns.capture.source import CapturedFrame


class PcapError(ValueError):
    pass


class PcapSource:
    def __init__(self, path: str | Path, max_frame_bytes: int = 262144):
        self.path = Path(path)
        self.max_frame_bytes = max_frame_bytes

    def __iter__(self) -> Iterator[CapturedFrame]:
        with self.path.open("rb") as stream:
            header = stream.read(24)
            formats = {b"\xd4\xc3\xb2\xa1": ("<", 1000), b"\xa1\xb2\xc3\xd4": (">", 1000),
                       b"\x4d\x3c\xb2\xa1": ("<", 1), b"\xa1\xb2\x3c\x4d": (">", 1)}
            if len(header) != 24 or header[:4] not in formats:
                raise PcapError("expected classic PCAP (convert PCAPNG externally)")
            endian, scale = formats[header[:4]]
            major, minor, _, _, snaplen, linktype = struct.unpack(endian + "HHIIII", header[4:])
            if (major, minor) != (2, 4) or not 0 < snaplen <= self.max_frame_bytes:
                raise PcapError("unsupported version or snap length")
            while True:
                record = stream.read(16)
                if not record:
                    break
                if len(record) != 16:
                    raise PcapError("truncated record header")
                sec, frac, captured, wire = struct.unpack(endian + "IIII", record)
                if captured > snaplen or wire < captured or frac * scale >= 1_000_000_000:
                    raise PcapError("invalid packet length or timestamp")
                payload = stream.read(captured)
                if len(payload) != captured:
                    raise PcapError("truncated packet")
                yield CapturedFrame(sec * 1_000_000_000 + frac * scale, payload, wire, linktype)
