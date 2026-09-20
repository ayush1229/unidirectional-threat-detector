"""Receive-only adapters. No sockets, name resolution, or process launch."""
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True, slots=True)
class CapturedFrame:
    timestamp_ns: int
    data: bytes
    wire_length: int
    linktype: int = 1


class FrameSource(Protocol):
    def __iter__(self) -> Iterator[CapturedFrame]: ...


class ReceiveOnlySource:
    """Consume frames supplied by an external TAP/SPAN/libpcap receiver.

    Receiver lifecycle and physical RX-only enforcement belong to the operator.
    The adapter deliberately accepts an iterable, never a writable socket.
    """

    def __init__(self, frames: Iterable[CapturedFrame]):
        self._frames = frames

    def __iter__(self) -> Iterator[CapturedFrame]:
        yield from self._frames
