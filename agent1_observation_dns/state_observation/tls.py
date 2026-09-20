"""Bounded in-order TCP early-session buffer. Parse plaintext hello metadata only."""
from collections import OrderedDict
from dataclasses import dataclass, field
from agent1_observation_dns.contracts import measured


def parse_hello(data: bytes):
    handshake = bytearray()
    offset = 0
    while offset + 5 <= len(data):
        kind, length = data[offset], int.from_bytes(data[offset+3:offset+5], "big")
        if kind != 22 or length > 18432 or offset+5+length > len(data):
            break
        handshake.extend(data[offset+5:offset+5+length])
        offset += 5+length
    if len(handshake) < 4 or handshake[0] not in (1, 2):
        return None
    length = int.from_bytes(handshake[1:4], "big")
    if len(handshake) < length+4:
        return None
    body = bytes(handshake[4:length+4])
    try:
        if len(body) < 35:
            return None
        pos = 35 + body[34]
        client = handshake[0] == 1
        if client:
            n = int.from_bytes(body[pos:pos+2], "big")
            if n == 0 or n % 2 or pos+2+n >= len(body):
                return None
            ciphers = [int.from_bytes(body[i:i+2], "big") for i in range(pos+2, pos+2+n, 2)]
            pos += 2+n
            pos += 1+body[pos]
        else:
            if pos+3 > len(body):
                return None
            ciphers = [int.from_bytes(body[pos:pos+2], "big")]
            pos += 3
        sni = None
        extensions = []
        if pos < len(body):
            end = pos+2+int.from_bytes(body[pos:pos+2], "big")
            pos += 2
            if end != len(body):
                return None
            while pos+4 <= end:
                kind = int.from_bytes(body[pos:pos+2], "big")
                size = int.from_bytes(body[pos+2:pos+4], "big")
                value = body[pos+4:pos+4+size]
                if len(value) != size:
                    return None
                extensions.append(kind)
                if kind == 0 and client and len(value) >= 5 and value[2] == 0:
                    n = int.from_bytes(value[3:5], "big")
                    if n and len(value) >= 5+n:
                        sni = value[5:5+n].decode("ascii")
                pos += 4+size
            if pos != end:
                return None
        return {"hello_type": "client" if client else "server", "legacy_version": int.from_bytes(body[:2], "big"),
                "cipher_suites": ciphers, "extension_types": extensions, "sni": sni}
    except (IndexError, UnicodeError):
        return None


@dataclass
class EarlySession:
    start_ns: int
    packets: int = 0
    next_seq: int | None = None
    data: bytearray = field(default_factory=bytearray)
    metadata: dict | None = None
    reason: str = "HANDSHAKE_NOT_OBSERVED"
    sealed: bool = False


class TLSBuffer:
    def __init__(self, config):
        self.config = config
        self.sessions: OrderedDict[str, EarlySession] = OrderedDict()

    def expire(self, ns):
        for key in list(self.sessions):
            state = self.sessions[key]
            if ns-state.start_ns > self.config.tls_timeout_s*1e9 and not state.sealed:
                state.reason, state.sealed = "EARLY_BUFFER_LIMIT", True
                state.data.clear()
            if ns-state.start_ns > self.config.flow_ttl_s*1e9:
                del self.sessions[key]

    def update(self, flow_id, packet):
        self.expire(packet.timestamp_ns)
        if packet.transport != "TCP":
            return self.features(None)
        if flow_id not in self.sessions:
            if len(self.sessions) >= self.config.max_flows:
                self.sessions.popitem(last=False)
            self.sessions[flow_id] = EarlySession(packet.timestamp_ns)
        state = self.sessions[flow_id]
        state.packets += 1
        if not state.sealed:
            if state.packets > self.config.tls_packets or packet.timestamp_ns-state.start_ns > self.config.tls_timeout_s*1e9:
                state.reason, state.sealed = "EARLY_BUFFER_LIMIT", True
            elif packet.payload:
                seq = (packet.tcp_sequence + bool(packet.flags & 2)) % 2**32
                if state.next_seq is not None and seq != state.next_seq:
                    # Exact/overlapping retransmissions before expected sequence are ignored.
                    behind = (state.next_seq-seq) % 2**32
                    if behind <= len(packet.payload):
                        payload = packet.payload[behind:]
                    else:
                        state.reason, state.sealed = "TCP_GAP_OR_REORDER", True
                        payload = b""
                else:
                    payload = packet.payload
                if len(state.data)+len(payload) > self.config.max_tls_bytes:
                    state.reason, state.sealed = "EARLY_BUFFER_BYTES", True
                elif not state.sealed:
                    state.data.extend(payload)
                    state.next_seq = (seq+len(packet.payload)) % 2**32
                    state.metadata = parse_hello(bytes(state.data))
                    if state.metadata:
                        state.sealed = True
            if state.sealed:
                state.data.clear()
        self.sessions.move_to_end(flow_id)
        return self.features(state)

    @staticmethod
    def features(state):
        metadata = state.metadata if state and state.metadata else {}
        reason = state.reason if state else "NOT_TCP"
        result = {k: measured(metadata.get(k), reason if k != "sni" else "SNI_NOT_OBSERVED", applicable=state is not None)
                  for k in ("hello_type", "legacy_version", "cipher_suites", "extension_types", "sni")}
        result.update(ja4=measured(None, "FINGERPRINT_NOT_IMPLEMENTED", applicable=state is not None),
                      ja4s=measured(None, "FINGERPRINT_NOT_IMPLEMENTED", applicable=state is not None))
        return result
