"""
processing/flow_object.py
=========================
Canonical JSON schema for a completed network flow.
This is the CONTRACT between Person 3 (ingestion) and Person 1 & 2 (ML).

Published to Redis channel: flow.raw
Schema version: 1.0.0

DO NOT change field names without bumping schema_version and notifying
Person 1, Person 2, and Person 4.
"""
from __future__ import annotations
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime, timezone
import uuid


# ── Sub-objects ───────────────────────────────────────────────────────────────

class FiveTuple(BaseModel):
    src_ip:   str
    dst_ip:   str
    src_port: int
    dst_port: int
    protocol: str   # "TCP" | "UDP" | "TCP/TLS" | "UDP/QUIC" | "ICMP"


class TLSMeta(BaseModel):
    """
    All fields derived exclusively from the UNENCRYPTED TLS/QUIC handshake.
    No payload decryption is performed — ever.
    """
    tls_version:              Optional[str]       = None   # e.g. "TLSv1.3"
    cipher_suites:            Optional[List[str]] = None   # ORDERED hex strings — order is the fingerprint signal
    extensions:               Optional[List[str]] = None   # ORDERED extension type numbers
    ec_curves:                Optional[List[str]] = None   # Elliptic curve / supported groups list
    ja3_raw_string:           Optional[str]       = None   # pre-hash string (Person 2 can inspect or re-hash)
    ja3_fingerprint:          Optional[str]       = None   # MD5 of ja3_raw_string
    ja4_fingerprint:          Optional[str]       = None   # JA4 hash (if computed)
    sni:                      Optional[str]       = None   # Server Name Indication from Client Hello (plain-text, no decryption)
    record_length:            Optional[int]       = None   # TLS record byte length
    is_quic:                  bool                = False  # True if source was QUIC Initial


class DNSMeta(BaseModel):
    """
    DNS query metadata. Populated for UDP/53 and DNS-over-TCP flows.
    Person 1 computes Shannon entropy and n-grams on query_name.
    """
    query_name:    Optional[str]       = None   # Raw FQDN as observed on the wire
    query_type:    Optional[str]       = None   # "A" | "AAAA" | "TXT" | "CNAME" | "NULL" | ...
    query_length:  Optional[int]       = None   # len(query_name)
    answer_count:  int                 = 0      # usually 0 in read-only mirror (no response seen)
    answer_ips:    Optional[List[str]] = None   # IPs from any observed answer records


# ── Top-level FlowObject ──────────────────────────────────────────────────────

class FlowObject(BaseModel):
    """
    One completed network flow. Emitted when:
      - TCP FIN or RST seen
      - Packet count reaches FLOW_MAX_PACKETS
      - Flow idle for FLOW_IDLE_TIMEOUT_S seconds
    """
    schema_version: str = "1.0.0"

    # ── Identity ──────────────────────────────────────────────────────────────
    flow_id:        str      = Field(default_factory=lambda: str(uuid.uuid4()))
    first_seen:     datetime
    last_seen:      datetime
    five_tuple:     FiveTuple

    # ── Volume / timing ───────────────────────────────────────────────────────
    duration_s:     float    # last_seen - first_seen in seconds
    total_packets:  int
    total_bytes:    int

    # ── Sequence features (capped at 50 to control message size) ──────────────
    packet_sizes:         List[int]   = Field(default_factory=list)
    inter_arrival_times:  List[float] = Field(default_factory=list)   # seconds between packets
    tcp_flags_seen:       List[str]   = Field(default_factory=list)   # e.g. ["S","P","A","F"]

    # ── Byte direction ────────────────────────────────────────────────────────
    bytes_in:       int = 0
    bytes_out_proxy: int = 0   # ALWAYS 0 — cannot observe outbound under data diode

    # ── Enrichment (attached by Zeek / tshark correlators) ───────────────────
    tls_meta:       Optional[TLSMeta] = None
    dns_meta:       Optional[DNSMeta] = None

    # ── Zeek correlation ──────────────────────────────────────────────────────
    zeek_conn_state: Optional[str] = None   # "SF" | "S0" | "REJ" | "S1" | "RSTO" | ...
    zeek_uid:        Optional[str] = None   # Zeek UID for cross-log correlation

    # ── Provenance ────────────────────────────────────────────────────────────
    sensor_id:          str
    capture_interface:  str
    pipeline_version:   str
