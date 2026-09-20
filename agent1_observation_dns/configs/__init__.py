"""Validated, file-loadable runtime configuration."""
import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Settings(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, allow_inf_nan=False)
    sensor_id: str = Field(default="agent1-offline", min_length=1)
    feature_version: Literal["2.0.0"] = "2.0.0"
    windows_s: tuple[int, ...] = (1, 5, 30, 60, 300, 900, 3600)
    flow_ttl_s: float = Field(default=60, gt=0)
    max_flows: int = Field(default=10000, gt=0)
    max_hosts: int = Field(default=2000, gt=0)
    max_window_events: int = Field(default=4096, gt=0)
    dns_ttl_s: float = Field(default=3600, gt=0)
    max_dns_keys: int = Field(default=5000, gt=0)
    max_dns_events: int = Field(default=128, ge=2)
    graph_ttl_s: float = Field(default=300, gt=0)
    max_graph_nodes: int = Field(default=10000, ge=3)
    max_graph_edges: int = Field(default=20000, ge=2)
    tls_packets: int = Field(default=24, ge=16, le=32)
    tls_timeout_s: float = Field(default=5, gt=0)
    max_tls_bytes: int = Field(default=65536, ge=1024)
    max_frame_bytes: int = Field(default=262144, ge=65535)
    burst_gap_s: float = Field(default=0.1, gt=0)
    idle_gap_s: float = Field(default=1, gt=0)
    suspicious_low: float = Field(default=0.25, ge=0, le=1)
    suspicious_high: float = Field(default=0.8, ge=0, le=1)
    audit_fraction: float = Field(default=0.01, ge=0, le=1)
    structural_label_length: int = Field(default=48, ge=1, le=63)
    sequence_min_events: int = Field(default=8, ge=2)
    graph_min_edges: int = Field(default=4, ge=2)
    research_evaluation: bool = False
    model_paths: dict[str, str] = Field(default_factory=dict)
    pcap_path: str | None = None

    @model_validator(mode="after")
    def valid_ranges(self):
        if not self.windows_s or any(w <= 0 for w in self.windows_s):
            raise ValueError("windows must be positive")
        if tuple(sorted(set(self.windows_s))) != self.windows_s:
            raise ValueError("windows must be unique and ascending")
        if self.suspicious_low > self.suspicious_high:
            raise ValueError("invalid suspicious band")
        if self.burst_gap_s > self.idle_gap_s:
            raise ValueError("burst gap exceeds idle gap")
        return self

    @classmethod
    def load(cls, path: str | Path):
        return cls.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))
