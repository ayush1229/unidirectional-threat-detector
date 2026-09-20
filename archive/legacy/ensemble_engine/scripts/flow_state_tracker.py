from __future__ import annotations
import math, threading, time
from collections import defaultdict, deque

MAX_EVENTS_PER_IP = 2000
DEFAULT_WINDOW_S = 60.0

class FlowStateTracker:
    """
    Thread-safe cross-flow sliding-window state tracker.

    Records per-flow (src_ip, dst_ip, dst_port) tuples and answers:
      get_port_fanout(src_ip)    -> int   distinct (dst_ip, dst_port) pairs seen from src_ip
      get_dst_entropy(dst_ip)    -> float normalized Shannon entropy of src-IP diversity
      get_unique_source_count()  -> int   distinct source IPs targeting dst_ip

    Use record() on every incoming flow before ensemble scoring.
    """
    def __init__(self, max_events_per_ip=MAX_EVENTS_PER_IP):
        self._lock = threading.Lock()
        self._max = max_events_per_ip
        self._fanout = defaultdict(lambda: deque(maxlen=self._max))
        self._dst_sources = defaultdict(lambda: deque(maxlen=self._max))

    def record(self, flow_obj):
        ft = flow_obj.get("five_tuple") or {}
        src_ip = ft.get("src_ip")
        dst_ip = ft.get("dst_ip")
        dst_port = ft.get("dst_port")
        if not src_ip or not dst_ip:
            return
        now = time.time()
        with self._lock:
            self._fanout[src_ip].append((now, (dst_ip, int(dst_port or 0))))
            self._dst_sources[dst_ip].append((now, src_ip))

    def get_port_fanout(self, src_ip, window_s=DEFAULT_WINDOW_S):
        cutoff = time.time() - window_s
        with self._lock:
            dq = self._fanout.get(src_ip)
            if not dq:
                return 0
            return len({pair for ts, pair in dq if ts >= cutoff})

    def get_dst_entropy(self, dst_ip, window_s=DEFAULT_WINDOW_S):
        cutoff = time.time() - window_s
        with self._lock:
            dq = self._dst_sources.get(dst_ip)
            counts = {}
            if dq:
                for ts, src in dq:
                    if ts >= cutoff:
                        counts[src] = counts.get(src, 0) + 1
        if len(counts) <= 1:
            return 0.0
        total = sum(counts.values())
        raw_h = -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
        max_h = math.log2(len(counts))
        return round(raw_h / max_h, 4) if max_h > 0 else 0.0

    def get_unique_source_count(self, dst_ip, window_s=DEFAULT_WINDOW_S):
        cutoff = time.time() - window_s
        with self._lock:
            dq = self._dst_sources.get(dst_ip)
            if not dq:
                return 0
            return len({src for ts, src in dq if ts >= cutoff})

    def stats(self):
        with self._lock:
            return {"tracked_src_ips": len(self._fanout), "tracked_dst_ips": len(self._dst_sources)}
