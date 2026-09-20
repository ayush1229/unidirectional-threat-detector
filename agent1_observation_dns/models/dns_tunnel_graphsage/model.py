"""GraphSAGE DNS tunnel/DGA graph branch — real fit() and predict().

Node features: [length, entropy, digit_ratio, label_count] for each domain.
Edges: co-query relationships (anonymous — no IP/domain identity in model).
Labels: 1 = DNS tunnel or DGA graph, 0 = benign.
"""
from __future__ import annotations
import json
from math import log2
from collections import Counter
from time import perf_counter

import numpy as np
import torch

from agent1_observation_dns.models.common import absent, scored


def _entropy(text: str) -> float:
    n = len(text)
    counts = Counter(text)
    return -sum((c/n) * log2(c/n) for c in counts.values()) if n else 0.0


def _graph_tensors(node_features, edges):
    """Convert lists to float32 tensors; handle empty edge case."""
    x = torch.as_tensor(node_features, dtype=torch.float32)
    if edges:
        ei = torch.as_tensor(edges, dtype=torch.long).T  # [2, E]
    else:
        ei = torch.zeros((2, 0), dtype=torch.long)
    return x, ei


class _GraphSAGENet(torch.nn.Module):
    def __init__(self, in_features: int = 4, hidden: int = 16, out_dim: int = 8):
        super().__init__()
        self.fc1 = torch.nn.Linear(in_features * 2, hidden)
        self.fc2 = torch.nn.Linear(hidden * 2, out_dim)
        self.head = torch.nn.Linear(out_dim, 1)

    @staticmethod
    def _agg(x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        agg = torch.zeros_like(x)
        cnt = torch.zeros(len(x), 1)
        if edge_index.numel():
            src, dst = edge_index
            agg.index_add_(0, dst, x[src])
            cnt.index_add_(0, dst, torch.ones(len(src), 1))
        return agg / cnt.clamp_min(1)

    def embed(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        h1 = torch.relu(self.fc1(torch.cat([x, self._agg(x, edge_index)], dim=1)))
        h2 = torch.relu(self.fc2(torch.cat([h1, self._agg(h1, edge_index)], dim=1)))
        return h2

    def forward(self, x: torch.Tensor, edge_index: torch.Tensor) -> torch.Tensor:
        emb = self.embed(x, edge_index)
        return self.head(emb.mean(dim=0, keepdim=True)).squeeze(-1)  # graph-level score


class GraphBranch:
    """DNS tunnel GraphSAGE branch — fits on co-query DNS graphs."""
    name = "DNS_TUNNEL_GRAPHSAGE"

    def __init__(self):
        self._model: _GraphSAGENet | None = None
        self._version: str = "untrained"

    def fit(self, corpus: list[dict], path, *, epochs: int = 20, version: str) -> "GraphBranch":
        """Train on graph corpus rows from specialist_generators.dns_graph_corpus()."""
        train_rows = [r for r in corpus if r["split"] == "train"]
        if len(train_rows) < 4:
            raise ValueError("dns_tunnel_graphsage requires at least 4 training graphs")
        model = _GraphSAGENet(in_features=4, hidden=16, out_dim=8)
        optimizer = torch.optim.Adam(model.parameters(), lr=1e-3)
        model.train()
        targets = torch.as_tensor([float(r["graph_label"]) for r in train_rows])
        pos = targets.sum().item()
        neg = len(targets) - pos
        pos_weight = torch.tensor([neg / max(pos, 1)])
        for epoch in range(epochs):
            total_loss = torch.tensor(0.0)
            for i, row in enumerate(train_rows):
                x, ei = _graph_tensors(row["node_features"], row["edges"])
                logit = model(x, ei)
                loss = torch.nn.functional.binary_cross_entropy_with_logits(
                    logit, targets[i:i+1], pos_weight=pos_weight)
                optimizer.zero_grad()
                loss.backward()
                optimizer.step()
                total_loss = total_loss + loss.detach()
        model.eval()
        self._model = model
        self._version = version
        import os
        os.makedirs(str(path.parent), exist_ok=True)
        torch.save(model.state_dict(), path)
        return self

    def predict(self, event_id: str, domain: str | None, context: dict | None = None):
        context = context or {}
        graph = context.get("graph")
        if not graph or not graph.get("sufficient"):
            return absent(event_id, self.name, "INSUFFICIENT_RELATION_VISIBILITY", applicable=False)
        if self._model is None:
            return absent(event_id, self.name, "OPTIONAL_BRANCH_NOT_IMPLEMENTED")
        started = perf_counter()
        nodes = graph.get("nodes", [])    # [[is_client, is_domain, is_resolver, degree], ...]
        edges = graph.get("edges", [])    # [[src_idx, dst_idx], ...]
        if len(nodes) < 2:
            return absent(event_id, self.name, "INSUFFICIENT_GRAPH_NODES")
        # Node features: first 4 values from structural snapshot
        node_features = [n[:4] for n in nodes]
        self._model.eval()
        with torch.no_grad():
            x, ei = _graph_tensors(node_features, edges)
            score = float(torch.sigmoid(self._model(x, ei)).item())
        return scored(event_id, self.name, score, self._version, started,
                      evidence={"nodes": len(nodes), "edges": len(edges)},
                      reason="GRAPHSAGE_INFERENCE")

    @classmethod
    def load(cls, path) -> "GraphBranch":
        branch = cls()
        state = torch.load(path, weights_only=True)
        # Infer architecture from saved state
        in_f = state["fc1.weight"].shape[1] // 2
        hidden = state["fc1.weight"].shape[0]
        out_dim = state["fc2.weight"].shape[0]
        model = _GraphSAGENet(in_features=in_f, hidden=hidden, out_dim=out_dim)
        model.load_state_dict(state)
        model.eval()
        branch._model = model
        return branch
