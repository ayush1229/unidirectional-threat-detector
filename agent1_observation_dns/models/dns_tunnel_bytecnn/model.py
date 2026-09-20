"""Byte CNN over canonical DNS query-name wire structure (not encrypted content)."""
from time import perf_counter
import torch
from torch import nn
from agent1_observation_dns.models.common import normalize_domain, absent, scored


def encode_bytes(domains):
    output = torch.zeros((len(domains), 256), dtype=torch.long)
    for i, domain in enumerate(domains):
        wire = b"".join(bytes([len(label)])+label.encode("ascii") for label in normalize_domain(domain).split(".")) + b"\0"
        output[i, :len(wire)] = torch.tensor([b+1 for b in wire])
    return output


class ByteCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(257, 16, padding_idx=0)
        self.conv = nn.Conv1d(16, 32, 5, padding=2)
        self.output = nn.Linear(32, 1)

    def forward(self, tokens):
        hidden = torch.relu(self.conv(self.embedding(tokens).transpose(1, 2)))
        hidden = hidden.masked_fill((tokens == 0).unsqueeze(1), -1e9)
        return self.output(hidden.amax(dim=2)).squeeze(-1)


class ByteBranch:
    name = "DNS_TUNNEL_BYTECNN"
    architecture = "dns_tunnel_bytecnn"

    def __init__(self, checkpoint=None):
        self.model, self.version = None, "untrained"
        if checkpoint:
            data = torch.load(checkpoint, weights_only=True, map_location="cpu")
            if data.get("architecture") != self.architecture or not data.get("trained") or data.get("preprocessing_version") != "1.0.0":
                raise ValueError("incompatible byte CNN checkpoint")
            self.model = ByteCNN()
            self.model.load_state_dict(data["state_dict"])
            self.model.eval()
            self.version = data["model_version"]

    def predict(self, event_id, domain, context=None):
        started = perf_counter()
        if self.model is None:
            return absent(event_id, self.name, "CHECKPOINT_ABSENT")
        with torch.inference_mode():
            probability = self.model(encode_bytes([domain])).sigmoid().item()
        return scored(event_id, self.name, probability, self.version, started)
