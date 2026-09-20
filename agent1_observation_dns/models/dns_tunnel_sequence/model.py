"""Ordered metadata GRU baseline; not a reproduction of Domainator results."""
from time import perf_counter
import math
import torch
from torch import nn
from agent1_observation_dns.models.common import absent, scored

MAX_EVENTS = 128
SCALES = (253, 8, 65535, 65535, 3600, 15)


def encode_sequences(sequences):
    tensor = torch.zeros((len(sequences), MAX_EVENTS, 12), dtype=torch.float32)
    lengths = []
    for i, sequence in enumerate(sequences):
        if not sequence:
            raise ValueError("empty sequence")
        sequence = sequence[-MAX_EVENTS:]
        lengths.append(len(sequence))
        for j, event in enumerate(sequence):
            if len(event) != 6:
                raise ValueError("sequence event needs six metadata fields")
            for k, value in enumerate(event):
                if value is not None:
                    if not isinstance(value, (int, float)) or not math.isfinite(value):
                        raise ValueError("invalid sequence number")
                    tensor[i, j, k] = value/SCALES[k]
                    tensor[i, j, k+6] = 1
    return tensor, torch.tensor(lengths, dtype=torch.long)


class MetadataSequence(nn.Module):
    def __init__(self):
        super().__init__()
        self.gru = nn.GRU(12, 32, batch_first=True)
        self.output = nn.Linear(32, 1)

    def forward(self, values, lengths):
        packed = nn.utils.rnn.pack_padded_sequence(values, lengths.cpu(), batch_first=True, enforce_sorted=False)
        _, hidden = self.gru(packed)
        return self.output(hidden[-1]).squeeze(-1)


class SequenceBranch:
    name = "DNS_TUNNEL_SEQUENCE"

    def __init__(self, checkpoint=None, min_events=8):
        self.model, self.version, self.min_events = None, "untrained", min_events
        if checkpoint:
            data = torch.load(checkpoint, weights_only=True, map_location="cpu")
            if data.get("architecture") != "dns_tunnel_sequence" or not data.get("trained") or data.get("preprocessing_version") != "1.0.0":
                raise ValueError("incompatible sequence checkpoint")
            self.model = MetadataSequence()
            self.model.load_state_dict(data["state_dict"])
            self.model.eval()
            self.version = data["model_version"]

    def predict(self, event_id, domain, context=None):
        started = perf_counter()
        sequence = (context or {}).get("sequence")
        if hasattr(sequence, "value"):
            sequence = sequence.value if sequence.available else None
        elif isinstance(sequence, dict):
            sequence = sequence.get("value") if sequence.get("available") else None
        if sequence is None or len(sequence) < self.min_events:
            return absent(event_id, self.name, "INSUFFICIENT_DNS_HISTORY", applicable=False)
        if self.model is None:
            return absent(event_id, self.name, "CHECKPOINT_ABSENT")
        with torch.inference_mode():
            probability = self.model(*encode_sequences([sequence])).sigmoid().item()
        return scored(event_id, self.name, probability, self.version, started)
