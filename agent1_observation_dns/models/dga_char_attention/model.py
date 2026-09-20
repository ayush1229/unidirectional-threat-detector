"""Compact masked character attention model. Random weights never score traffic."""
from pathlib import Path
from time import perf_counter
import torch
from torch import nn

from agent1_observation_dns.models.common import absent, scored, normalize_domain

ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789-_."
MAX_LENGTH = 253


def encode_domains(domains):
    encoded = torch.zeros((len(domains), MAX_LENGTH), dtype=torch.long)
    for row, domain in enumerate(domains):
        values = [ALPHABET.index(c)+1 for c in normalize_domain(domain)]
        encoded[row, :len(values)] = torch.tensor(values)
    return encoded


class CharacterAttention(nn.Module):
    def __init__(self):
        super().__init__()
        self.embedding = nn.Embedding(len(ALPHABET)+1, 24, padding_idx=0)
        self.conv = nn.Conv1d(24, 48, 3, padding=1)
        self.attention = nn.Linear(48, 1)
        self.output = nn.Linear(48, 1)

    def forward(self, tokens):
        hidden = torch.relu(self.conv(self.embedding(tokens).transpose(1, 2))).transpose(1, 2)
        weights = self.attention(hidden).squeeze(-1).masked_fill(tokens == 0, -1e9).softmax(dim=1)
        return self.output((hidden*weights.unsqueeze(-1)).sum(dim=1)).squeeze(-1)


class CharacterCNN(CharacterAttention):
    """Architecture comparison using masked mean pooling instead of attention."""
    def forward(self, tokens):
        hidden = torch.relu(self.conv(self.embedding(tokens).transpose(1, 2))).transpose(1, 2)
        mask = (tokens != 0).unsqueeze(-1)
        return self.output((hidden*mask).sum(1)/mask.sum(1).clamp(min=1)).squeeze(-1)


class CharacterBranch:
    name = "DGA_CHARACTER"

    def __init__(self, checkpoint: str | Path | None = None):
        self.model = None
        self.version = "untrained"
        if checkpoint:
            artifact = torch.load(checkpoint, map_location="cpu", weights_only=True)
            if artifact.get("architecture") != "dga_char_attention" or artifact.get("preprocessing_version") != "1.0.0":
                raise ValueError("incompatible character checkpoint")
            if not artifact.get("trained"):
                raise ValueError("checkpoint has not been trained")
            self.model = CharacterAttention()
            self.model.load_state_dict(artifact["state_dict"])
            self.model.eval()
            self.version = artifact["model_version"]

    def predict(self, event_id, domain, context=None):
        started = perf_counter()
        normalize_domain(domain)
        if self.model is None:
            return absent(event_id, self.name, "CHECKPOINT_ABSENT")
        with torch.inference_mode():
            probability = self.model(encode_domains([domain])).sigmoid().item()
        return scored(event_id, self.name, probability, self.version, started)
