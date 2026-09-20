"""Allowlisted structured logging: payloads and raw names are never serialized."""
import json
import logging

FIELDS = ("event_id", "processing_ms", "state_size", "feature_availability", "route_decision",
          "skipped_specialists", "reason_codes", "model_version")


class JSONFormatter(logging.Formatter):
    def format(self, record):
        return json.dumps({"stage": record.name, "event": record.getMessage(), "level": record.levelname,
                           **{key: getattr(record, key) for key in FIELDS if hasattr(record, key)}}, allow_nan=False)


def configure_logging():
    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    logger = logging.getLogger("agent1")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
