from pathlib import Path
import ast


ROOT = Path(__file__).parents[1]


def test_capture_has_no_transmit_api():
    forbidden = {"send", "sendp", "sr", "sr1", "srp", "connect", "create_connection", "getaddrinfo", "gethostbyname"}
    for path in (ROOT / "capture").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr not in forbidden, f"outbound API in {path}: {node.func.attr}"
            if isinstance(node, ast.ImportFrom):
                assert node.module not in {"socket", "http.client", "urllib.request"}


def test_agent1_does_not_import_agent2_or_shared_decision_modules():
    forbidden_tokens = ("ensemble_engine", "perosn4", "soc-dashboard", "Meta-XGBoost", "final_decision")
    for path in ROOT.rglob("*.py"):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert not any(token in text for token in forbidden_tokens), path


def test_no_raw_payload_logging():
    for path in ROOT.rglob("*.py"):
        if "tests" not in path.parts:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"debug", "info", "warning", "error", "exception"}:
                    assert "payload" not in ast.unparse(node).lower()
