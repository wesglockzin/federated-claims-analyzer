"""Where the service listens: all interfaces in the container, loopback in dev."""

from pathlib import Path

import sso_tester_logic as logic

DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"


def test_container_command_binds_all_interfaces_on_port():
    commands = [
        line for line in DOCKERFILE.read_text().splitlines() if line.startswith("CMD")
    ]
    assert len(commands) == 1
    assert "--bind 0.0.0.0:${PORT:-8080}" in commands[0]


def test_listen_port_follows_port():
    assert logic.listen_port({"PORT": "9123"}) == 9123
    assert logic.listen_port({}) == 8080


def test_dev_server_listens_on_loopback_on_the_configured_port(app_mod, monkeypatch):
    calls = []
    monkeypatch.setattr(app_mod.app, "run", lambda **kwargs: calls.append(kwargs))
    monkeypatch.setattr(app_mod.os.path, "exists", lambda path: True)
    assert app_mod.start_flask_dev_server() is True
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == logic.LISTEN_PORT
