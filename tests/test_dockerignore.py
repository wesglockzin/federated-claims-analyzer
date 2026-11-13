from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_dockerignore_excludes_local_settings_files():
    # A local settings file baked into the image could switch the login off.
    lines = {line.strip() for line in (ROOT / ".dockerignore").read_text().splitlines()}
    assert "env.config" in lines
    assert "env.config.DO_NOT_SHARE" in lines
    assert ".env" in lines
