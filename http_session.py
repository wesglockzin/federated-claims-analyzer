"""HTTP session factory: one place that sets the User-Agent for every IdP call."""

from __future__ import annotations

import requests


def make_session(tool_name: str, tool_version: str) -> requests.Session:
    """Return a requests.Session with a User-Agent and an Accept header.

    Sets:
      - User-Agent: {tool_name}/{tool_version}
      - Accept:     application/json

    Callers may change `session.headers` afterwards, for example to add an
    Authorization header.
    """
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": f"{tool_name}/{tool_version}",
            "Accept": "application/json",
        }
    )
    return session
