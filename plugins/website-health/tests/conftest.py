import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from shadetree_ai_plugins_common import secrets  # noqa: E402

PACKAGE = "shadetree_ai_plugins_website_health"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Fresh HOME (state dir) and an in-memory keychain for every test."""
    monkeypatch.setenv("HOME", str(tmp_path))
    ring: dict = {}

    class MemoryKeyring:
        def get_password(self, service, username):
            return ring.get((service, username))

        def set_password(self, service, username, password):
            ring[service, username] = password

        def delete_password(self, service, username):
            ring.pop((service, username), None)

    monkeypatch.setattr(secrets, "_secure_backend", lambda: MemoryKeyring())
    from shadetree_ai_plugins_website_health import google_auth

    google_auth.clear_cache()
    return ring


@pytest.fixture
def store(tmp_path):
    from shadetree_ai_plugins_website_health.store import Store

    s = Store(tmp_path / "state")
    yield s
    s.close()


@pytest.fixture
def site():
    from shadetree_ai_plugins_website_health import config

    config.upsert_site("prod", {"url": "https://example.com", "timezone": "UTC",
                                "ga4PropertyId": "123", "gscSiteUrl": "sc-domain:example.com",
                                "bingSiteUrl": "https://example.com/",
                                "clarityProjectId": "abc", "githubRepos": ["org/repo"]})
    return config.site("prod")
