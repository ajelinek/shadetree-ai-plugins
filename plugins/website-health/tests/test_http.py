import io
import urllib.error

import pytest
from shadetree_ai_plugins_website_health import http


def test_errors_redact_query_and_bearer_secrets(monkeypatch):
    def boom(req, timeout):
        raise urllib.error.HTTPError(req.full_url, 400, "Bad", {},
                                     io.BytesIO(b'{"Message": "bad key SECRET123"}'))

    monkeypatch.setattr(http.urllib.request, "urlopen", boom)
    with pytest.raises(http.HttpError) as exc:
        http.request("GET", "https://api.test/x", secret_params={"apikey": "SECRET123"})
    assert "SECRET123" not in str(exc.value)
    assert exc.value.status == 400


def test_build_url_repeats_list_params():
    url = http.build_url("https://x.test/a", {"category": ["seo", "performance"], "n": None})
    assert url == "https://x.test/a?category=seo&category=performance"
