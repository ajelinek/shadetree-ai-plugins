import json

from fastmcp import Client
from shadetree_ai_plugins_website_health import collector, config, credentials, doctor
from shadetree_ai_plugins_website_health.server import mcp

FAKE_SA = json.dumps({"type": "service_account", "client_email": "wh@proj.iam.gserviceaccount.com",
                      "private_key": "fixture-private-key"})


async def test_tools_never_take_or_return_secrets(isolated):
    isolated["shadetree-ai-plugins:website-health", "bing-api-key"] = "BINGSECRET"
    config.upsert_site("prod", {"url": "https://example.com", "bingSiteUrl": "https://example.com/"})
    async with Client(mcp) as client:
        tools = await client.list_tools()
        for tool in tools:
            schema = json.dumps(getattr(tool, "input_schema", None) or tool.inputSchema).lower()
            assert "api_key" not in schema and "token" not in schema and "password" not in schema
        report = (await client.call_tool("check_setup", {})).data
    dumped = json.dumps(report)
    assert "BINGSECRET" not in dumped
    assert "doctor" in report["doctor_command"]
    bing = next(s for s in report["sites"]["prod"] if s["source"] == "bing")
    assert bing["status"] == "ready"
    ga4 = next(s for s in report["sites"]["prod"] if s["source"] == "ga4")
    assert ga4["status"] == "not_configured"


async def test_collect_reports_setup_required_without_network(isolated):
    config.upsert_site("prod", {"url": "https://example.com", "ga4PropertyId": "1"})
    async with Client(mcp) as client:
        out = (await client.call_tool("collect", {"site": "prod", "sources": ["ga4"]})).data
    assert out["sources"]["ga4"]["status"] == "setup_required"


async def test_unknown_site_is_a_structured_error():
    async with Client(mcp) as client:
        out = (await client.call_tool("detect_anomalies", {"site": "nope"})).data
    assert out["ok"] is False and out["error"] == "config"


def test_grant_hint_names_service_account_email(isolated):
    isolated["shadetree-ai-plugins:website-health", "google-service-account"] = FAKE_SA

    class Forbidden(Exception):
        status = 403

    hint = collector.grant_hint("ga4", Forbidden())
    assert "wh@proj.iam.gserviceaccount.com" in hint["fix"] and "Viewer" in hint["fix"]


def test_per_site_clarity_credential_key():
    assert credentials.BY_KEY["clarity-token"].keychain_key("prod") == "clarity-token.prod"


def test_doctor_refuses_non_interactive(monkeypatch, capsys):
    monkeypatch.setattr(doctor.sys.stdin, "isatty", lambda: False)
    assert doctor.main([]) == 1
    assert "terminal" in capsys.readouterr().err


def test_doctor_stores_hidden_value_and_validates(monkeypatch, isolated):
    monkeypatch.setattr(doctor.sys.stdin, "isatty", lambda: True)
    answers = iter(["BINGSECRET", "BINGSECRET"])
    monkeypatch.setattr(doctor.getpass, "getpass", lambda *a: next(answers))
    monkeypatch.setitem(doctor.VALIDATORS, "bing-api-key", lambda v, s: "key sees 1 site(s)")
    assert doctor.main(["--only", "bing-api-key"]) == 0
    assert isolated["shadetree-ai-plugins:website-health", "bing-api-key"] == "BINGSECRET"


def test_doctor_stores_service_account_file_and_deletes_it(monkeypatch, isolated, tmp_path):
    key = tmp_path / "sa.json"
    key.write_text(FAKE_SA)
    monkeypatch.setattr(doctor.sys.stdin, "isatty", lambda: True)
    inputs = iter([str(key), "yes"])
    monkeypatch.setattr("builtins.input", lambda *a: next(inputs))
    assert doctor.main(["--only", "google-service-account", "--no-validate"]) == 0
    stored = isolated["shadetree-ai-plugins:website-health", "google-service-account"]
    assert json.loads(stored)["client_email"].startswith("wh@")
    assert not key.exists()


def test_service_account_token_is_signed_and_cached(monkeypatch, isolated):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from shadetree_ai_plugins_website_health import google_auth, http

    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()).decode()
    info = {"type": "service_account", "client_email": "wh@p.iam.gserviceaccount.com",
            "private_key": pem, "private_key_id": "k1",
            "token_uri": "https://oauth2.googleapis.com/token"}
    isolated["shadetree-ai-plugins:website-health", "google-service-account"] = json.dumps(info)
    calls = []

    def fake(method, url, **kw):
        calls.append(kw["form"])
        return http.Response(200, {}, {"access_token": "ya29.test", "expires_in": 3600})

    monkeypatch.setattr(http, "request", fake)
    assert google_auth.headers("ga4") == {"Authorization": "Bearer ya29.test"}
    google_auth.token("ga4")
    assert len(calls) == 1 and calls[0]["assertion"].count(".") == 2
