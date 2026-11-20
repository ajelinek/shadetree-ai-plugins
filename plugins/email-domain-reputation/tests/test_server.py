import importlib
import importlib.util
import json
from pathlib import Path

import keyring
import pytest
from fastmcp import Client

PACKAGE = "shadetree_ai_plugins_email_domain_reputation"


def server_module():
    assert importlib.util.find_spec(PACKAGE), "The reputation plugin package must exist"
    return importlib.import_module(f"{PACKAGE}.server")


async def test_mcp_tools_never_accept_or_return_api_keys(monkeypatch):
    module = server_module()
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())
    async with Client(module.mcp) as client:
        tools = await client.list_tools()
        assert {tool.name for tool in tools} == {
            "check_setup", "investigate_email", "audit_domain", "audit_client_domain"}
        for tool in tools:
            assert "api_key" not in json.dumps(tool.input_schema)
            assert tool.annotations.read_only_hint is True
        report = (await client.call_tool("check_setup", {})).data
    assert report["ready"] is False
    assert "credentials set" in report["setup_command"]


async def test_missing_key_prevents_address_network_calls(monkeypatch):
    module = server_module()
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())
    async with Client(module.mcp) as client:
        report = (await client.call_tool("investigate_email", {"email": "person@example.com"})).data
    assert report["ok"] is False
    assert report["error"] == "setup_required"
    assert "dns" not in report


KEY = "sk-test-SECRET-123"
NXDOMAIN = {"status": "NXDOMAIN", "answers": [], "ad": False}


def _module(name):
    return importlib.import_module(f"{PACKAGE}.{name}")


def fake_query(calls):
    def query(name, rtype, **kwargs):
        calls.append((name, rtype))
        return dict(NXDOMAIN, answers=[])
    return query


async def test_keyless_domain_audit_uses_real_dns_aggregation(monkeypatch):
    module = server_module()
    calls = []
    monkeypatch.setattr(_module("_dns"), "query", fake_query(calls))
    async with Client(module.mcp) as client:
        report = (await client.call_tool("audit_domain", {"target": "example.com"})).data
    assert report["ok"] is True
    assert set(report) == {"ok", "checked_at", "dns"}
    assert report["dns"]["spf"]["found"] is False
    assert report["dns"]["dmarc"]["found"] is False
    assert calls


async def call_client_audit(module, args):
    async with Client(module.mcp) as client:
        return (await client.call_tool("audit_client_domain", args)).data


def use_key(monkeypatch, module, key=KEY):
    monkeypatch.setattr(module, "get_secret", lambda namespace, name: key)


@pytest.mark.parametrize(("args", "fragment"), [
    ({"target": "example.com"}, "audit_domain"),
    ({"target": "person@example.com", "raw_headers": "From: a@example.com\n" * 20000}, "256 KB"),
    ({"target": "person@example.com", "raw_headers": "no headers here"}, "headers"),
    ({"target": "person@example.com", "sending_ips": ["999.1.1.1"]}, "IP"),
    ({"target": "person@example.com", "selectors": ["bad selector"]}, "selector"),
])
async def test_client_audit_rejects_invalid_input_before_key_or_network(
        monkeypatch, args, fragment):
    module = server_module()
    calls, key_reads = [], []
    monkeypatch.setattr(_module("_dns"), "query", fake_query(calls))
    monkeypatch.setattr(module, "get_secret", lambda *a: key_reads.append(a) or KEY)
    report = await call_client_audit(module, args)
    assert report["ok"] is False
    assert report["error"] == "invalid_input"
    assert fragment in report["detail"]
    assert calls == [] and key_reads == []


async def test_client_audit_missing_key_is_setup_required_without_network(monkeypatch):
    module = server_module()
    calls = []
    monkeypatch.setattr(keyring, "get_keyring", lambda: keyring.backends.fail.Keyring())
    monkeypatch.setattr(_module("_dns"), "query", fake_query(calls))
    report = await call_client_audit(module, {"target": "person@example.com"})
    assert report["ok"] is False
    assert report["error"] == "setup_required"
    assert "credentials set" in report["setup_command"]
    assert "sections" not in report
    assert calls == []


def mock_network(monkeypatch, reputation_result):
    calls = {"dns": [], "rdap": [], "reputation": []}
    monkeypatch.setattr(_module("_dns"), "query", fake_query(calls["dns"]))
    monkeypatch.setattr(_module("registration"), "fetch_rdap", lambda domain, *a, **k: (
        calls["rdap"].append(domain) or
        {"ok": True, "error": None, "detail": None, "raw": {"nameservers": []}}))
    monkeypatch.setattr(_module("reputation"), "check_reputation", lambda email, key: (
        calls["reputation"].append((email, key)) or reputation_result))
    return calls


async def test_client_audit_reputation_failure_returns_no_partial_audit(monkeypatch):
    module = server_module()
    use_key(monkeypatch, module)
    failure = {"signals": {}, "source": {"ok": False, "error": "quota_exhausted",
                                         "detail": "AbstractAPI credits or access are exhausted."}}
    calls = mock_network(monkeypatch, failure)
    report = await call_client_audit(module, {"target": "person@example.com"})
    assert report == {"ok": False, "error": "reputation_unavailable", **failure}
    assert calls["reputation"] == [("person@example.com", KEY)]
    assert calls["dns"] == [] and calls["rdap"] == []  # reputation runs first
    assert KEY not in json.dumps(report)


async def test_client_audit_reputation_exception_is_unavailable_and_scrubbed(monkeypatch):
    module = server_module()
    use_key(monkeypatch, module)
    calls = mock_network(monkeypatch, None)

    def boom(email, key):
        raise RuntimeError(f"Bearer {key} rejected")
    monkeypatch.setattr(_module("reputation"), "check_reputation", boom)
    report = await call_client_audit(module, {"target": "person@example.com"})
    assert report["ok"] is False
    assert report["error"] == "reputation_unavailable"
    assert report["source"]["ok"] is False
    assert "sections" not in report
    assert report["source"]["error"] == "unexpected_error"
    assert calls["dns"] == [] and calls["rdap"] == []
    assert KEY not in json.dumps(report)


async def test_client_audit_success_returns_full_audit_without_key(monkeypatch):
    module = server_module()
    use_key(monkeypatch, module)
    ok = {"signals": {"deliverable": True}, "source": {"ok": True, "error": None, "detail": None}}
    calls = mock_network(monkeypatch, ok)
    raw = (Path(__file__).parent / "fixtures" / "headers" / "gmail_pass_aligned.eml").read_text()
    report = await call_client_audit(module, {
        "target": "Person@Example.com", "raw_headers": raw, "selectors": ["Custom"],
        "sending_ips": ["198.51.100.7"]})
    assert report["ok"] is True
    assert report["target"] == "Person@example.com"
    assert report["domain"] == "example.com"
    assert report["section_errors"] == {}
    assert report["skipped"] == {}
    sections = report["sections"]
    assert sections["reputation"] == ok
    assert sections["headers"]["from"]["domain"]
    assert sections["dns"]["dkim"]["selectors_checked"][:2] == ["custom", "s1"]
    # Documentation IPs are reserved, so blocklists reports them as skipped.
    assert [(ip["ip"], ip["source"]) for ip in sections["blocklists"]["skipped_ips"]] == [
        ("198.51.100.7", "argument"), ("203.0.113.25", "headers")]
    assert sections["registration"]["source"]["ok"] is True
    assert calls["rdap"] == ["example.com"]
    assert calls["reputation"] == [("Person@example.com", KEY)]
    assert len(report["cross_checks"]) == 7
    assert KEY not in json.dumps(report)
