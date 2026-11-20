import json

import pytest
from shadetree_ai_plugins_website_health import config
from shadetree_ai_plugins_website_health.store import Flag, Row


def test_site_merges_defaults_and_validates(site):
    assert site["ga4PropertyId"] == "123"
    assert site["anomalyThresholds"]["ga4.keyEvents"]["method"] == "percentChange"
    assert "ga4.conversions" not in site["anomalyThresholds"]
    with pytest.raises(config.ConfigError):
        config.upsert_site("prod", {"gscSiteUrl": "https://example.com"})  # no trailing slash
    with pytest.raises(config.ConfigError):
        config.upsert_site("prod", {"apiKey": "nope"})  # unknown keys rejected
    with pytest.raises(config.ConfigError):
        config.upsert_site("new", {"timezone": "UTC"})  # new site needs url
    assert config.upsert_site("prod", {"ga4PropertyId": "properties/456"})["ga4PropertyId"] == "456"


def test_legacy_import_renames_conversions_to_key_events(tmp_path):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(json.dumps({
        "timezone": "America/New_York", "githubRepos": ["org/repo"],
        "sites": [{"name": "prod", "gscSiteUrl": "https://example.com/",
                   "ga4PropertyId": "properties/1"}],
        "anomalyThresholds": {"conversions": {"method": "percentChange", "baselineDays": 7,
                                              "warn": 0.2, "critical": 0.4}}}))
    imported = config.import_legacy(legacy)["prod"]
    assert imported["url"] == "https://example.com"
    assert imported["anomalyThresholds"]["ga4.keyEvents"]["warn"] == 0.2


def test_upsert_replaces_provisional_values(store):
    store.upsert("s", [Row("ga4.sessions", "2026-01-02", 10, provisional=True)])
    store.upsert("s", [Row("ga4.sessions", "2026-01-02", 12)])
    rows = store.series("s", "ga4.sessions")
    assert [(r["value"], r["provisional"]) for r in rows] == [(12, 0)]
    store.add_flags("s", [Flag("ga4", "2026-01-02", "thresholded")])
    assert store.flags_for("s", "2026-01-02")[0]["flag"] == "thresholded"
    store.record_call("s", "clarity")
    store.record_call("s", "clarity")
    assert store.calls_today("s", "clarity") == 2
