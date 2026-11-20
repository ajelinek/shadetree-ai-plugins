from datetime import UTC, datetime, timedelta

from shadetree_ai_plugins_website_health import collector, credentials, http
from shadetree_ai_plugins_website_health.analysis import anomalies
from shadetree_ai_plugins_website_health.sources import psi
from shadetree_ai_plugins_website_health.store import Row

RESPONSE = {
    "lighthouseResult": {
        "finalDisplayedUrl": "https://example.com/",
        "categories": {"performance": {"score": 0.42}, "accessibility": {"score": 0.8},
                       "best-practices": {"score": 1}, "seo": {"score": 0.95}},
        "audits": {
            "largest-contentful-paint": {"numericValue": 4100, "score": 0.2,
                                         "scoreDisplayMode": "numeric"},
            "total-byte-weight": {"numericValue": 3_500_000},
            "render-blocking-resources": {"title": "Eliminate render-blocking resources",
                                          "score": 0.3, "scoreDisplayMode": "numeric",
                                          "details": {"overallSavingsMs": 900}},
            "image-alt": {"title": "Images need alt", "score": 0, "scoreDisplayMode": "binary"},
        }},
    "loadingExperience": {"metrics": {
        "LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 3100, "category": "AVERAGE"},
        "CUMULATIVE_LAYOUT_SHIFT_SCORE": {"percentile": 30, "category": "AVERAGE"}}},
}
SITE = {"name": "prod", "url": "https://example.com", "timezone": "UTC", "keyPaths": ["/"]}


def test_summarize_extracts_opportunities_lab_and_field():
    s = psi.summarize(RESPONSE)
    assert s["scores"]["performance"] == 42
    assert s["opportunities"][0]["id"] == "render-blocking-resources"
    assert s["opportunities"][0]["savingsMs"] == 900
    assert "render-blocking-resources" not in {a["id"] for a in s["failingAudits"]}
    assert s["lab"]["totalBytes"] == 3_500_000 and s["lab"]["lcpMs"] == 4100
    assert s["field"]["scope"] == "url"
    assert s["field"]["metrics"]["clsP75"]["p75"] == 0.3


def test_insight_style_audits_use_metric_savings():
    data = {"lighthouseResult": {"categories": {}, "audits": {
        "render-blocking-insight": {"title": "Render blocking", "score": 0,
                                    "scoreDisplayMode": "metricSavings",
                                    "metricSavings": {"FCP": 450, "LCP": 300}, "details": {}}}}}
    assert psi.summarize(data)["opportunities"] == [
        {"id": "render-blocking-insight", "title": "Render blocking", "savingsMs": 450,
         "savingsBytes": 0}]


def test_collect_stores_weekly_points_and_keyless_field_findings(store, monkeypatch):
    monkeypatch.setattr(psi, "_call", lambda url, strategy, key: RESPONSE)
    result = psi.collect(SITE, store)
    store.upsert("prod", result.rows)
    assert result.summary["keyless"] is True
    assert store.series("prod", "psi.performance")[0]["value"] == 42
    assert store.series("prod", "psi.performance", dim="page=/")[0]["grain"] == "week"
    assert store.series("prod", "psi.fieldLcpP75")[0]["value"] == 3100
    kinds = {f["kind"] for f in result.findings}
    assert {"lighthouse_performance_poor", "lighthouse_accessibility_low",
            "core_web_vital"} <= kinds


def test_collect_is_interval_gated_and_keeps_last_findings(store, monkeypatch):
    calls = []
    monkeypatch.setattr(psi, "_call", lambda *a: calls.append(a) or RESPONSE)
    first = psi.collect(SITE, store)
    again = psi.collect(SITE, store)
    assert len(calls) == 1 and "skipped" in again.summary
    assert again.findings == first.findings
    assert psi.collect(SITE, store, force=True).rows
    assert len(calls) == 2
    store.put("prod", "psi.lastRun", (datetime.now(UTC) - timedelta(days=7)).date().isoformat())
    psi.collect(SITE, store)
    assert len(calls) == 3


def test_quota_error_is_a_warning_not_a_failed_source(store, monkeypatch):
    def boom(*a):
        raise http.HttpError("HTTP 429: quota", 429)

    monkeypatch.setattr(psi, "_call", boom)
    result = psi.collect(SITE, store)
    assert result.rows == [] and "quota" in result.warnings[0]
    assert store.get("prod", "psi.lastRun") is None  # retried next run


def test_psi_source_is_ready_without_a_key(site):
    assert credentials.status("google-api-key") == "missing"
    assert collector.source_status(site, "psi")["status"] == "ready"
    assert collector.source_status(site, "crux")["status"] == "setup_required"


def test_lab_timings_and_bytes_count_as_lower_is_better():
    for metric in ("psi.lcpMs", "psi.totalBytes", "psi.layoutShift", "psi.fieldLcpP75"):
        assert not anomalies.higher_is_better(metric)
    assert anomalies.higher_is_better("psi.performance")


def test_performance_score_drop_is_a_regression(store, site):
    for i, score in enumerate([90, 91, 89, 90, 60]):
        day = (datetime(2026, 11, 1) + timedelta(days=7 * i)).date().isoformat()
        store.upsert("prod", [Row("psi.performance", day, score, grain="week")])
    found = anomalies.detect(store, site)["anomalies"]
    hit = next(a for a in found if a["metric"] == "psi.performance")
    assert hit["direction"] == "regression" and hit["severityDraft"] == "critical"


def test_reminder_asks_for_an_audit_until_one_runs(store, site):
    assert any("audit_site" in r for r in collector.reminders(store, site))
    store.put("prod", "audit.last", {"date": datetime.now(UTC).date().isoformat()})
    assert not any("audit_site" in r for r in collector.reminders(store, site))
