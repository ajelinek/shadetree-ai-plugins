"""Parser and error-mapping tests for each source, using fixture payloads."""

from datetime import UTC, datetime, timedelta

from shadetree_ai_plugins_website_health.sources import (
    bing,
    clarity,
    cloud_monitoring,
    crux,
    firebase_auth,
    ga4,
    gsc,
    psi,
)


def test_ga4_parse_rows_flags_and_ai_referrers():
    totals = {"metricHeaders": [{"name": "sessions"}, {"name": "keyEvents"}],
              "rows": [{"dimensionValues": [{"value": "20260101"}],
                        "metricValues": [{"value": "100"}, {"value": "5"}]},
                       {"dimensionValues": [{"value": "20260102"}],
                        "metricValues": [{"value": "90"}, {"value": "4"}]}],
              "metadata": {"subjectToThresholding": True, "dataLossFromOtherRow": True,
                           "dataTruncationReasons": ["TOO_MANY_ROWS"]}}
    sources = {"rows": [{"dimensionValues": [{"value": "20260101"}, {"value": "chatgpt.com"}],
                         "metricValues": [{"value": "7"}]},
                        {"dimensionValues": [{"value": "20260101"}, {"value": "google"}],
                         "metricValues": [{"value": "50"}]}]}
    res = ga4.parse([totals, {}, {}, sources, {}], ["chatgpt.com"], "2026-01-02",
                    "2026-01-01", "2026-01-02")
    by = {(r.metric, r.period_end, r.dim): r for r in res.rows}
    assert by["ga4.keyEvents", "2026-01-01", ""].value == 5
    assert by["ga4.sessions", "2026-01-02", ""].provisional is True
    assert by["ga4.aiReferralSessions", "2026-01-01", ""].value == 7
    assert by["ga4.aiReferralSessions", "2026-01-02", ""].value == 0
    assert {f.flag for f in res.flags} == {"thresholded", "other_row", "truncated"}


def test_ga4_requests_use_key_events_not_conversions():
    body = str(ga4.build_requests("2026-01-01", "2026-01-07", "sign_up"))
    assert "keyEvents" in body and "conversions" not in body


def test_gsc_first_incomplete_date_marks_provisional():
    data = {"rows": [{"keys": ["2026-01-01"], "clicks": 10, "impressions": 100, "ctr": 0.1,
                      "position": 4.2},
                     {"keys": ["2026-01-03"], "clicks": 3, "impressions": 40, "ctr": 0.07,
                      "position": 5.0}],
            "metadata": {"firstIncompleteDate": "2026-01-03"}}
    start = gsc.first_incomplete(data)
    rows = gsc.parse_daily(data, start)
    assert start == "2026-01-03"
    assert [r.provisional for r in rows if r.metric == "gsc.clicks"] == [False, True]
    insp = gsc.summarize_inspection("https://e.com/", {"inspectionResult": {
        "indexStatusResult": {"verdict": "PASS", "googleCanonical": "https://e.com/a",
                              "userCanonical": "https://e.com/"}}})
    assert insp["canonicalMismatch"] is True


def test_clarity_parse_is_case_insensitive_and_coerces_strings():
    blocks = [
        {"metricName": "Traffic", "information": [
            {"totalSessionCount": "200", "totalBotSessionCount": "50",
             "distantUserCount": "150", "PagesPerSessionPercentage": "1.8"}]},
        {"metricName": "RageClickCount", "information": [
            {"sessionsCount": "200", "sessionsWithMetricPercentage": "3.5", "subTotal": "7"}]},
        {"metricName": "Script Error Count", "information": [
            {"sessionsWithMetricPercentage": 1.25, "Url": "https://e.com/x"}]},
    ]
    rows = {r.metric: r for r in clarity.parse(blocks, "2026-01-02", "2026-01-01", "rolling24h")}
    assert rows["clarity.sessions"].value == 200
    assert rows["clarity.distinctUsers"].value == 150
    assert rows["clarity.botSharePct"].value == 20
    assert rows["clarity.rageClickPct"].value == 3.5
    by_url = clarity.parse(blocks, "2026-01-02", "2026-01-01", "rolling24h", by_url=True)
    assert [r.dim for r in by_url] == ["page=https://e.com/x"]


def test_clarity_window_covers_gap_since_last_snapshot():
    now = datetime(2026, 1, 10, 12, tzinfo=UTC)
    assert clarity.plan_window(None, now) == (1, None)
    assert clarity.plan_window((now - timedelta(hours=30)).isoformat(), now) == (2, None)
    days, lost = clarity.plan_window((now - timedelta(hours=100)).isoformat(), now)
    assert days == 3 and round(lost) == 28


def test_clarity_skips_recent_snapshot_to_protect_quota(store, site, isolated):
    isolated["shadetree-ai-plugins:website-health", "clarity-token.prod"] = "a.b.c"
    store.put("prod", "clarity.lastCallAt", datetime.now(UTC).isoformat())
    res = clarity.collect(site, store)
    assert res.summary["skipped"] and store.calls_today("prod", "clarity") == 0


def test_bing_dates_respect_offset_and_unwrap_envelope():
    assert bing.parse_date("/Date(1316156400000-0700)/") == "2011-09-16"
    rows = bing.parse_traffic([{"Date": "/Date(1316156400000-0700)/", "Clicks": 4,
                                "Impressions": 90}], "2011-09-20")
    assert {r.metric: r.value for r in rows} == {"bing.clicks": 4, "bing.impressions": 90}
    weekly = bing.parse_weekly([{"Date": "/Date(1316156400000)/", "Query": "shoes",
                                 "Clicks": 1, "Impressions": 9, "AvgImpressionPosition": 3}],
                               "query")
    assert all(r.grain == "week" and r.dim == "query=shoes" for r in weekly)


def test_firebase_counts_first_provider_only():
    day_ms = int(datetime(2026, 1, 5, 12, tzinfo=UTC).timestamp() * 1000)
    users = [{"createdAt": str(day_ms), "providerUserInfo": [{"providerId": "google.com"},
                                                             {"providerId": "password"}]},
             {"createdAt": str(day_ms), "providerUserInfo": [{"providerId": "password"}]}]
    rows = firebase_auth.aggregate(users, "UTC", "2026-01-05")
    totals = [r for r in rows if r.period_end == "2026-01-05"]
    assert {r.dim: r.value for r in totals} == {"": 2, "provider=google.com": 1,
                                                "provider=password": 1}


def test_crux_history_rows_and_ratings():
    data = {"record": {"collectionPeriods": [
        {"firstDate": {"year": 2026, "month": 1, "day": 1},
         "lastDate": {"year": 2026, "month": 1, "day": 28}}],
        "metrics": {"largest_contentful_paint": {"percentilesTimeseries": {"p75s": [3100]}},
                    "cumulative_layout_shift": {"percentilesTimeseries": {"p75s": ["0.05"]}}}}}
    rows = crux.parse_history(data, "formFactor=PHONE")
    assert {r.metric: r.value for r in rows} == {"crux.lcpP75": 3100, "crux.clsP75": 0.05}
    assert crux.rating("lcpP75", 3100) == "needs_improvement"
    assert crux.rating("inpP75", 600) == "poor"


def test_psi_summary_lists_failing_audits():
    data = {"lighthouseResult": {"requestedUrl": "https://e.com/",
                                 "categories": {"performance": {"score": 0.71}},
                                 "audits": {"render-blocking-resources": {
                                     "score": 0.3, "scoreDisplayMode": "numeric",
                                     "title": "Eliminate render-blocking resources"},
                                     "is-on-https": {"score": 1, "scoreDisplayMode": "binary"}}}}
    s = psi.summarize(data)
    assert s["scores"] == {"performance": 71}
    assert [a["id"] for a in s["failingAudits"]] == ["render-blocking-resources"]


def test_cloud_monitoring_groups_status_classes():
    data = {"timeSeries": [
        {"metric": {"labels": {"status": "503"}},
         "points": [{"interval": {"endTime": "2026-01-02T00:00:00Z"},
                     "value": {"int64Value": "3"}}]},
        {"metric": {"labels": {"status": "200"}},
         "points": [{"interval": {"endTime": "2026-01-02T00:00:00Z"},
                     "value": {"int64Value": "97"}}]}]}
    rows = {(r.metric, r.dim): r.value for r in cloud_monitoring.parse(data, "responses", "UTC")}
    assert rows["cloud_monitoring.responses5xx", ""] == 3
    assert rows["cloud_monitoring.responses", "status=2xx"] == 97
