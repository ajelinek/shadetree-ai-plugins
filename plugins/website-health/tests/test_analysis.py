from datetime import date, timedelta

from shadetree_ai_plugins_website_health.analysis import anomalies, correlate
from shadetree_ai_plugins_website_health.store import Flag, Row


def _days(n, end=date(2026, 3, 1)):
    return [(end - timedelta(days=n - 1 - i)).isoformat() for i in range(n)]


def test_regression_detected_on_latest_final_day_not_provisional(store, site):
    days = _days(31)
    values = [100 + (i % 3) for i in range(29)] + [40, 5]
    store.upsert("prod", [Row("ga4.sessions", d, v, provisional=(i == 30))
                          for i, (d, v) in enumerate(zip(days, values))])
    store.upsert("prod", [Row("ga4.sessions", days[29], 10, dim="page=/pricing"),
                          Row("ga4.sessions", days[28], 60, dim="page=/pricing")])
    store.add_flags("prod", [Flag("ga4", days[29], "thresholded")])
    result = anomalies.detect(store, site)
    a = next(x for x in result["anomalies"] if x["metric"] == "ga4.sessions")
    assert a["period"] == days[29]  # provisional last day ignored
    assert a["direction"] == "regression" and a["severityDraft"] == "critical"
    assert a["qualityFlags"][0]["flag"] == "thresholded"
    assert a["topContributors"][0]["dim"] == "page=/pricing"


def test_position_increase_is_a_regression(store, site):
    days = _days(20)
    store.upsert("prod", [Row("gsc.position", d, 5.0 + (0.1 if i % 2 else 0))
                          for i, d in enumerate(days[:-1])] + [Row("gsc.position", days[-1], 14)])
    a = next(x for x in anomalies.detect(store, site)["anomalies"]
             if x["metric"] == "gsc.position")
    assert a["direction"] == "regression"


def test_weekly_and_rolling_grains_use_own_minimums(store, site):
    store.upsert("prod", [Row("crux.lcpP75", d, 2000, grain="week") for d in _days(2)])
    skipped = {s["metric"]: s["reason"] for s in anomalies.detect(store, site)["skipped"]}
    assert "week" in skipped["crux.lcpP75"]


def test_correlate_window_widens_for_lagging_sources(site):
    frm_probe, _, anchor = correlate.window(site, "2026-03-01", "probe")
    frm_gsc, _, _ = correlate.window(site, "2026-03-01", "gsc")
    assert (anchor - frm_probe).total_seconds() / 3600 == 48
    assert (anchor - frm_gsc).total_seconds() / 3600 == 120


def test_correlate_ranks_candidates(monkeypatch, site):
    def fake(args):
        if args[0] == "api" and "deployments" in args[1]:
            return [{"environment": "production", "created_at": "2026-02-28T20:00:00Z",
                     "sha": "abc", "creator": {"login": "dev"}}]
        if args[0] == "api":
            return [{"sha": "def", "commit": {"message": "tweak\nbody",
                                              "committer": {"date": "2026-02-27T10:00:00Z"}}}]
        return []

    monkeypatch.setattr(correlate, "gh_json", fake)
    out = correlate.correlate(site, "2026-03-01")
    assert [c["type"] for c in out["candidates"]] == ["deployment", "commit"]
    assert out["candidates"][0]["hoursBeforeAnomaly"] == 4.0
