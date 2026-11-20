"""Rank GitHub deploys, workflow runs, merged PRs and commits preceding an anomaly.

Port of correlate-window.mjs. Uses the ``gh`` CLI (its own keychain auth). The
look-back window widens with the detecting source's lag: a GSC drop on day D
can be caused by a deploy days earlier, a probe failure only by a recent one.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from datetime import datetime, timedelta

from .. import dates

GH_TIMEOUT = 30
# Extra hours of look-back per source, on top of correlation.windowHours.
SOURCE_LAG_HOURS = {"probe": 0, "clarity": 24, "ga4": 24, "firebase_auth": 0,
                    "cloud_monitoring": 0, "gsc": 72, "bing": 72, "crux": 24 * 28}


class GhError(RuntimeError):
    pass


def gh_json(args: list[str]):
    if not shutil.which("gh"):
        raise GhError("'gh' is not on PATH. Install GitHub CLI and run 'gh auth login'.")
    try:
        out = subprocess.run(["gh", *args], capture_output=True, text=True, timeout=GH_TIMEOUT,
                             check=False)
    except subprocess.TimeoutExpired:
        raise GhError(f"gh {' '.join(args[:2])} timed out") from None
    if out.returncode != 0:
        raise GhError(f"gh {' '.join(args[:2])} failed: {out.stderr.strip()[:300]}")
    try:
        return json.loads(out.stdout or "null")
    except ValueError:
        raise GhError(f"gh {' '.join(args[:2])} returned invalid JSON") from None


def _parse(ts: str | None) -> datetime | None:
    return datetime.fromisoformat(ts.replace("Z", "+00:00")) if ts else None


def window(site: dict, day: str, source: str | None) -> tuple[datetime, datetime, datetime]:
    corr = site["correlation"]
    start_utc, end_utc = dates.day_bounds_utc(day, site["timezone"])
    lag = SOURCE_LAG_HOURS.get(source or "", 0)
    return (start_utc - timedelta(hours=corr["windowHours"] + lag),
            end_utc + timedelta(hours=corr["bufferHours"]), start_utc)


def candidates_for(repo: str, frm: datetime, to: datetime, anchor: datetime,
                   warnings: list[str]) -> list[dict]:
    out = []

    def add(kind, at, **fields):
        moment = _parse(at)
        if moment and frm <= moment <= to:
            out.append({"type": kind, "repo": repo, "at": at,
                        "hoursBeforeAnomaly": round((anchor - moment).total_seconds() / 3600, 1),
                        **fields})

    try:
        deps = gh_json(["api", f"repos/{repo}/deployments?per_page=100"]) or []
        prod = [d for d in deps if d.get("environment") in ("production", "Production")] or deps
        for d in prod:
            add("deployment", d.get("created_at"), sha=d.get("sha"),
                title=d.get("description") or d.get("environment"),
                author=(d.get("creator") or {}).get("login"))
    except GhError as exc:
        warnings.append(f"{repo} deployments: {exc}")
    try:
        runs = gh_json(["run", "list", "--repo", repo, "--status", "success", "--json",
                        "workflowName,createdAt,headSha,headBranch,event", "--limit", "50"]) or []
        for r in runs:
            add("workflow_run", r.get("createdAt"), sha=r.get("headSha"),
                title=r.get("workflowName"), branch=r.get("headBranch"))
    except GhError as exc:
        warnings.append(f"{repo} workflow runs: {exc}")
    try:
        prs = gh_json(["pr", "list", "--repo", repo, "--state", "merged", "--search",
                       f"merged:{frm.date().isoformat()}..{to.date().isoformat()}", "--json",
                       "number,title,mergedAt,mergeCommit,author,files", "--limit", "50"]) or []
        for pr in prs:
            add("pr", pr.get("mergedAt"), number=pr.get("number"), title=pr.get("title"),
                sha=(pr.get("mergeCommit") or {}).get("oid"),
                author=(pr.get("author") or {}).get("login"),
                files=[f.get("path") for f in pr.get("files") or []][:50])
    except GhError as exc:
        warnings.append(f"{repo} merged PRs: {exc}")
    try:
        commits = gh_json(["api", f"repos/{repo}/commits?since={frm.isoformat()}"
                           f"&until={to.isoformat()}&per_page=100"]) or []
        for c in commits:
            commit = c.get("commit") or {}
            add("commit", (commit.get("committer") or commit.get("author") or {}).get("date"),
                sha=c.get("sha"), title=(commit.get("message") or "").split("\n", 1)[0],
                author=(c.get("author") or {}).get("login"))
    except GhError as exc:
        warnings.append(f"{repo} commits: {exc}")
    return out


def correlate(site: dict, day: str, source: str | None = None,
              repos: list[str] | None = None) -> dict:
    repos = repos or site.get("githubRepos") or []
    if not repos:
        return {"ok": False, "error": "no_repos",
                "detail": "Set githubRepos with configure_site."}
    frm, to, anchor = window(site, day, source)
    warnings: list[str] = []
    found = []
    for repo in repos:
        found += candidates_for(repo, frm, to, anchor, warnings)
    rank = {"deployment": 0, "workflow_run": 1, "pr": 2, "commit": 3}
    found.sort(key=lambda c: (c["hoursBeforeAnomaly"] < 0, abs(c["hoursBeforeAnomaly"]),
                              rank[c["type"]]))
    return {"ok": True, "day": day, "source": source, "window": {
        "from": frm.isoformat(), "to": to.isoformat()}, "candidates": found[:40],
        "warnings": warnings,
        "nextSteps": "Inspect diffs: gh api repos/{repo}/commits/{sha} or gh pr diff {n}."}
