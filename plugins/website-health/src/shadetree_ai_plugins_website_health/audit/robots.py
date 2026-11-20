"""robots.txt parsing and Google-style matching (exact product token, longest rule wins).

Python's ``urllib.robotparser`` uses first-match semantics, which disagrees with Google's
longest-match, so the audit carries its own small matcher.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class Group:
    agents: list[str] = field(default_factory=list)
    rules: list[tuple[str, str]] = field(default_factory=list)  # ("allow"|"disallow", path)


@dataclass
class Robots:
    groups: list[Group] = field(default_factory=list)
    sitemaps: list[str] = field(default_factory=list)
    signals: dict[str, str] = field(default_factory=dict)  # Content-Signal: ai-train=no, ...


def parse(text: str) -> Robots:
    robots, group, in_rules = Robots(), None, False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if ":" not in line:
            continue
        key, value = (x.strip() for x in line.split(":", 1))
        key = key.lower()
        if key == "user-agent":
            if group is None or in_rules:
                group, in_rules = Group(), False
                robots.groups.append(group)
            group.agents.append(value.lower())
        elif key in ("allow", "disallow"):
            if group is None:
                continue
            in_rules = True
            group.rules.append((key, value))
        elif key == "sitemap":
            robots.sitemaps.append(value)
        elif key == "content-signal":
            for part in value.split(","):
                name, _, setting = part.partition("=")
                if name.strip():
                    robots.signals[name.strip().lower()] = setting.strip().lower()
    return robots


def _pattern(path: str) -> re.Pattern[str]:
    anchored = path.endswith("$")
    body = re.escape(path.removesuffix("$")).replace(r"\*", ".*")
    return re.compile("^" + body + ("$" if anchored else ""))


def _rules_for(robots: Robots, token: str) -> list[tuple[str, str]]:
    token = token.lower()
    specific = [g for g in robots.groups if token in g.agents]
    chosen = specific or [g for g in robots.groups if "*" in g.agents]
    return [rule for g in chosen for rule in g.rules]


def check(robots: Robots, token: str, path: str) -> tuple[bool, str | None]:
    """Return (allowed, deciding rule) for a crawler token and URL path."""
    best: tuple[int, bool, str] | None = None
    for kind, value in _rules_for(robots, token):
        if not value:
            continue  # an empty Disallow allows everything
        if _pattern(value).match(path):
            candidate = (len(value), kind == "allow", value)
            if best is None or candidate[:2] > best[:2]:
                best = candidate
    if best is None:
        return True, None
    return best[1], best[2]
