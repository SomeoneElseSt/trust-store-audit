"""Compare installed or locked versions against the patched-versions table."""
from __future__ import annotations

import json
import re
from pathlib import Path

OUTDATED = "OUTDATED"
OK = "ok"
UNKNOWN = "unknown"


def parse(version: str) -> tuple[int, ...] | None:
    m = re.match(r"v?(\d+(?:\.\d+)*)", version.strip())
    if not m:
        return None
    return tuple(int(p) for p in m.group(1).split("."))


def load_rules(path: str) -> dict:
    return json.loads(Path(path).read_text())["packages"]


def line_key(rule: dict, v: tuple[int, ...]) -> str:
    if rule["line"] == "major":
        return str(v[0])
    if rule["line"] == "minor":
        return ".".join(str(p) for p in v[:2])
    return "*"


def check(rules: dict, package: str, version: str) -> tuple[str, str]:
    """Return (status, explanation)."""
    rule = rules.get(package)
    v = parse(version)
    if not rule or not v:
        return UNKNOWN, f"no rule or unparsable version {version!r}"
    if rule.get("pending"):
        return OUTDATED, "no fixed release yet (pending upstream); avoid for untrusted HTTPS"
    mins = rule["min"]
    key = line_key(rule, v)
    if key in mins:
        need = parse(mins[key])
        if v >= need:
            return OK, f">= {mins[key]}"
        return OUTDATED, f"needs >= {mins[key]}"
    newest_line = max(parse(k) for k in mins)
    if parse(key) > newest_line:
        return OK, "newer than every listed release line"
    return OUTDATED, f"release line {key} has no fix; upgrade to a patched line ({', '.join(mins.values())})"
