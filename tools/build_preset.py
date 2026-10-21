#!/usr/bin/env python3
"""Build presets/emudhra-2026.json from the incident site's published data
(github.com/galadran/we-have-a-problem.com: impacted-intermediates.json and
roots.json). Every entry is re-derived from its PEM and checked against the
published SHA-256 and SPKI SHA-256; any mismatch aborts.

    python3 tools/build_preset.py presets/sources presets/emudhra-2026.json
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import tsa_indicators as ind  # noqa: E402

EXPECTED_INTERMEDIATES = 16
EXPECTED_ROOTS = 4


def entry(raw: dict, kind: str) -> dict | None:
    der = ind.der_from_pem(raw["pem"])
    if not der:
        print(f"bad PEM: {raw['name']}", file=sys.stderr)
        return None
    spki = ind.spki_der(der)
    sha = hashlib.sha256(der).hexdigest().upper()
    spki_sha = hashlib.sha256(spki).hexdigest().upper() if spki else ""
    if sha != raw["sha256"].upper() or spki_sha != raw["spki_sha256"].upper():
        print(f"hash mismatch: {raw['name']}", file=sys.stderr)
        return None
    return {"name": raw["name"], "kind": kind, "subject": raw["subject"],
            "sha256": sha, "spki_sha256": spki_sha, "pem": raw["pem"]}


def main() -> int:
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    intermediates = json.loads((src / "impacted-intermediates.json").read_text())
    roots = json.loads((src / "roots.json").read_text())
    if len(intermediates) != EXPECTED_INTERMEDIATES or len(roots) != EXPECTED_ROOTS:
        print("unexpected entry counts", file=sys.stderr)
        return 2
    built = [entry(r, "intermediate") for r in intermediates]
    built += [entry(r, "root") for r in roots]
    if any(e is None for e in built):
        return 2
    # Cross-signed copies share a key with their emSign twin; label them apart.
    for e, raw in zip(built, intermediates + roots):
        if raw.get("issued_by") == "AAA Certificate Services":
            e["name"] += " (AAA cross-sign)"
    sources = {f: hashlib.sha256((src / f).read_bytes()).hexdigest()
               for f in ("impacted-intermediates.json", "roots.json")}
    out.write_text(json.dumps({"source": "https://github.com/galadran/we-have-a-problem.com",
                               "source_sha256": sources, "certificates": built}, indent=1) + "\n")
    print(f"wrote {len(built)} certificates to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
