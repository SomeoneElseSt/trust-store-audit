#!/usr/bin/env python3
"""Electron patch status for every app in /Applications and ~/Applications.

For each Electron app: the installed Electron version against the patched
versions table, and any update already downloaded but not yet installed
(Squirrel/ShipIt staging or electron-updater pending zips), read in place.
Read-only. Meant for: watch -n 300 python3 -I tools/electron_status.py
"""
from __future__ import annotations

import json
import plistlib
import re
import sys
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))
import tsa_scan  # noqa: E402
import tsa_versions as ver  # noqa: E402

CACHES = Path.home() / "Library" / "Caches"
FRAMEWORK_PLIST = "Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"
ZIP_PLIST_RE = re.compile(r"[^/]+\.app/Contents/Frameworks/Electron Framework\.framework/"
                          r"(?:Versions/A/)?Resources/Info\.plist$")
ZIP_APP_PLIST_RE = re.compile(r"^[^/]+\.app/Contents/Info\.plist$")
UPDATER_DIR_RE = re.compile(r"^updaterCacheDirName:\s*['\"]?([^'\"\n]+)", re.M)
STATUS_LABEL = {ver.OK: "patched", ver.OUTDATED: "VULNERABLE", ver.UNKNOWN: "unknown"}


def plist_value(data: bytes, key: str) -> str | None:
    try:
        return plistlib.loads(data).get(key)
    except (plistlib.InvalidFileException, ValueError):
        return None


def app_info(app: Path, key: str) -> str | None:
    try:
        return plist_value((app / "Contents/Info.plist").read_bytes(), key)
    except OSError:
        return None


def shipit_staged(app: Path) -> tuple[str, str] | None:
    """(app version, Electron version) of an update Squirrel has staged."""
    bid = app_info(app, "CFBundleIdentifier")
    state = CACHES / f"{bid}.ShipIt" / "ShipItState.plist"
    if not bid or not state.is_file():
        return None
    url = plist_value(state.read_bytes(), "updateBundleURL")
    if not url:
        return None
    staged = Path(unquote(urlparse(url).path))
    electron = None
    try:
        electron = plist_value((staged / FRAMEWORK_PLIST).read_bytes(), "CFBundleVersion")
    except OSError:
        return None
    version = app_info(staged, "CFBundleShortVersionString")
    return (version, electron) if version and electron else None


def updater_cache_dir(app: Path) -> Path | None:
    cfg = app / "Contents/Resources/app-update.yml"
    try:
        m = UPDATER_DIR_RE.search(cfg.read_text())
    except OSError:
        return None
    return CACHES / m.group(1).strip() if m else None


def pending_zip_version(zpath: Path) -> tuple[str, str] | None:
    """(app version, Electron version) read from the zip without extracting."""
    try:
        with zipfile.ZipFile(zpath) as z:
            names = z.namelist()
            fw = next((n for n in names if ZIP_PLIST_RE.search(n)), None)
            info = next((n for n in names if ZIP_APP_PLIST_RE.search(n)), None)
            if not fw or not info:
                return None
            electron = plist_value(z.read(fw), "CFBundleVersion")
            version = plist_value(z.read(info), "CFBundleShortVersionString")
    except (OSError, zipfile.BadZipFile, KeyError):
        return None
    return (version, electron) if version and electron else None


def updater_staged(app: Path) -> tuple[str, str] | None:
    """(app version, Electron version) of an electron-updater zip in pending/."""
    cache = updater_cache_dir(app)
    pending = cache / "pending" if cache else None
    if not pending or not pending.is_dir():
        return None
    zips = sorted(pending.glob("*.zip"), key=lambda p: p.stat().st_mtime, reverse=True)
    return pending_zip_version(zips[0]) if zips else None


def staged_note(rules: dict, app_version: str | None, electron: str,
                staged: tuple[str, str] | None) -> str:
    """Describe a downloaded-but-not-installed update; '' if none or a leftover."""
    if not staged or staged[0] == app_version:
        return ""
    new_app, new_electron = staged
    status, _ = ver.check(rules, "electron", new_electron)
    if new_electron == electron:
        return f"update {new_app} downloaded, same Electron (no fix yet)"
    return f"update {new_app} downloaded: Electron {new_electron} ({STATUS_LABEL[status]}), restart the app"


def main() -> int:
    rules = ver.load_rules(str(HERE / "presets" / "emudhra-2026-patched.json"))
    rows = []
    for app in tsa_scan.electron_apps():
        installed = tsa_scan.electron_version(app) or "?"
        status, why = ver.check(rules, "electron", installed)
        staged = shipit_staged(app) or updater_staged(app)
        app_version = app_info(app, "CFBundleShortVersionString")
        note = staged_note(rules, app_version, installed, staged) or ("" if status == ver.OK else why + " (vendor must ship it)")
        rows.append((status != ver.OK, app.stem, installed, STATUS_LABEL[status], note))
    rows.sort(key=lambda r: (not r[0], r[1].lower()))
    print(f"Electron patch status  {datetime.now():%Y-%m-%d %H:%M}   "
          f"(need 42.11.16+ / 43.8.1+ / 44.9.1+)\n")
    print(f"{'APP':22} {'ELECTRON':10} {'STATUS':11} NOTE")
    for _, name, installed, label, note in rows:
        print(f"{name[:22]:22} {installed:10} {label:11} {note}")
    bad = sum(1 for r in rows if r[0])
    print(f"\n{len(rows) - bad} patched, {bad} vulnerable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
