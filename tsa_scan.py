"""Filesystem sweeps: PEM bundles and keystores anywhere under a directory,
roots embedded in binaries, Electron apps, runtime versions and lockfiles.

Everything here only reads files; no interpreter found on disk is executed.
"""
from __future__ import annotations

import glob
import json
import mmap
import os
import plistlib
import re
import shutil
import subprocess
from pathlib import Path

import tsa_indicators as ind
import tsa_versions as ver

BUNDLE_NAMES = {
    "cacert.pem", "cert.pem", "ca-bundle.crt", "ca-bundle.pem", "ca-certificates.crt",
    "cacerts.pem", "tls-ca-bundle.pem", "roots.pem", "ca-root-nss.crt", "curl-ca-bundle.crt",
}
KEYSTORE_NAMES = {"cacerts", "cacerts.jks", "truststore.jks", "cacerts.p12"}
BIG_BUNDLE_BYTES = 20_000  # any .pem/.crt at least this large is probably a CA bundle
MAX_TEXT_BYTES = 20_000_000
SKIP_DIRS = {".git", ".hg", ".svn", "__pycache__", ".Trash"}
DIST_INFO_RE = re.compile(r"^(pip|certifi)-([0-9][^-]*)\.dist-info$")
ELECTRON_FRAMEWORK = "Contents/Frameworks/Electron Framework.framework"
ELECTRON_BINARY = "Versions/A/Electron Framework"
ELECTRON_PLIST = "Resources/Info.plist"
APP_DIRS = ("/Applications", "~/Applications")
CLI_TOOLS = {  # tool -> (version args, embeds its own roots?)
    "node": (["--version"], True),
    "uv": (["--version"], True),
    "go": (["version"], False),
    "rustup": (["--version"], True),
    "bun": (["--version"], True),
    "deno": (["--version"], True),
}
NODE_VERSION_GLOBS = (
    "~/.nvm/versions/node/v*/bin/node",
    "~/.local/share/fnm/node-versions/v*/installation/bin/node",
    "~/.volta/tools/image/node/*/bin/node",
    "~/.asdf/installs/nodejs/*/bin/node",
    "/opt/homebrew/Cellar/node*/*/bin/node",
    "/usr/local/Cellar/node*/*/bin/node",
)
LOCKFILE_NAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock",
    "uv.lock", "poetry.lock", "Pipfile.lock", "Cargo.lock", "go.mod",
}
LOCK_SKIP_DIRS = SKIP_DIRS | {"node_modules", ".venv", "venv", "site-packages", "target", "dist", "build"}
TOML_PKG_RE = r'name = "{name}"\nversion = "([^"]+)"'
LOCK_PATTERNS = {  # lockfile -> [(package, regex with one version group)]
    "pnpm-lock.yaml": [("electron", r"(?m)^\s+/?electron@(\d+\.\d+\.\d+)[(:]")],
    "yarn.lock": [("electron", r'(?m)^"?electron@[^\n]*:\n\s+version:? "?(\d+\.\d+\.\d+)')],
    "bun.lock": [("electron", r'"electron@(\d+\.\d+\.\d+)"')],
    "uv.lock": [("certifi", TOML_PKG_RE.format(name="certifi"))],
    "poetry.lock": [("certifi", TOML_PKG_RE.format(name="certifi"))],
    "Cargo.lock": [(n, TOML_PKG_RE.format(name=n))
                   for n in ("rustls-webpki", "webpki-roots", "webpki-root-certs")],
    "go.mod": [("go", r"(?m)^toolchain go(\d+\.\d+(?:\.\d+)?)"), ("go", r"(?m)^go (\d+\.\d+\.\d+)")],
}
REQUIREMENTS_RE = re.compile(r"(?mi)^certifi\s*==\s*([0-9][\w.]*)")
DOCKER_FROM_RE = re.compile(r"(?mi)^FROM\s+(\S+)")
CHUNK = 64 * 1024 * 1024


def result(name, kind, location, version, status, found=(), note="", total="-"):
    return {"store": name, "kind": kind, "location": str(location), "version": version,
            "total": total, "status": status, "found": list(found), "note": note}


# --------------------------------------------------------------- binary scan
def scan_binary(path: Path, patterns: list[tuple[bytes, str]]) -> list[str] | None:
    """Labels of every indicator whose bytes occur in the file; None if unreadable."""
    try:
        with open(path, "rb") as fh:
            if os.fstat(fh.fileno()).st_size == 0:
                return []
            with mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                return sorted({label for pat, label in patterns if mm.find(pat) != -1})
    except (OSError, ValueError):
        return None


def found_entries(labels):
    return [{"sha256": "embedded", "label": label} for label in labels]


# ------------------------------------------------------------ bundle sweeps
def is_bundle_candidate(entry: os.DirEntry) -> str | None:
    """'pem' for a PEM bundle, 'keystore' for a binary keystore, else None."""
    name = entry.name
    if name in KEYSTORE_NAMES:
        return "keystore"
    if name in BUNDLE_NAMES:
        return "pem"
    if not name.endswith((".pem", ".crt")):
        return None
    try:
        return "pem" if entry.stat(follow_symlinks=False).st_size >= BIG_BUNDLE_BYTES else None
    except OSError:
        return None


def walk(root: Path, skip: set[str]):
    """Yield DirEntry for every regular file under root without following symlinks."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError:
            continue
        with it:
            for e in it:
                if e.is_dir(follow_symlinks=False):
                    if e.name not in skip:
                        stack.append(Path(e.path))
                    continue
                if e.is_file(follow_symlinks=False):
                    yield e


def audit_pem_bundle(path: Path, lookup: dict[str, str]):
    try:
        if path.stat().st_size > MAX_TEXT_BYTES:
            return None
        text = path.read_text(errors="replace")
    except OSError:
        return None
    blocks = ind.pem_blocks_re().findall(text)
    if not blocks:
        return None
    found = []
    for b in blocks:
        der = ind.der_from_pem(b)
        if not der:
            continue
        hit = ind.first_match(ind.cert_keys(der), lookup)
        if hit:
            found.append({"sha256": hit, "label": lookup[hit]})
    status = "PRESENT" if found else "absent"
    return result("pem-bundle", "pem-file", path, "", status, found, total=len(blocks))


def sweep_dir(root: Path, lookup, patterns, rules) -> list[dict]:
    """Every CA bundle, keystore and pip/certifi install under root."""
    out = []
    for e in walk(root, SKIP_DIRS):
        path = Path(e.path)
        kind = is_bundle_candidate(e)
        if kind == "pem":
            r = audit_pem_bundle(path, lookup)
            if r:
                out.append(r)
        elif kind == "keystore":
            labels = scan_binary(path, patterns)
            if labels is not None:
                out.append(result("keystore", "keystore", path, "",
                                  "PRESENT" if labels else "absent", found_entries(labels)))
    out.extend(sweep_dist_info(root, rules))
    return out


def sweep_dist_info(root: Path, rules) -> list[dict]:
    """pip and certifi versions from *.dist-info folder names (every venv)."""
    out = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError:
            continue
        with it:
            for e in it:
                if not e.is_dir(follow_symlinks=False) or e.name in SKIP_DIRS:
                    continue
                m = DIST_INFO_RE.match(e.name)
                if not m:
                    stack.append(Path(e.path))
                    continue
                status, why = ver.check(rules, m.group(1), m.group(2))
                out.append(result(f"{m.group(1)} install", "package", Path(e.path).parent,
                                  f"{m.group(1)} {m.group(2)}", status, note=why))
    return out


# ------------------------------------------------------------ Electron apps
def electron_apps() -> list[Path]:
    apps = []
    for d in APP_DIRS:
        for app in sorted(Path(d).expanduser().glob("*.app")):
            if (app / ELECTRON_FRAMEWORK).is_dir():
                apps.append(app)
    return apps


def electron_version(app: Path) -> str | None:
    plist = app / ELECTRON_FRAMEWORK / ELECTRON_PLIST
    try:
        with open(plist, "rb") as fh:
            return plistlib.load(fh).get("CFBundleVersion")
    except (OSError, plistlib.InvalidFileException):
        return None


def audit_electron(app: Path, patterns, rules) -> dict:
    version = electron_version(app)
    if not version:
        return result(app.name, "electron", app, "", "skipped", note="no Electron version found")
    status, why = ver.check(rules, "electron", version)
    labels = scan_binary(app / ELECTRON_FRAMEWORK / ELECTRON_BINARY, patterns) or []
    note = why
    if labels:
        note += "; roots embedded in the binary (expected even when patched: the fix is a blocklist)"
    return result(app.name, "electron", app, f"electron {version}", status,
                  found_entries(labels) if status == ver.OUTDATED else [], note)


# -------------------------------------------------------------- CLI runtimes
def tool_version(exe: str, args: list[str]) -> str | None:
    try:
        r = subprocess.run([exe, *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r"(\d+\.\d+(?:\.\d+)?)", r.stdout + r.stderr)
    return m.group(1) if m else None


def audit_cli_tools(patterns, rules) -> list[dict]:
    out = []
    for tool, (args, embeds) in CLI_TOOLS.items():
        exe = shutil.which(tool)
        if not exe:
            continue
        version = tool_version(exe, args) or "unknown"
        status, why = ver.check(rules, tool, version)
        labels = scan_binary(Path(os.path.realpath(exe)), patterns) if embeds else []
        if status == ver.UNKNOWN and labels:
            status, why = "PRESENT", "roots embedded and no patched-version rule"
        out.append(result(tool, "runtime", exe, f"{tool} {version}", status,
                          found_entries(labels or []), why))
    return out


def audit_node_installs(rules) -> list[dict]:
    """Node versions installed by nvm, fnm, volta, asdf and Homebrew (from paths)."""
    out = []
    for pattern in NODE_VERSION_GLOBS:
        for exe in sorted(glob.glob(os.path.expanduser(pattern))):
            m = re.search(r"/v?(\d+\.\d+\.\d+)[^/]*/(?:installation/)?bin/node$", exe)
            if not m:
                continue
            status, why = ver.check(rules, "node", m.group(1))
            out.append(result("node install", "runtime", exe, f"node {m.group(1)}", status, note=why))
    return out


# ---------------------------------------------------------------- lockfiles
def lock_versions(path: Path, text: str) -> list[tuple[str, str]]:
    name = path.name
    if name in ("package-lock.json", "npm-shrinkwrap.json"):
        return npm_lock_versions(text)
    if name.startswith("requirements") and name.endswith(".txt"):
        return [("certifi", v) for v in REQUIREMENTS_RE.findall(text)]
    if name == "Pipfile.lock":
        return pipfile_versions(text)
    found = []
    for package, regex in LOCK_PATTERNS.get(name, []):
        found += [(package, v) for v in re.findall(regex, text)]
    return found


def npm_lock_versions(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    pkgs = data.get("packages") or {}
    return [("electron", meta["version"]) for key, meta in pkgs.items()
            if key.endswith("node_modules/electron") and isinstance(meta, dict) and "version" in meta]


def pipfile_versions(text: str) -> list[tuple[str, str]]:
    try:
        data = json.loads(text)
    except ValueError:
        return []
    out = []
    for section in ("default", "develop"):
        spec = (data.get(section) or {}).get("certifi", {}).get("version", "")
        if spec.startswith("=="):
            out.append(("certifi", spec[2:]))
    return out


def is_lockfile(name: str) -> bool:
    return name in LOCKFILE_NAMES or (name.startswith("requirements") and name.endswith(".txt"))


def sweep_lockfiles(root: Path, rules) -> list[dict]:
    out = []
    for e in walk(root, LOCK_SKIP_DIRS):
        path = Path(e.path)
        if path.name.startswith("Dockerfile"):
            out.extend(dockerfile_results(path))
            continue
        if not is_lockfile(path.name):
            continue
        try:
            text = path.read_text(errors="replace")
        except OSError:
            continue
        for package, version in sorted(set(lock_versions(path, text))):
            status, why = ver.check(rules, package, version)
            out.append(result(f"lockfile {package}", "lockfile", path, f"{package} {version}", status, note=why))
    return out


def dockerfile_results(path: Path) -> list[dict]:
    try:
        images = DOCKER_FROM_RE.findall(path.read_text(errors="replace"))
    except OSError:
        return []
    if not images:
        return []
    return [result("dockerfile", "docker", path, ", ".join(images), "REBUILD",
                   note="images built before 2026-10-20 carry the old trust store; rebuild and redeploy")]
