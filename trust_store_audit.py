#!/usr/bin/env python3
"""trust-store-audit: find (and optionally remove) distrusted root CAs by SHA-256
fingerprint across the trust stores on a Linux or macOS machine.

Python standard library only. Dry run by default; nothing is changed without
--apply, and sudo is only ever used with --apply.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path

# Works under `python3 -I` (isolated mode), which drops the script directory.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import tsa_indicators as ind  # noqa: E402
import tsa_scan  # noqa: E402
import tsa_sites  # noqa: E402
import tsa_versions  # noqa: E402

__version__ = "0.2.0"

PEM_RE = re.compile(
    r"-----BEGIN CERTIFICATE-----\s.*?-----END CERTIFICATE-----\n?", re.S
)
HEX64 = re.compile(r"^[0-9A-F]{64}$")
HERE = Path(__file__).resolve().parent

DEBIAN_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
MACOS_CERT_PEM = "/etc/ssl/cert.pem"
MACOS_ROOTS_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"
PEM_BEGIN = "-----BEGIN CERTIFICATE-----"
PEM_END = "-----END CERTIFICATE-----"
ENTRY_HEADER = "=== "  # macOS /etc/ssl/cert.pem entry header
GROUP_HEADER = "### "  # macOS /etc/ssl/cert.pem organization header
PROBLEM_STATUSES = {"PRESENT", tsa_versions.OUTDATED}
QUIET_STATUSES = {"absent", tsa_versions.OK, "REBUILD"}

NODE_GUIDANCE = """\
Node.js ships its own copy of the Mozilla roots inside the binary, so removing a
root from the system store does not affect Node. Until your Node release drops
the root, tell Node to use the (patched) system store instead:

    NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-openssl-ca"   # e.g. in ~/.profile
    export NODE_OPTIONS

or source contrib/node-use-openssl-ca.sh, which appends the flag only once.
--use-openssl-ca reads the default CA file of the OpenSSL that Node was built
with, which is NOT always the system store. Homebrew's Node reads
$(brew --prefix)/etc/openssl@3/cert.pem (Homebrew's ca-certificates; patched
from 2026-09-25_1), not /etc/ssl/cert.pem. Other builds use their own compiled-in
OpenSSL directory. To pin it, also set SSL_CERT_FILE to a patched bundle.
Note: tls.rootCertificates always lists the bundled roots, even with the flag,
so the audit keeps reporting Node as PRESENT. Verify the flag with a live test
instead: trust-store-audit audit --live (compare "node bundled" with
"node --use-openssl-ca")."""


# --------------------------------------------------------------------- parsing
def normalize_fp(text: str) -> str:
    fp = re.sub(r"[\s:]", "", text).upper()
    if not HEX64.match(fp):
        raise ValueError(f"not a SHA-256 fingerprint: {text!r}")
    return fp


def load_fingerprints(path: str) -> dict[str, str]:
    """Read a JSON preset (certificate and key hashes) or a text file of
    'FINGERPRINT  optional label' lines; '#' starts a comment line."""
    if str(path).endswith(".json"):
        return ind.load_preset_json(path)[0]
    out: dict[str, str] = {}
    for n, raw in enumerate(Path(path).read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        try:
            fp = normalize_fp(parts[0])
        except ValueError as exc:
            print(f"{path}:{n}: {exc}", file=sys.stderr)
            raise SystemExit(2)
        out[fp] = parts[1].strip() if len(parts) > 1 else ""
    if not out:
        print(f"{path}: no fingerprints found", file=sys.stderr)
        raise SystemExit(2)
    return out


def load_hosts(path: str) -> list[str]:
    hosts = []
    for raw in Path(path).read_text().splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            hosts.append(line)
    return hosts


def pem_blocks(text: str) -> list[str]:
    return PEM_RE.findall(text)


def pem_fp(block: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(block.strip())
    return hashlib.sha256(der).hexdigest().upper()


def fps_from_pem_text(text: str) -> list[str]:
    fps = []
    for b in pem_blocks(text):
        try:
            fps.append(pem_fp(b))
        except ValueError:
            continue
    return fps


def keys_from_pem_text(text: str) -> list[list[str]]:
    """Per certificate: [cert SHA-256, SPKI key] for matching by cert or by key."""
    out = []
    for b in pem_blocks(text):
        der = ind.der_from_pem(b)
        if der:
            out.append(ind.cert_keys(der))
    return out


def block_hit(block: str, bad: dict[str, str]) -> str | None:
    der = ind.der_from_pem(block)
    return ind.first_match(ind.cert_keys(der), bad) if der else None


def run(cmd: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


# ---------------------------------------------------------------------- stores
def store_result(name, kind, location, version, certs, bad, note=""):
    """certs: one list of lookup keys per certificate (see keys_from_pem_text)."""
    hits = (ind.first_match(keys, bad) for keys in certs)
    found = sorted({h for h in hits if h})
    return {
        "store": name,
        "kind": kind,
        "location": location,
        "version": version,
        "total": len(certs),
        "status": "PRESENT" if found else "absent",
        "found": [{"sha256": fp, "label": bad[fp]} for fp in found],
        "note": note,
    }


def skipped(name, why):
    return {"store": name, "status": "skipped", "note": why, "found": []}


def audit_pem_file(name, path, version, bad, kind="pem-file"):
    p = Path(path)
    if not p.is_file():
        return skipped(name, f"{path} not found")
    try:
        text = p.read_text(errors="replace")
    except OSError as exc:
        return skipped(name, f"cannot read {path}: {exc.strerror}")
    return store_result(name, kind, path, version, keys_from_pem_text(text), bad)


def debian_version():
    if shutil.which("dpkg-query"):
        r = run(["dpkg-query", "-W", "-f=${Version}", "ca-certificates"])
        if r.returncode == 0 and r.stdout.strip():
            return "ca-certificates " + r.stdout.strip()
    return "unknown"


def macos_version():
    if shutil.which("sw_vers"):
        r = run(["sw_vers", "-productVersion"])
        if r.returncode == 0:
            return "macOS " + r.stdout.strip()
    return "unknown"


def audit_keychain(bad, keychain=MACOS_ROOTS_KEYCHAIN):
    name = "macos-system-roots-keychain"
    if not shutil.which("security") or not Path(keychain).exists():
        return skipped(name, "macOS security tool or keychain not found")
    r = run(["security", "find-certificate", "-a", "-p", keychain])
    if r.returncode != 0:
        return skipped(name, "security find-certificate failed")
    res = store_result(name, "keychain", keychain, macos_version(),
                       keys_from_pem_text(r.stdout), bad,
                       note="read-only; Apple manages this keychain (fix via OS update)")
    return res


def audit_certifi(bad, pythons):
    results = []
    code = "import certifi,sys;print(certifi.where());print(certifi.__version__)"
    seen = set()
    for py in pythons:
        exe = shutil.which(py) or (py if Path(py).is_file() else None)
        name = f"certifi ({py})"
        if not exe:
            results.append(skipped(name, f"{py} not found"))
            continue
        try:
            r = run([exe, "-c", code])
        except (OSError, subprocess.TimeoutExpired):
            results.append(skipped(name, "could not run interpreter"))
            continue
        if r.returncode != 0:
            results.append(skipped(name, "certifi not installed"))
            continue
        where, ver = (r.stdout.strip().splitlines() + ["", ""])[:2]
        if where in seen:
            continue
        seen.add(where)
        results.append(audit_pem_file(name, where, "certifi " + ver, bad))
    return results


def audit_node(bad, node="node"):
    name = "node-bundled-roots"
    exe = shutil.which(node)
    if not exe:
        return skipped(name, "node not found")
    # fs.writeSync avoids truncated output when stdout is a pipe (node -p is async).
    cmd = [exe, "-e", "require('fs').writeSync(1, JSON.stringify("
           "{v:process.version,c:require('tls').rootCertificates}))"]
    # Run with a clean NODE_OPTIONS so the bundled store is what we measure.
    envv = {k: v for k, v in os.environ.items() if k != "NODE_OPTIONS"}
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=60, env=envv)
    if r.returncode != 0:
        return skipped(name, "node failed to print tls.rootCertificates")
    try:
        data = json.loads(r.stdout)
    except ValueError:
        return skipped(name, "node printed unexpected output")
    fps = keys_from_pem_text("\n".join(data["c"]))
    note = "compiled into the binary; see Node guidance"
    if "--use-openssl-ca" in os.environ.get("NODE_OPTIONS", ""):
        note += "; NODE_OPTIONS sets --use-openssl-ca in this shell"
    return store_result(name, "node", exe, "node " + data["v"], fps, bad, note)


def java_cacerts_candidates():
    cands = []
    jh = os.environ.get("JAVA_HOME")
    if jh:
        cands += [Path(jh, "lib/security/cacerts"), Path(jh, "jre/lib/security/cacerts")]
    java = shutil.which("java")
    if java:
        home = Path(os.path.realpath(java)).parent.parent
        cands += [home / "lib/security/cacerts", home / "jre/lib/security/cacerts"]
    cands.append(Path("/etc/ssl/certs/java/cacerts"))
    out = []
    for c in cands:
        if c.is_file() and c.resolve() not in [o.resolve() for o in out]:
            out.append(c)
    return out


def parse_keytool(text: str) -> list[str]:
    fps = []
    for m in re.finditer(r"SHA-?256\)?:\s*([0-9A-Fa-f:]{95})", text):
        fps.append(normalize_fp(m.group(1)))
    return fps


def audit_java(bad, storepass="changeit"):
    keytool = shutil.which("keytool")
    stores = java_cacerts_candidates()
    if not stores:
        return [skipped("java-cacerts", "no Java cacerts found")]
    if not keytool:
        return [skipped("java-cacerts", "keytool not found")]
    ver = "unknown"
    if shutil.which("java"):
        r = run(["java", "-version"])
        ver = (r.stderr.strip().splitlines() or ["unknown"])[0]
    out = []
    for s in stores:
        r = run([keytool, "-list", "-v", "-keystore", str(s), "-storepass", storepass])
        if r.returncode != 0:
            out.append(skipped(f"java-cacerts ({s})", "keytool -list failed"))
            continue
        fps = [[fp] for fp in parse_keytool(r.stdout)]
        out.append(store_result("java-cacerts", "java", str(s), ver, fps, bad,
                                note="fix: keytool -delete -alias <alias> (needs --apply by hand)"))
    return out


def audit_all(bad, args) -> list[dict]:
    results = []
    if args.bundle:
        for b in args.bundle:
            results.append(audit_pem_file(f"custom ({b})", b, "n/a", bad))
        if args.only_bundles:
            return results + sweep_extras(bad, args)
    results.append(audit_pem_file("debian-system-bundle", DEBIAN_BUNDLE, debian_version(), bad))
    results.append(audit_pem_file("macos-cert.pem", MACOS_CERT_PEM, macos_version(), bad))
    results.append(audit_keychain(bad))
    results.extend(audit_certifi(bad, args.python))
    results.append(audit_node(bad))
    results.extend(audit_java(bad))
    results.extend(sweep_extras(bad, args))
    return results


def sweep_extras(bad, args) -> list[dict]:
    """Optional sweeps: directories, binaries/apps, lockfiles, deployed sites."""
    if not (args.scan or args.projects or args.apps or args.site or args.ct):
        return []
    _, entries = ind.load_preset_json(args.preset_json)
    patterns = ind.binary_patterns(entries)
    rules = tsa_versions.load_rules(args.patched)
    out = []
    for d in (args.scan or []) + (args.projects or []):
        out.extend(tsa_scan.sweep_dir(Path(d).expanduser(), bad, patterns, rules))
    for d in args.projects or []:
        out.extend(tsa_scan.sweep_lockfiles(Path(d).expanduser(), rules))
    if args.apps:
        out.extend(tsa_scan.audit_electron(app, patterns, rules) for app in tsa_scan.electron_apps())
        out.extend(tsa_scan.audit_cli_tools(patterns, rules))
        out.extend(tsa_scan.audit_node_installs(rules))
    out.extend(tsa_sites.audit_site(s, bad) for s in args.site or [])
    out.extend(tsa_sites.audit_ct(s) for s in args.ct or [])
    for r in out:
        r["sweep"] = True
    return out


# ------------------------------------------------------------------------ live
def live_python(host: str, cafile: str | None, timeout=10) -> str:
    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host):
                return "ACCEPTED"
    except ssl.SSLCertVerificationError:
        return "rejected"
    except (OSError, ssl.SSLError) as exc:
        return f"error ({type(exc).__name__})"


def live_node(host: str, use_openssl_ca: bool, timeout=15) -> str:
    exe = shutil.which("node")
    if not exe:
        return "skipped"
    js = ("const t=require('tls');const s=t.connect({host:process.argv[1],port:443,"
          "servername:process.argv[1]},()=>{console.log('ACCEPTED');s.end()});"
          "s.on('error',e=>{console.log(/CERT|UNABLE|SELF_SIGNED|verify/i.test(e.code+e.message)"
          "?'rejected':'error ('+e.code+')')});s.setTimeout(10000,()=>{console.log('error (timeout)');s.destroy()})")
    cmd = [exe] + (["--use-openssl-ca"] if use_openssl_ca else []) + ["-e", js, host]
    envv = {k: v for k, v in os.environ.items() if k != "NODE_OPTIONS"}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=envv)
        return (r.stdout.strip().splitlines() or ["error"])[0]
    except subprocess.TimeoutExpired:
        return "error (timeout)"


def live_tests(hosts, results) -> list[dict]:
    clients = [("python default", lambda h: live_python(h, None))]
    for r in results:
        if r.get("kind") == "pem-file" and not r.get("sweep"):
            loc = r["location"]
            clients.append((f"python cafile={r['store']}", lambda h, loc=loc: live_python(h, loc)))
    if shutil.which("node"):
        clients.append(("node bundled", lambda h: live_node(h, False)))
        clients.append(("node --use-openssl-ca", lambda h: live_node(h, True)))
    rows = []
    for h in hosts:
        for cname, fn in clients:
            rows.append({"host": h, "client": cname, "result": fn(h)})
    return rows


# ------------------------------------------------------------------------- fix
def block_spans(lines: list[str]) -> list[tuple[int, int]]:
    """(begin, end) line indexes of every PEM certificate block."""
    spans, begin = [], None
    for i, line in enumerate(lines):
        if line.startswith(PEM_BEGIN):
            begin = i
        elif line.startswith(PEM_END) and begin is not None:
            spans.append((begin, i))
            begin = None
    return spans


def entry_start(lines: list[str], begin: int, floor: int) -> int:
    """First line of the entry owning the block at begin. macOS cert.pem entries
    start at a '=== /subject' line followed by an openssl text dump that contains
    blank lines; other bundles have label lines directly above the block."""
    for i in range(begin - 1, floor - 1, -1):
        if lines[i].startswith(ENTRY_HEADER):
            return i
    start = begin
    while start > floor and lines[start - 1].strip() and not lines[start - 1].startswith("-"):
        start -= 1
    return start


def certless_groups(lines: list[str], drop: set[int]) -> set[int]:
    """Indexes of '### group' header lines with no certificate left under them."""
    empty, current, has_cert = set(), None, False
    for i, line in enumerate(lines):
        if i in drop:
            continue
        if line.startswith(GROUP_HEADER):
            if current is not None and not has_cert:
                empty.add(current)
            current, has_cert = i, False
        elif line.startswith(PEM_BEGIN):
            has_cert = True
    if current is not None and not has_cert:
        empty.add(current)
    return empty


def drop_with_blank(lines: list[str], idx: int, drop: set[int]):
    drop.add(idx)
    if idx + 1 < len(lines) and not lines[idx + 1].strip():
        drop.add(idx + 1)


def filter_bundle(text: str, bad: dict[str, str]):
    """Return (new_text, before, removed_fps, after). Drops each matching
    certificate with its whole entry (labels or macOS '===' header and text
    dump), and any '###' group header that loses its last certificate."""
    lines = text.splitlines(keepends=True)
    spans = block_spans(lines)
    drop: set[int] = set()
    removed = []
    prev_end = -1
    for begin, end in spans:
        fp = block_hit("".join(lines[begin:end + 1]), bad)
        if fp:
            removed.append(fp)
            drop.update(range(entry_start(lines, begin, prev_end + 1), end))
            drop_with_blank(lines, end, drop)
        prev_end = end
    for idx in certless_groups(lines, drop) - certless_groups(lines, set()):
        drop_with_blank(lines, idx, drop)
    res = "".join(line for i, line in enumerate(lines) if i not in drop)
    return res, len(spans), removed, len(pem_blocks(res))


def verify_filter(before, removed, after, new_text, bad, expect):
    if expect is not None and len(removed) != expect:
        return f"expected to remove exactly {expect}, matched {len(removed)}"
    if after != before - len(removed):
        return f"count mismatch: before={before} removed={len(removed)} after={after}"
    if any(block_hit(b, bad) for b in pem_blocks(new_text)):
        return "a distrusted certificate is still present after filtering"
    return None


def write_undo(undo_path: Path, backup: Path, target: Path, mode: int, needs_sudo: bool):
    sudo = "sudo " if needs_sudo else ""
    undo_path.write_text(
        "#!/usr/bin/env bash\n"
        "# Restore the trust bundle saved by trust-store-audit fix --apply.\n"
        "set -euo pipefail\n"
        f"{sudo}install -m {mode:o} {shlex.quote(str(backup))} {shlex.quote(str(target))}\n"
        f"grep -c 'BEGIN CERTIFICATE' {shlex.quote(str(target))}\n"
    )
    undo_path.chmod(0o755)


def cmd_fix(args, bad) -> int:
    target = Path(args.target)
    if not target.is_file():
        print(f"ABORT: {target} not found", file=sys.stderr)
        return 2
    text = target.read_text()
    new_text, before, removed, after = filter_bundle(text, bad)
    print(f"target={target} before={before} removed={len(removed)} after={after}")
    for fp in removed:
        print(f"  remove {fp}  {bad[fp]}")
    err = verify_filter(before, removed, after, new_text, bad, args.expect)
    if err:
        print(f"ABORT: {err}; nothing changed", file=sys.stderr)
        return 3
    if not removed:
        print("Nothing to remove; store is clean.")
        print("\n" + NODE_GUIDANCE)
        return 0
    if not args.apply:
        print("DRY RUN: nothing changed. Re-run with --apply to back up, install and write undo.")
        print("\n" + NODE_GUIDANCE)
        return 0

    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    bdir = Path(args.backup_dir).expanduser()
    bdir.mkdir(parents=True, exist_ok=True)
    backup = bdir / f"{target.name}.bak-{ts}"
    filtered = bdir / f"{target.name}.filtered-{ts}"
    shutil.copy2(target, backup)
    if fps_from_pem_text(backup.read_text()) != fps_from_pem_text(text):
        print("ABORT: backup does not match the original; nothing changed", file=sys.stderr)
        return 3
    filtered.write_text(new_text)
    mode = target.stat().st_mode & 0o777
    needs_sudo = not os.access(target, os.W_OK)
    if needs_sudo:
        if not shutil.which("sudo"):
            print("ABORT: target not writable and sudo not available", file=sys.stderr)
            return 3
        st = target.stat()
        cmd = ["sudo", "install", "-m", f"{mode:o}", "-o", str(st.st_uid), "-g", str(st.st_gid),
               str(filtered), str(target)]
    else:
        cmd = ["install", "-m", f"{mode:o}", str(filtered), str(target)]
    undo = bdir / f"undo-{target.name}-{ts}.sh"
    write_undo(undo, backup, target, mode, needs_sudo)
    print(f"Backup: {backup}\nUndo:   bash {undo}")
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print("ABORT: install failed; original left in place", file=sys.stderr)
        return 3
    if any(block_hit(b, bad) for b in pem_blocks(target.read_text())):
        print("ERROR: distrusted root still present after install; run the undo script",
              file=sys.stderr)
        return 3
    print("Installed and verified.")
    if str(target) == DEBIAN_BUNDLE:
        print("Note: update-ca-certificates regenerates this file. To make it stick, also\n"
              "deselect the roots in /etc/ca-certificates.conf (prefix with '!').")
    if str(target) == MACOS_CERT_PEM:
        print("Note: macOS updates may restore /etc/ssl/cert.pem; re-run after updates.")
    print("\n" + NODE_GUIDANCE)
    return 0


# ------------------------------------------------------------------------- cli
def is_problem(r) -> bool:
    return r["status"] in PROBLEM_STATUSES


def print_table(results, verbose=False):
    shown = [r for r in results if verbose or not r.get("sweep") or r["status"] not in QUIET_STATUSES]
    hidden = len(results) - len(shown)
    print(f"{'STORE':34} {'STATUS':8} {'CERTS':>5}  VERSION")
    if hidden:
        print(f"({hidden} clean sweep results hidden; --verbose shows them)")
    for r in shown:
        print(f"{r['store'][:34]:34} {r['status']:8} {str(r.get('total', '-')):>5}  "
              f"{r.get('version', '')}")
        if r.get("location"):
            print(f"{'':34}   at {r['location']}")
        for f in r["found"]:
            print(f"{'':34}   ! {f['sha256']}  {f['label']}")
        if r.get("note"):
            print(f"{'':34}   ({r['note']})")
    print_summary(results)


def print_summary(results):
    counts: dict[tuple[str, str], int] = {}
    for r in results:
        if r["status"] in PROBLEM_STATUSES or r["status"] == "REBUILD":
            key = (r["status"], r.get("kind", r["store"]))
            counts[key] = counts.get(key, 0) + 1
    if not counts:
        print("\nSUMMARY: nothing affected found.")
        return
    print("\nSUMMARY")
    for (status, kind), n in sorted(counts.items()):
        print(f"  {status:8} {n:4}  {kind}")


def default_preset():
    return str(HERE / "presets" / "emudhra-2026.json")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="trust-store-audit", description=__doc__.split("\n")[0])
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--fingerprints", "-f", default=default_preset(),
                       help="file of SHA-256 fingerprints (default: eMudhra 2026 preset)")

    a = sub.add_parser("audit", help="report distrusted roots per store (read-only)")
    common(a)
    a.add_argument("--bundle", action="append", help="also audit this PEM bundle (repeatable)")
    a.add_argument("--only-bundles", action="store_true",
                   help="skip the built-in stores: audit only --bundle files and the sweep options")
    a.add_argument("--python", action="append", default=None,
                   help="interpreter(s) to check for certifi (default: python3)")
    a.add_argument("--live", action="store_true", help="also test live TLS to known-bad hosts")
    a.add_argument("--hosts", default=str(HERE / "presets" / "emudhra-2026-hosts.txt"))
    a.add_argument("--json", action="store_true", help="JSON output")
    a.add_argument("--scan", action="append", metavar="DIR",
                   help="sweep DIR for CA bundles, keystores and pip/certifi installs")
    a.add_argument("--projects", action="append", metavar="DIR",
                   help="like --scan, plus lockfiles and Dockerfiles of the projects under DIR")
    a.add_argument("--apps", action="store_true",
                   help="Electron apps, runtimes (node, uv, go, ...) and roots embedded in their binaries")
    a.add_argument("--site", action="append", metavar="HOST",
                   help="check the certificate chain HOST serves (repeatable)")
    a.add_argument("--ct", action="append", metavar="DOMAIN",
                   help="search crt.sh for unexpired eMudhra certificates for DOMAIN and subdomains")
    a.add_argument("--preset-json", default=default_preset(),
                   help="certificate preset used for binary and key matching")
    a.add_argument("--patched", default=str(HERE / "presets" / "emudhra-2026-patched.json"),
                   help="patched-versions table")
    a.add_argument("--verbose", "-v", action="store_true", help="also list clean sweep results")

    f = sub.add_parser("fix", help="remove distrusted roots from one PEM bundle")
    common(f)
    f.add_argument("target", help="PEM bundle, e.g. /etc/ssl/cert.pem")
    f.add_argument("--expect", type=int, default=None,
                   help="abort unless exactly this many certificates match")
    f.add_argument("--apply", action="store_true", help="really change the file (may use sudo)")
    f.add_argument("--backup-dir", default="~/.trust-store-audit")

    sub.add_parser("node-guidance", help="print how to make Node use the system store")

    args = ap.parse_args(argv)
    if args.cmd == "node-guidance":
        print(NODE_GUIDANCE)
        return 0
    bad = load_fingerprints(args.fingerprints)
    if args.cmd == "fix":
        return cmd_fix(args, bad)

    args.python = args.python or ["python3"]
    results = audit_all(bad, args)
    live = live_tests(load_hosts(args.hosts), results) if args.live else []
    if args.json:
        print(json.dumps({"version": __version__, "fingerprints": len(bad),
                          "stores": results, "live": live}, indent=2))
    else:
        print(f"trust-store-audit {__version__}: checking {len(bad)} fingerprint(s)\n")
        print_table(results, args.verbose)
        if live:
            print(f"\n{'HOST':48} {'CLIENT':40} RESULT")
            for row in live:
                print(f"{row['host'][:48]:48} {row['client'][:40]:40} {row['result']}")
        if any(r["status"] == "PRESENT" and r["kind"] == "node" for r in results):
            print("\n" + NODE_GUIDANCE)
    present = any(is_problem(r) for r in results)
    accepted = any(row["result"] == "ACCEPTED" for row in live)
    return 1 if (present or accepted) else 0


if __name__ == "__main__":
    sys.exit(main())
