"""Offline tests for the sweep modules, using the real incident certificates
from presets/emudhra-2026.json and temporary folders. No network."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))
import trust_store_audit as tsa  # noqa: E402
import tsa_indicators as ind  # noqa: E402
import tsa_scan  # noqa: E402
import tsa_versions as ver  # noqa: E402

PRESET = ROOT / "presets" / "emudhra-2026.json"
PATCHED = ROOT / "presets" / "emudhra-2026-patched.json"


def preset():
    return ind.load_preset_json(str(PRESET))


def entry(name):
    return next(e for e in preset()[1] if e["name"] == name)


class TestIndicators(unittest.TestCase):
    def test_spki_matches_published_and_openssl(self):
        e = entry("EM DV TLS CA - G3B")
        der = ind.der_from_pem(e["pem"])
        spki = ind.spki_der(der)
        self.assertEqual(hashlib.sha256(spki).hexdigest().upper(), e["spki_sha256"])
        pub = subprocess.run(["openssl", "x509", "-pubkey", "-noout"], input=e["pem"].encode(),
                             capture_output=True, check=True).stdout
        der_pub = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=pub,
                                 capture_output=True, check=True).stdout
        self.assertEqual(der_pub, spki)

    def test_every_preset_entry_self_consistent(self):
        for e in preset()[1]:
            der = ind.der_from_pem(e["pem"])
            self.assertEqual(ind.cert_keys(der), [e["sha256"], "SPKI:" + e["spki_sha256"]], e["name"])

    def test_spki_rejects_garbage(self):
        self.assertIsNone(ind.spki_der(b"\x30\x03\x02\x01\x00"))
        self.assertIsNone(ind.spki_der(b""))

    def test_cross_sign_matched_by_key(self):
        lookup, _ = preset()
        cross = entry("EM DV TLS CA - G3B (AAA cross-sign)")
        only_spki = {k: v for k, v in lookup.items() if k.startswith("SPKI:")}
        der = ind.der_from_pem(cross["pem"])
        self.assertIsNotNone(ind.first_match(ind.cert_keys(der), only_spki))

    def test_fixture_not_matched(self):
        lookup, _ = preset()
        der = ind.der_from_pem((FIX / "good1.pem").read_text())
        self.assertIsNone(ind.first_match(ind.cert_keys(der), lookup))


class TestVersions(unittest.TestCase):
    def setUp(self):
        self.rules = ver.load_rules(str(PATCHED))

    def test_lines(self):
        cases = [("electron", "44.9.1", ver.OK), ("electron", "44.9.0", ver.OUTDATED),
                 ("electron", "41.0.0", ver.OUTDATED), ("electron", "45.0.0", ver.OK),
                 ("node", "v24.22.1", ver.OK), ("node", "23.11.0", ver.OUTDATED),
                 ("node", "20.19.2", ver.OUTDATED), ("go", "1.26.9", ver.OUTDATED),
                 ("go", "1.27.3", ver.OK), ("certifi", "2026.10.19", ver.OK),
                 ("certifi", "2025.8.3", ver.OUTDATED), ("pip", "26.2.1", ver.OUTDATED),
                 ("uv", "0.13.4", ver.OK), ("webpki-roots", "0.26.11", ver.OUTDATED),
                 ("bun", "1.3.9", ver.OUTDATED), ("nope", "1.0", ver.UNKNOWN)]
        for pkg, v, want in cases:
            self.assertEqual(ver.check(self.rules, pkg, v)[0], want, (pkg, v))


class TestSweeps(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.lookup, self.entries = preset()
        self.patterns = ind.binary_patterns(self.entries)
        self.rules = ver.load_rules(str(PATCHED))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_finds_intermediate_in_nested_bundle(self):
        venv = self.tmp / ".venv/lib/python3.12/site-packages/pip/_vendor/certifi"
        venv.mkdir(parents=True)
        bundle = (FIX / "clean.pem").read_text() + entry("EM OV TLS CA - G3C")["pem"] + "\n"
        (venv / "cacert.pem").write_text(bundle)
        res = tsa_scan.sweep_dir(self.tmp, self.lookup, self.patterns, self.rules)
        hits = [r for r in res if r["status"] == "PRESENT"]
        self.assertEqual(len(hits), 1)
        self.assertIn("EM OV TLS CA - G3C", hits[0]["found"][0]["label"])

    def test_dist_info_versions(self):
        sp = self.tmp / "proj/.venv/lib/python3.12/site-packages"
        (sp / "pip-24.0.dist-info").mkdir(parents=True)
        (sp / "certifi-2026.10.19.dist-info").mkdir()
        res = {r["version"]: r["status"] for r in tsa_scan.sweep_dist_info(self.tmp, self.rules)}
        self.assertEqual(res, {"pip 24.0": ver.OUTDATED, "certifi 2026.10.19": ver.OK})

    def test_keystore_and_binary_scan(self):
        der = ind.der_from_pem(entry("AAA Certificate Services")["pem"])
        (self.tmp / "cacerts").write_bytes(b"\xfe\xed\xfe\xed" + der + b"\x00" * 10)
        res = tsa_scan.sweep_dir(self.tmp, self.lookup, self.patterns, self.rules)
        self.assertEqual(res[0]["status"], "PRESENT")

    def test_binary_scan_pem_and_spki_forms(self):
        e = entry("emSign ECC Root CA - G3")
        (self.tmp / "nodelike").write_bytes(b"\x00junk" + e["pem"].encode() + b"\x00")
        spki = ind.spki_content(ind.spki_der(ind.der_from_pem(e["pem"])))
        (self.tmp / "webpki").write_bytes(b"\x01" * 100 + spki + b"\x02")
        (self.tmp / "clean").write_bytes(b"\x00" * 1000)
        label = "emSign ECC Root CA - G3 (root)"
        self.assertEqual(tsa_scan.scan_binary(self.tmp / "nodelike", self.patterns), [label])
        self.assertEqual(tsa_scan.scan_binary(self.tmp / "webpki", self.patterns), [label])
        self.assertEqual(tsa_scan.scan_binary(self.tmp / "clean", self.patterns), [])

    def test_lockfiles(self):
        app = self.tmp / "app"
        app.mkdir()
        (app / "package-lock.json").write_text(json.dumps(
            {"packages": {"node_modules/electron": {"version": "33.2.0"}}}))
        (app / "uv.lock").write_text('[[package]]\nname = "certifi"\nversion = "2024.8.30"\n')
        (app / "requirements.txt").write_text("requests==2.32.3\ncertifi==2026.10.19\n")
        (app / "Cargo.lock").write_text('[[package]]\nname = "webpki-roots"\nversion = "1.0.10"\n')
        (app / "go.mod").write_text("module x\n\ngo 1.26.4\n")
        (app / "pnpm-lock.yaml").write_text("packages:\n\n  electron@44.9.1:\n    resolution: {}\n")
        (app / "Dockerfile").write_text("FROM python:3.12-slim\n")
        nm = app / "node_modules/x"
        nm.mkdir(parents=True)
        (nm / "package-lock.json").write_text(json.dumps(
            {"packages": {"node_modules/electron": {"version": "1.0.0"}}}))
        res = {(r["store"], r["version"]): r["status"] for r in tsa_scan.sweep_lockfiles(self.tmp, self.rules)}
        self.assertEqual(res, {
            ("lockfile electron", "electron 33.2.0"): ver.OUTDATED,
            ("lockfile certifi", "certifi 2024.8.30"): ver.OUTDATED,
            ("lockfile certifi", "certifi 2026.10.19"): ver.OK,
            ("lockfile webpki-roots", "webpki-roots 1.0.10"): ver.OK,
            ("lockfile go", "go 1.26.4"): ver.OUTDATED,
            ("lockfile electron", "electron 44.9.1"): ver.OK,
            ("dockerfile", "python:3.12-slim"): "REBUILD",
        })

    def test_fix_removes_intermediate_by_key(self):
        target = self.tmp / "cert.pem"
        target.write_text((FIX / "clean.pem").read_text() + "# cross\n"
                          + entry("EM EV TLS CA - G3B (AAA cross-sign)")["pem"] + "\n")
        new, before, removed, after = tsa.filter_bundle(target.read_text(), self.lookup)
        self.assertEqual((before, len(removed), after), (3, 1, 2))
        self.assertNotIn("# cross", new)


if __name__ == "__main__":
    unittest.main()
