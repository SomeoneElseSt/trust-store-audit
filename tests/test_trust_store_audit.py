"""Offline tests using self-signed fixture certificates. No network."""
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))
import trust_store_audit as tsa  # noqa: E402


def quiet(fn, *a, **kw):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = fn(*a, **kw)
    return rc, out.getvalue(), err.getvalue()


class TestParsing(unittest.TestCase):
    def test_normalize_colons_and_case(self):
        fp = tsa.normalize_fp("86:a1:" + "0" * 60)
        self.assertEqual(fp, "86A1" + "0" * 60)

    def test_normalize_rejects_bad(self):
        with self.assertRaises(ValueError):
            tsa.normalize_fp("abc")

    def test_load_fixture_fingerprints(self):
        bad = tsa.load_fingerprints(FIX / "distrusted.txt")
        self.assertEqual(len(bad), 2)
        self.assertEqual(sorted(bad.values()), ["bad1", "bad2"])

    def test_preset_file(self):
        bad = tsa.load_fingerprints(tsa.default_preset())
        self.assertIn("86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B", bad)  # pragma: allowlist secret (public root CA fingerprint)
        self.assertIn("D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4", bad)  # pragma: allowlist secret (public root CA fingerprint)
        self.assertIn("42C4ACCD12C4F59597925E1A08A7A90102608543809308D50EC427E118BA1493", bad)  # EM DV TLS CA - G3B
        self.assertIn("SPKI:EBED6475C2C2D80FCB199F3FE8DD6E6B3CE60B77EB15D4E42C3DEC0C6F5B5105", bad)
        self.assertEqual(sum(1 for k in bad if not k.startswith("SPKI:")), 20)

    def test_text_preset_still_loads(self):
        bad = tsa.load_fingerprints(ROOT / "presets" / "emudhra-2026.txt")
        self.assertEqual(len(bad), 2)

    def test_hosts_preset(self):
        hosts = tsa.load_hosts(ROOT / "presets" / "emudhra-2026-hosts.txt")
        self.assertEqual(len(hosts), 12)
        self.assertTrue(all(h.endswith("we-have-a-problem.com") for h in hosts))

    def test_empty_list_rejected(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# nothing\n")
        with self.assertRaises(SystemExit):
            tsa.load_fingerprints(f.name)
        os.unlink(f.name)

    def test_fingerprint_matches_openssl_style(self):
        fps = tsa.fps_from_pem_text((FIX / "bad1.pem").read_text())
        bad = tsa.load_fingerprints(FIX / "distrusted.txt")
        self.assertEqual(bad[fps[0]], "bad1")

    def test_parse_keytool(self):
        fp = ":".join(["AB"] * 32)
        text = f"Alias name: x\nCertificate fingerprints:\n\t SHA1: 00\n\t SHA256: {fp}\n"
        self.assertEqual(tsa.parse_keytool(text), ["AB" * 32])


class TestAudit(unittest.TestCase):
    def setUp(self):
        self.bad = tsa.load_fingerprints(FIX / "distrusted.txt")

    def test_bundle_present(self):
        r = tsa.audit_pem_file("t", FIX / "bundle.pem", "v", self.bad)
        self.assertEqual(r["status"], "PRESENT")
        self.assertEqual(r["total"], 4)
        self.assertEqual(len(r["found"]), 2)

    def test_clean_absent(self):
        r = tsa.audit_pem_file("t", FIX / "clean.pem", "v", self.bad)
        self.assertEqual(r["status"], "absent")
        self.assertEqual(r["total"], 2)

    def test_missing_skipped(self):
        r = tsa.audit_pem_file("t", "/nonexistent/x.pem", "v", self.bad)
        self.assertEqual(r["status"], "skipped")

    def test_cli_exit_codes_and_json(self):
        base = ["audit", "-f", str(FIX / "distrusted.txt"), "--only-bundles", "--json"]
        rc, out, _ = quiet(tsa.main, base + ["--bundle", str(FIX / "bundle.pem")])
        self.assertEqual(rc, 1)
        self.assertEqual(json.loads(out)["stores"][0]["status"], "PRESENT")
        rc, out, _ = quiet(tsa.main, base + ["--bundle", str(FIX / "clean.pem")])
        self.assertEqual(rc, 0)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_node_store_reads(self):
        r = tsa.audit_node(self.bad)
        self.assertEqual(r["status"], "absent")
        self.assertGreater(r["total"], 50)

    def test_node_missing(self):
        with mock.patch.object(tsa.shutil, "which", return_value=None):
            self.assertEqual(tsa.audit_node(self.bad)["status"], "skipped")

    def test_full_audit_runs_offline(self):
        args = mock.Mock(bundle=None, only_bundles=False, python=[sys.executable],
                         scan=None, projects=None, apps=False, site=None, ct=None)
        results = tsa.audit_all(self.bad, args)
        names = [r["store"] for r in results]
        self.assertIn("debian-system-bundle", names)
        self.assertIn("node-bundled-roots", names)


class TestLiveNoNetwork(unittest.TestCase):
    def test_live_python_classifies_without_network(self):
        with mock.patch.object(tsa.socket, "create_connection", side_effect=OSError("no net")):
            self.assertTrue(tsa.live_python("example.invalid", None).startswith("error"))


class TestFix(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.target = self.tmp / "cert.pem"
        shutil.copy(FIX / "bundle.pem", self.target)
        self.bad = str(FIX / "distrusted.txt")
        self.bdir = self.tmp / "backups"

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def fix(self, *extra):
        return quiet(tsa.main, ["fix", "-f", self.bad, str(self.target),
                                "--backup-dir", str(self.bdir), *extra])

    def test_filter_removes_blocks_and_labels(self):
        new, before, removed, after = tsa.filter_bundle(
            self.target.read_text(), tsa.load_fingerprints(self.bad))
        self.assertEqual((before, len(removed), after), (4, 2, 2))
        self.assertNotIn("bad1", new)
        self.assertNotIn("bad2", new)
        self.assertIn("# good1", new)

    def test_dry_run_changes_nothing(self):
        orig = self.target.read_bytes()
        rc, out, _ = self.fix()
        self.assertEqual(rc, 0)
        self.assertIn("DRY RUN", out)
        self.assertIn("--use-openssl-ca", out)
        self.assertEqual(self.target.read_bytes(), orig)
        self.assertFalse(self.bdir.exists())

    def test_expect_mismatch_aborts(self):
        orig = self.target.read_bytes()
        rc, _, err = self.fix("--expect", "3", "--apply")
        self.assertEqual(rc, 3)
        self.assertIn("ABORT", err)
        self.assertEqual(self.target.read_bytes(), orig)
        self.assertFalse(self.bdir.exists())

    def test_apply_backup_verify_and_undo(self):
        orig = self.target.read_bytes()
        rc, out, _ = self.fix("--expect", "2", "--apply")
        self.assertEqual(rc, 0, out)
        self.assertIn("Installed and verified", out)
        left = tsa.fps_from_pem_text(self.target.read_text())
        self.assertEqual(len(left), 2)
        backups = list(self.bdir.glob("cert.pem.bak-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), orig)
        undo = next(self.bdir.glob("undo-*.sh"))
        self.assertNotIn("sudo", undo.read_text())
        subprocess.run(["bash", str(undo)], check=True, capture_output=True)
        self.assertEqual(self.target.read_bytes(), orig)

    def test_clean_target_nothing_to_do(self):
        shutil.copy(FIX / "clean.pem", self.target)
        rc, out, _ = self.fix("--apply")
        self.assertEqual(rc, 0)
        self.assertIn("clean", out)
        self.assertFalse(self.bdir.exists())

    def test_never_calls_sudo_without_apply(self):
        with mock.patch.object(tsa.subprocess, "run") as run:
            self.fix()
            for call in run.call_args_list:
                self.assertNotEqual(call.args[0][0], "sudo")

    def test_wrapper_script(self):
        r = subprocess.run(["bash", str(ROOT / "trust-store-audit"), "--version"],
                           capture_output=True, text=True)
        self.assertEqual(r.stdout.strip(), tsa.__version__)


class TestNodeSnippet(unittest.TestCase):
    def run_snippet(self, initial):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        if initial is not None:
            env["NODE_OPTIONS"] = initial
        r = subprocess.run(["bash", "-c", '. "$1"; . "$1"; printf %s "$NODE_OPTIONS"', "_",
                            str(ROOT / "contrib" / "node-use-openssl-ca.sh")],
                           capture_output=True, text=True, env=env)
        return r.stdout

    def test_appends_once(self):
        self.assertEqual(self.run_snippet(None), "--use-openssl-ca")
        self.assertEqual(self.run_snippet("--max-old-space-size=512"),
                         "--max-old-space-size=512 --use-openssl-ca")


if __name__ == "__main__":
    unittest.main()
