import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import fim  # noqa: E402

FIXTURES = Path(__file__).parent.parent / "test" / "fixtures"


class FimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "site"
        (self.root / "css").mkdir(parents=True)
        (self.root / "index.html").write_text("<h1>Hi</h1>\n")
        (self.root / "config.php").write_text("<?php define('A', 1);\n")
        (self.root / "css" / "site.css").write_text("body{}\n")
        (self.root / ".git").mkdir()
        (self.root / ".git" / "HEAD").write_text("ref\n")

    def tearDown(self):
        self.tmp.cleanup()

    def test_hash_file_matches_known_vector(self):
        p = self.root / "abc.txt"
        p.write_bytes(b"abc")
        self.assertEqual(fim.hash_file(p), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_manifest_uses_relative_posix_paths_and_ignores_git(self):
        m = fim.build_manifest(self.root)
        self.assertEqual(sorted(m["files"]), ["config.php", "css/site.css", "index.html"])
        fim.validate_manifest(m)

    def test_detects_modified_added_removed(self):
        base = fim.build_manifest(self.root)
        (self.root / "config.php").write_text("<?php eval($_GET['x']);\n")
        (self.root / "uploads").mkdir()
        (self.root / "uploads" / "a.php").write_text("<?php system($_GET['c']);\n")
        (self.root / "css" / "site.css").unlink()
        r = fim.compare(base, fim.build_manifest(self.root))
        self.assertFalse(r["clean"])
        self.assertEqual([(x["path"], x["severity"]) for x in r["modified"]], [("config.php", "high")])
        self.assertEqual([(x["path"], x["severity"]) for x in r["added"]], [("uploads/a.php", "critical")])
        self.assertEqual([x["path"] for x in r["removed"]], ["css/site.css"])

    def test_validate_rejects_bad_manifests(self):
        with self.assertRaises(ValueError):
            fim.validate_manifest({"tool": "other"})
        with self.assertRaises(ValueError):
            fim.validate_manifest({"tool": "file-integrity", "version": 1, "algorithm": "sha256", "files": {"a": {"sha256": "nope"}}})

    def test_cli_exit_codes(self):
        out = Path(self.tmp.name) / "baseline.json"
        script = Path(fim.__file__)
        run = lambda *a: subprocess.run([sys.executable, str(script), *a], capture_output=True, text=True)
        self.assertEqual(run("baseline", str(self.root), "-o", str(out)).returncode, 0)
        self.assertEqual(run("check", str(self.root), "-m", str(out)).returncode, 0)
        (self.root / "index.html").write_text("changed\n")
        res = run("check", str(self.root), "-m", str(out))
        self.assertEqual(res.returncode, 1)
        self.assertIn("MODIFIED", res.stdout)

    def test_fixture_baseline_is_current(self):
        """The shared fixture baseline (also checked by the JavaScript tests) matches the files."""
        saved = fim.load_manifest(FIXTURES / "sample-site.baseline.json")
        fresh = fim.build_manifest(FIXTURES / "sample-site")
        self.assertTrue(fim.compare(saved, fresh)["clean"])


if __name__ == "__main__":
    unittest.main()
