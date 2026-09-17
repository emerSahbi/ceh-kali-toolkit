import argparse
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from cehkit import common, recon, scanning


class CoreTests(unittest.TestCase):
    def commands(self):
        root = argparse.ArgumentParser()
        subs = root.add_subparsers(dest="command", required=True)
        scanning.register(subs)
        recon.register(subs)
        return root

    def test_recon_dry_run_includes_apex(self):
        args = self.commands().parse_args(["recon", "www.test.test", "--subdomains", "--dry-run"])
        result = recon.run(args)
        self.assertEqual(result["registration_domain"], "test.test")
        self.assertIn("zone_dns", result["modules"])
        self.assertIn("subdomains", result["modules"])

    def test_nested_collection_failures(self):
        self.assertTrue(recon.collection_errors("dns", {"records": {"A": {"error": "LifetimeTimeout: resolver failed"}}}))
        self.assertTrue(recon.collection_errors("whois", {"responses": [{"text": "referral"}, {"error": "TimeoutError: timeout"}]}))
        self.assertTrue(recon.collection_errors("website", {"attempts": [{"error": "https failed"}, {"error": "http failed"}]}))

    def test_expected_dns_absence_and_http_fallback(self):
        self.assertFalse(recon.collection_errors("dns", {"records": {"AAAA": {"error": "NoAnswer: no record"}, "MX": {"error": "NXDOMAIN: absent"}}}))
        self.assertFalse(recon.collection_errors("website", {"attempts": [{"error": "https failed"}], "pages": {"homepage": {"status": 200}}}))

    def test_recon_partial_failure_returns_nonzero(self):
        from cehkit.cli import main
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            output = Path(directory) / "recon.json"
            with patch.object(recon.footprint, "dns_lookup", return_value={"records": {"A": {"error": "LifetimeTimeout: resolver failed"}}}), patch.object(recon.footprint, "whois_lookup", return_value={}), patch.object(recon.footprint, "rdap_lookup", return_value={}), patch.object(recon.footprint, "website_lookup", return_value={"pages": {}}), patch.object(recon.footprint, "tls_lookup", return_value={}):
                self.assertEqual(main(["recon", "test.test", "-o", str(output)]), 1)
            self.assertEqual(json.loads(output.read_text())["result"]["status"], "completed_with_errors")

    def test_selective_enumeration_plan(self):
        args = self.commands().parse_args(["enumerate", "192.168.56.101", "--services", "ssh,web", "--ports", "22,443", "--dry-run"])
        args.output_path = Path("reports/enum.json")
        plan = scanning.run(args)
        command = plan["commands"]["tcp_services"]
        scripts = command[command.index("--script") + 1]
        self.assertIn("ssh-hostkey", scripts)
        self.assertNotIn("smb", scripts)
        self.assertEqual(command[-1], "192.168.56.101")

    def test_large_network_rejected(self):
        args = self.commands().parse_args(["scan", "10.0.0.1/8", "--dry-run"])
        args.output_path = Path("reports/scan.json")
        with self.assertRaisesRegex(ValueError, "max-hosts"):
            scanning.run(args)

    def test_unknown_services_rejected(self):
        args = self.commands().parse_args(["enumerate", "127.0.0.1", "--services", "all,brute", "--dry-run"])
        args.output_path = Path("reports/enum.json")
        with self.assertRaisesRegex(ValueError, "Unknown services"):
            scanning.run(args)

    def test_bad_numeric_limits(self):
        for value in ("nan", "inf", "-1", "0"):
            with self.assertRaises(argparse.ArgumentTypeError):
                common.positive_float(value)

    def test_report_evidence_cannot_break_fence(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            envelope = {"phase": "test", "created_at": "now", "result": {"note": "evidence", "body": "```untrusted"}}
            common.write_report(path, envelope)
            self.assertEqual(json.loads(path.read_text())["phase"], "test")
            self.assertIn("````json", path.with_suffix(".md").read_text())

    def test_cli_dry_run_does_not_write_files(self):
        from cehkit.cli import main
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()) as stdout:
            output = Path(directory) / "report.json"
            self.assertEqual(main(["scan", "127.0.0.1", "--dry-run", "-o", str(output)]), 0)
            self.assertFalse(output.exists())
        self.assertTrue(json.loads(stdout.getvalue())["dry_run"])


if __name__ == "__main__":
    unittest.main()
