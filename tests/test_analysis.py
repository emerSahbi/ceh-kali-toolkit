"""Offline tests for evidence review, capture summaries, and report aggregation."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cehkit import assessment, reporting, traffic


class AssessmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.xml = Path(self.temp.name) / "scan.xml"

    def scan(self, ports, host_scripts=""):
        self.xml.write_text(
            '<nmaprun><host><status state="up"/><address addr="192.168.56.101" addrtype="ipv4"/>'
            '<ports>' + ports + '</ports><hostscript>' + host_scripts + '</hostscript></host></nmaprun>',
            encoding="utf-8",
        )
        return assessment.run(argparse.Namespace(xml=self.xml))

    def test_open_plaintext_and_database_are_review_findings(self):
        result = self.scan(
            '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
            '<port protocol="tcp" portid="3306"><state state="open"/><service name="mysql"/></port>'
        )
        self.assertEqual(result["open_ports_reviewed"], 2)
        self.assertEqual(result["finding_count"], 2)
        self.assertTrue(all(item["severity"] == "review" for item in result["findings"]))
        self.assertEqual(result["findings"][1]["evidence"]["address_scope"], "non-global")
        self.assertIn("does not establish Internet exposure", result["findings"][1]["detail"])

    def test_filtered_or_closed_ports_do_not_create_exposure_findings(self):
        result = self.scan(
            '<port protocol="tcp" portid="23"><state state="filtered"/><service name="telnet"/></port>'
            '<port protocol="tcp" portid="3306"><state state="closed"/><service name="mysql"/></port>'
        )
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["open_ports_reviewed"], 0)

    def test_tls_tunnel_and_unknown_port_do_not_imply_plaintext(self):
        result = self.scan(
            '<port protocol="tcp" portid="21"><state state="open"/><service name="ftp" tunnel="ssl"/></port>'
            '<port protocol="tcp" portid="23"><state state="open"/></port>'
        )
        self.assertEqual(result["findings"], [])

    def test_anonymous_ftp_requires_explicit_positive_script_evidence(self):
        result = self.scan(
            '<port protocol="tcp" portid="21"><state state="open"/><service name="ftp"/>'
            '<script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></port>'
            '<port protocol="tcp" portid="2121"><state state="open"/><service name="ftp"/>'
            '<script id="ftp-anon" output="ERROR: login failed"/></port>'
        )
        matches = [item for item in result["findings"] if item["id"] == "anonymous-ftp-access"]
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["evidence"]["port"], 21)

    def test_starttls_is_reviewed_without_claiming_plaintext_authentication(self):
        result = self.scan('<port protocol="tcp" portid="25"><state state="open"/><service name="smtp"/></port>')
        self.assertEqual(result["findings"][0]["id"], "mail-transport-encryption-review")
        self.assertIn("cannot be determined", result["findings"][0]["detail"])

    def test_smb_signing_requires_explicit_script_evidence(self):
        result = self.scan("", '<script id="smb2-security-mode" output="3.1.1: Message signing enabled but not required"/>')
        self.assertEqual(result["findings"][0]["id"], "smb-signing-review")

    def test_invalid_xml_and_wrong_document_are_reported(self):
        for text in ("<nmaprun>", "<anything/>", '<!DOCTYPE nmaprun [<!ENTITY a "x">]><nmaprun/>'):
            with self.subTest(text=text):
                self.xml.write_text(text, encoding="utf-8")
                self.assertEqual(assessment.run(argparse.Namespace(xml=self.xml))["status"], "failed")

    def test_missing_file_is_reported(self):
        self.assertEqual(assessment.run(argparse.Namespace(xml=self.xml))["status"], "failed")


class TrafficTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.capture = Path(self.temp.name) / "capture with spaces.pcap"
        self.capture.write_bytes(b"fixture")
        self.args = argparse.Namespace(capture=self.capture, max_packets=2, timeout=3)

    def test_counts_include_protocol_layers_and_ipv6(self):
        result = traffic.summarize_rows(
            "eth:ip:tcp:http\t192.168.56.1\t\t192.168.56.2\t\n"
            "eth:ipv6:udp:dns\t\t2001:db8::1\t\t2001:db8::2\n"
            "eth:ip:ip:tcp\t192.168.56.2\t\t192.168.56.1\t\n"
        )
        self.assertEqual(result["packets_summarized"], 3)
        self.assertEqual(result["unique_ip_endpoints"], 4)
        protocols = {item["protocol"]: item["packets"] for item in result["protocols"]}
        self.assertEqual(protocols["ip"], 2)
        self.assertEqual(protocols["eth"], 3)
        self.assertEqual(result["endpoints"][0]["appearances"], 2)

    @patch("cehkit.traffic.shutil.which", return_value="/usr/bin/tshark")
    @patch("cehkit.traffic.subprocess.run")
    def test_offline_command_has_limits_and_no_payload_fields(self, process, _which):
        process.return_value = subprocess.CompletedProcess([], 0,
            "eth:ip:tcp\t192.168.56.1\t\t192.168.56.2\t\n" * 2, "")
        result = traffic.run(self.args)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["packet_limit_reached"])
        args, kwargs = process.call_args
        command = args[0]
        self.assertIsInstance(command, list)
        self.assertEqual(command[command.index("-r") + 1], str(self.capture.resolve()))
        self.assertEqual(command[command.index("-c") + 1], "2")
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], 3)
        self.assertNotIn("-i", command)
        self.assertNotIn("data", command)

    @patch("cehkit.traffic.shutil.which", return_value=None)
    def test_missing_tshark_has_install_hint(self, _which):
        result = traffic.run(self.args)
        self.assertEqual(result["status"], "failed")
        self.assertIn("sudo apt install tshark", result["error"])

    @patch("cehkit.traffic.shutil.which", return_value="tshark")
    @patch("cehkit.traffic.subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 3))
    def test_timeout_is_explicit(self, _process, _which):
        result = traffic.run(self.args)
        self.assertEqual(result["status"], "failed")
        self.assertIn("3 second runtime limit", result["error"])

    @patch("cehkit.traffic.shutil.which", return_value="tshark")
    @patch("cehkit.traffic.subprocess.run")
    def test_tshark_failure_is_not_reported_as_success(self, process, _which):
        process.return_value = subprocess.CompletedProcess([], 2, "", "invalid capture format")
        result = traffic.run(self.args)
        self.assertEqual(result["status"], "failed")
        self.assertIn("invalid capture format", result["error"])

    def test_invalid_limits_are_rejected_before_execution(self):
        self.args.max_packets = 100001
        with patch("cehkit.traffic.subprocess.run") as process:
            result = traffic.run(self.args)
        self.assertEqual(result["status"], "failed")
        process.assert_not_called()


class ReportingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def report(self, name="assess", result=None):
        path = self.root / (name + ".json")
        path.write_text(json.dumps({"phase": name, "created_at": "2026-09-16T12:00:00+00:00",
                                    "result": result or {"status": "completed"}}), encoding="utf-8")
        return path

    def test_aggregate_preserves_sources_and_evidence(self):
        paths = [self.report("assess", {"findings": [{"id": "review", "evidence": {"port": 21}}]}),
                 self.report("scan")]
        result = reporting.run(argparse.Namespace(inputs=paths))
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["counts"]["reports"], 2)
        self.assertEqual(result["counts"]["findings"], 1)
        self.assertEqual(result["counts"]["evidence"], 1)
        self.assertEqual(result["findings"][0]["source"], str(paths[0]))
        self.assertEqual(result["evidence"][0]["observation"], {"port": 21})

    def test_bad_json_and_invalid_schema_are_explicit_and_valid_reports_survive(self):
        bad = self.root / "bad.json"
        bad.write_text("{broken", encoding="utf-8")
        wrong = self.root / "wrong.json"
        wrong.write_text('{"phase": "scan", "created_at": "yesterday", "result": {}}', encoding="utf-8")
        result = reporting.run(argparse.Namespace(inputs=[self.report(), bad, wrong]))
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["counts"]["invalid_inputs"], 2)
        self.assertEqual(result["counts"]["reports"], 1)

    def test_all_invalid_reports_fail_and_duplicate_input_is_not_counted_twice(self):
        invalid = reporting.run(argparse.Namespace(inputs=[self.root / "missing.json"]))
        self.assertEqual(invalid["status"], "failed")
        report = self.report()
        duplicate = reporting.run(argparse.Namespace(inputs=[report, report]))
        self.assertEqual(duplicate["counts"]["reports"], 1)
        self.assertIn("Duplicate", duplicate["errors"][0]["error"])

    def test_nonstandard_json_numeric_literals_are_rejected(self):
        path = self.root / "nonfinite.json"
        path.write_text('{"phase":"scan","created_at":"2026-09-16T12:00:00Z",'
                        '"result":{"value":NaN}}', encoding="utf-8")
        result = reporting.run(argparse.Namespace(inputs=[path]))
        self.assertEqual(result["status"], "failed")
        self.assertIn("not valid JSON", result["errors"][0]["error"])

    def test_all_commands_register_handlers(self):
        parser = argparse.ArgumentParser()
        subs = parser.add_subparsers(dest="phase")
        for module in (assessment, traffic, reporting):
            module.register(subs)
        for command, source in (("assess", "scan.xml"), ("traffic", "capture.pcap"), ("report", "scan.json")):
            with self.subTest(command=command):
                self.assertTrue(callable(parser.parse_args([command, source]).handler))


if __name__ == "__main__":
    unittest.main()
