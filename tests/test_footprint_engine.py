"""Offline tests: python3 -m unittest -v test_footprint.py."""
import argparse
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from urllib.request import Request
from cehkit import footprint as f

XML = '''<nmaprun><host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="8080"><state state="open"/>
<service name="http" product="TestServer" version="1.0"/>
<script id="http-title" output="Lab"/></port></ports></host>
<runstats><finished exit="success"/></runstats></nmaprun>'''


class FootprintTests(unittest.TestCase):
    def test_targets(self):
        self.assertEqual(f.target_value(r"www\.test.test"), "www.test.test")
        self.assertEqual(f.target_value("192.168.56.29/24"), "192.168.56.0/24")
        self.assertEqual(f.target_value("::1"), "::1")
        for value in ("--script=all", "example.com;whoami", "https://example.com", "example.com/path"):
            with self.assertRaises(argparse.ArgumentTypeError):
                f.target_value(value)

    def test_ports(self):
        self.assertEqual(f.port_list("22,80,443,8000-8100"), "22,80,443,8000-8100")
        for value in ("0", "65536", "90-80", "80;id", "1,,2"):
            with self.assertRaises(argparse.ArgumentTypeError):
                f.port_list(value)

    def test_profiles(self):
        args = f.build_parser().parse_args(["192.168.56.10", "--profile", "full", "--ports", "22,80", "--skip-host-discovery"])
        scan = dict(f.nmap_commands(args, Path("artifacts")))["tcp_services"]
        for value in ("-sT", "-Pn", f.ENUM_SCRIPTS):
            self.assertIn(value, scan)
        self.assertEqual(scan[-1], "192.168.56.10")
        self.assertNotIn("--top-ports", scan)
        args.profile = "discover"
        self.assertNotIn("--script", dict(f.nmap_commands(args, Path("artifacts")))["tcp_services"])

    def test_ipv6_udp(self):
        args = f.build_parser().parse_args(["::1", "--profile", "full", "--udp"])
        commands = dict(f.nmap_commands(args, Path("artifacts")))
        self.assertIn("-6", commands["tcp_services"])
        self.assertIn("-sU", commands["udp_services"])

    def test_dry_run_no_network(self):
        with patch("sys.argv", ["footprint.py", "www.test.test", "--profile", "full", "--dry-run"]), patch.object(f, "fetch", side_effect=AssertionError("network")), patch.object(f, "execute_nmap", side_effect=AssertionError("process")), contextlib.redirect_stdout(io.StringIO()) as output:
            f.main()
        plan = json.loads(output.getvalue())
        self.assertIn("subdomains", plan["modules"])
        self.assertEqual(len(plan["commands"]), 2)

    def test_cli_constraints(self):
        cases = [["10.0.0.0/8", "--profile", "full"], ["test.test", "--timeout", "nan"], ["test.test", "--udp"], ["test.test", "--top-ports", "65536"], ["127.0.0.1", "--subdomains"], ["test.test", "-o", "result.md"]]
        for args in cases:
            with patch("sys.argv", ["footprint.py"] + args), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
                f.main()
            self.assertEqual(error.exception.code, 2)

    def test_xml_and_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            xml = Path(directory) / "scan.xml"
            xml.write_text(XML, encoding="utf-8")
            results = f.parse_nmap(xml)
            port = results["hosts"][0]["ports"][0]
            self.assertEqual(port["service"]["product"], "TestServer")
            self.assertEqual(port["scripts"][0]["output"], "Lab")
            output = Path(directory) / "report.json"
            f.save_report({"target": "127.0.0.1", "profile": "full", "scans": {"tcp": {"results": results}}}, output)
            self.assertIn("8080/tcp open", output.with_suffix(".md").read_text(encoding="utf-8"))
            self.assertEqual(json.loads(output.read_text())["target"], "127.0.0.1")

    def test_missing_nmap(self):
        with patch.object(f.shutil, "which", return_value=None):
            self.assertIn("missing", f.execute_nmap(["nmap"], 1)["error"])

    def test_nmap_timeout(self):
        with tempfile.TemporaryDirectory() as directory:
            command = ["nmap", "-oA", str(Path(directory) / "tcp"), "127.0.0.1"]
            with patch.object(f.shutil, "which", return_value="nmap"), patch.object(f.subprocess, "run", side_effect=subprocess.TimeoutExpired(command, 1)):
                result = f.execute_nmap(command, 1)
            self.assertIn("timed out", result["error"])
            self.assertTrue(Path(result["log"]).exists())

    def test_nmap_argument_list(self):
        with tempfile.TemporaryDirectory() as directory:
            command = ["nmap", "-oA", str(Path(directory) / "space in path"), "127.0.0.1"]
            with patch.object(f.shutil, "which", return_value="nmap"), patch.object(f.subprocess, "run", return_value=subprocess.CompletedProcess(command, 2)) as run:
                result = f.execute_nmap(command, 1)
            self.assertEqual(run.call_args[0][0], command)
            self.assertFalse(run.call_args[1].get("shell", False))
            self.assertEqual(result["returncode"], 2)

    def test_email_sources(self):
        result = f.emails_from({"whois": {"responses": [{"server": "whois.test", "text": "help@test.test"}]}, "website": {"pages": {"homepage": {"final_url": "https://test.test", "body": "help@test.test contact&#64;test.test"}, "missing": {"error": "timeout"}}}})
        self.assertEqual(len(result), 2)
        self.assertEqual(len(next(x for x in result if x["address"] == "help@test.test")["sources"]), 2)

    def test_redirect_scope(self):
        redirect = f.SameHostRedirect()
        request = Request("https://test.test")
        with self.assertRaises(ValueError):
            redirect.redirect_request(request, None, 302, "Found", {}, "https://other.test")
        allowed = redirect.redirect_request(request, None, 302, "Found", {}, "https://test.test/contact")
        self.assertEqual(allowed.full_url, "https://test.test/contact")

    def test_crawl_stays_bounded_and_on_host(self):
        def fake_fetch(url, timeout, same_host):
            return {"requested_url": url, "final_url": url, "status": 200,
                    "headers": {"content-type": "text/html"},
                    "body": '<a href="https://other.test/">offsite</a><a href="/one">one</a><a href="/two">two</a>', "title": "Test"}
        with patch.object(f, "fetch", side_effect=fake_fetch) as fetch:
            result = f.website_lookup("test.test", 1, max_pages=2)
        self.assertEqual(len(result["pages"]), 5)
        self.assertEqual(fetch.call_count, 5)
        self.assertTrue(all(call[0][0].startswith("https://test.test/") for call in fetch.call_args_list))
        self.assertTrue(all(call[0][2] for call in fetch.call_args_list))

    def test_one_bad_module_does_not_lose_report(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            with patch("sys.argv", ["footprint.py", "127.0.0.1", "-o", str(output)]), patch.object(f, "website_lookup", side_effect=TimeoutError("lab timeout")), patch.object(f, "tls_lookup", return_value={"version": "TLSv1.3"}), contextlib.redirect_stdout(io.StringIO()):
                f.main()
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertIn("lab timeout", report["website"]["error"])
            self.assertEqual(report["tls"]["version"], "TLSv1.3")
            self.assertEqual(report["status"], "completed")


if __name__ == "__main__":
    unittest.main()
