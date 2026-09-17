import argparse
import email.message
import hashlib
import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from cehkit import crypto, system_audit, web_audit


class AuditTests(unittest.TestCase):
    def test_url_validation(self):
        self.assertEqual(web_audit.validate_url("http://localhost:8080"), "http://localhost:8080/")
        self.assertEqual(web_audit.validate_url("https://[::1]:8443/"), "https://[::1]:8443/")
        for value in ("file:///etc/passwd", "http://user:secret@example.test", "http://example.test:0", "http://example.test:99999", "http://bad_host/", "https://example.test/\r\nX:bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                web_audit.validate_url(value)

    def test_cookie_values_are_never_reported(self):
        headers = email.message.Message()
        headers.add_header("Set-Cookie", "session=supersecret; Secure; HttpOnly; SameSite=Lax")
        headers.add_header("Set-Cookie", "prefs=othersecret; SameSite=None")
        result = web_audit.inspect_headers(headers, True)
        self.assertNotIn("supersecret", json.dumps(result))
        self.assertNotIn("othersecret", json.dumps(result))
        self.assertEqual(len(result["cookies"]), 2)
        self.assertTrue(result["cookies"][0]["secure"])
        self.assertTrue(any("SameSite=None" in finding["message"] for finding in result["findings"]))

    def test_redirect_restrictions(self):
        handler = web_audit.SameHostRedirect("example.test")
        request = urllib.request.Request("https://example.test/")
        for target in ("https://elsewhere.test/", "http://example.test/", "file:///etc/passwd"):
            with self.subTest(target=target), self.assertRaises(urllib.error.URLError):
                handler.redirect_request(request, None, 302, "Found", {}, target)
        redirected = handler.redirect_request(request, None, 302, "Found", {}, "https://example.test:8443/next")
        self.assertEqual(redirected.full_url, "https://example.test:8443/next")

    def test_local_http_fallback_and_redaction(self):
        class Handler(BaseHTTPRequestHandler):
            def do_HEAD(self):
                self.send_response(405)
                self.end_headers()

            def do_GET(self):
                self.send_response(200)
                self.send_header("Set-Cookie", "session=privatevalue; HttpOnly")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = web_audit.audit_url("http://127.0.0.1:" + str(server.server_port) + "/?token=querysecret", 2)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(2)
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(result["method"], "GET")
        self.assertTrue(result["query_omitted"])
        self.assertNotIn("privatevalue", json.dumps(result))
        self.assertNotIn("querysecret", json.dumps(result))

    def test_hash_streams_large_file_and_verifies(self):
        data = b"fixture" * 400000
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(data)
            expected = hashlib.sha256(data).hexdigest()
            result = crypto.hash_file(path, expected=expected.upper())
            self.assertEqual(result["bytes_read"], len(data))
            self.assertTrue(result["matches_expected"])
            self.assertEqual(crypto.hash_file(path, "sha512")["digest"], hashlib.sha512(data).hexdigest())
            self.assertEqual(crypto.hash_file(path, expected="0" * 64)["status"], "mismatch")
            with self.assertRaises(ValueError):
                crypto.hash_file(path, expected="not-hex")
            with self.assertRaises(ValueError):
                crypto.hash_file(directory)

    def test_sshd_includes_and_match_are_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "etc" / "ssh" / "sshd_config"
            path.parent.mkdir(parents=True)
            path.write_text("Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\nPermitRootLogin yes\nMatch User test\nPasswordAuthentication yes\nSetEnv SECRET=sensitive-value\n", encoding="utf-8")
            result = system_audit.inspect_sshd(directory)
            self.assertTrue(result["include_present"])
            self.assertTrue(result["directives"][0]["first_global_in_file"])
            self.assertFalse(result["directives"][1]["first_global_in_file"])
            self.assertEqual(result["directives"][2]["context"], "conditional")
            self.assertNotIn("sensitive-value", json.dumps(result))
            self.assertIn("not the effective", result["limitation"])

    def test_permission_findings_from_metadata(self):
        file_stat = mock.Mock(st_mode=0o100666, st_uid=0, st_gid=0)
        with mock.patch.object(Path, "lstat", return_value=file_stat):
            result = system_audit.inspect_permissions(Path.cwd(), "etc/shadow")
        self.assertEqual(result["mode"], "0666")
        self.assertTrue(any("readable" in message for message in result["findings"]))
        self.assertTrue(any("writable by other" in message for message in result["findings"]))

    def test_nonlinux_default_is_explicit(self):
        with mock.patch.object(system_audit.platform, "system", return_value="Windows"):
            result = system_audit.audit_system()
        self.assertEqual(result["status"], "unsupported")

    def test_local_root_never_reads_password_database(self):
        with tempfile.TemporaryDirectory() as directory:
            shadow = Path(directory) / "etc" / "shadow"
            shadow.parent.mkdir()
            shadow.write_text("private-password-database-fixture", encoding="utf-8")
            result = system_audit.audit_system(directory)
            self.assertEqual(result["status"], "ok")
            self.assertNotIn("private-password", json.dumps(result))
            with self.assertRaises(ValueError):
                system_audit.local_path(directory, "../outside")

    def test_command_registration(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        for module in (web_audit, system_audit, crypto):
            module.register(subparsers)
        self.assertEqual(parser.parse_args(["web-audit", "http://example.test"]).handler, web_audit.run)
        self.assertEqual(parser.parse_args(["system-audit"]).handler, system_audit.run)
        self.assertEqual(parser.parse_args(["hash", "sample.txt"]).handler, crypto.run)


if __name__ == "__main__":
    unittest.main()
