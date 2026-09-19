import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from cehkit import __version__, cli, menu, workflow

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("install_app", ROOT / "scripts" / "install_app.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


class MenuTests(unittest.TestCase):
    def test_tty_opens_menu_and_redirected_input_prints_help(self):
        with patch.object(sys.stdin, "isatty", return_value=True), patch.object(menu, "run_menu", return_value=0) as launch:
            self.assertEqual(cli.main([]), 0)
            launch.assert_called_once_with()
        with patch.object(sys.stdin, "isatty", return_value=False), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main([]), 0)
        self.assertIn("usage: cehkit", out.getvalue())

    def test_explicit_menu_dispatch(self):
        with patch.object(menu, "run_menu", return_value=0) as launch:
            self.assertEqual(cli.main(["menu"]), 0)
            launch.assert_called_once_with()

    def test_menu_retries_and_dispatches_argument_list(self):
        with patch("builtins.input", side_effect=["bad", "12", "folder with spaces/result.json", "0"]), contextlib.redirect_stdout(io.StringIO()):
            calls = []
            self.assertEqual(menu.run_menu(lambda argv: calls.append(argv) or 0), 0)
        self.assertEqual(calls, [["doctor", "-o", "folder with spaces/result.json"]])

    def test_web_plan_input_does_not_prompt_for_ports(self):
        answers = ["auto", "https://www.test.test/", "n", "test.test", "y"]
        with patch("builtins.input", side_effect=answers):
            argv = menu.build_arguments("run")
        self.assertEqual(argv, ["run", "https://www.test.test/", "--type", "auto", "--registration-domain", "test.test", "--dry-run"])
        cli.parser().parse_args(argv)

    def test_shell_characters_remain_literal_arguments(self):
        target = "test.test; echo bad"
        with patch("builtins.input", side_effect=["host", target, "", "n", "y"]):
            argv = menu.build_arguments("vuln")
        self.assertEqual(argv[1], target)
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(argv), 2)

    def test_eof_exits_and_parser_errors_return_to_menu(self):
        with patch("builtins.input", side_effect=EOFError), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(menu.run_menu(), 0)
        with patch("builtins.input", side_effect=["12", "", "0"]), contextlib.redirect_stdout(io.StringIO()):
            def invalid(argv):
                raise SystemExit(2)
            self.assertEqual(menu.run_menu(invalid), 0)


class WorkflowTests(unittest.TestCase):
    def args(self, argv, output="reports/combined.json"):
        args = cli.parser().parse_args(["run"] + argv)
        args.output_path = Path(output)
        return args

    def test_profile_phases_and_domain_recon(self):
        cases = [("https://www.test.test/path/", "auto", ["recon", "vuln"]),
                 ("www.test.test", "host", ["recon", "enumerate", "vuln"]),
                 ("192.0.2.10", "host", ["enumerate", "vuln"]),
                 ("192.0.2.10", "firewall", ["vuln"]),
                 ("::1", "tls", ["vuln"])]
        for target, kind, phases in cases:
            with self.subTest(target=target, kind=kind):
                plan = workflow.make_plan(self.args([target, "--type", kind]))
                self.assertEqual([step[0] for step in plan["steps"]], phases)
                for step in plan["steps"]:
                    cli.parser().parse_args(step)
        self.assertEqual(workflow.make_plan(self.args([cases[0][0]]))["steps"][0][1], "www.test.test")

    def test_limits_and_ports_propagate(self):
        plan = workflow.make_plan(self.args(["192.0.2.10", "--ports", "22,443", "--skip-host-discovery", "--max-hosts", "10", "--command-timeout", "30"]))
        for step in plan["steps"]:
            parsed = cli.parser().parse_args(step)
            self.assertEqual(parsed.ports, "22,443")
            self.assertEqual(parsed.command_timeout, 30)
            self.assertEqual(parsed.max_hosts, 10)
            self.assertTrue(parsed.skip_host_discovery)

    def test_invalid_plan_rejected_before_execution(self):
        for argv in (["10.0.0.0/8"], ["192.0.2.10", "--registration-domain", "test.test"],
                     ["https://test.test", "--ports", "22"], ["test.test", "--allowed-tcp", "443"]):
            with self.subTest(argv=argv), self.assertRaises(ValueError):
                workflow.make_plan(self.args(argv))

    def test_dry_run_produces_no_files_or_phase_execution(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(cli, "main", side_effect=AssertionError("phase ran")):
            result = workflow.run(self.args(["https://test.test", "--dry-run"], Path(directory) / "run.json"))
            self.assertTrue(result["dry_run"])
            self.assertEqual(list(Path(directory).iterdir()), [])

    def fake_phase(self, argv, corrupt=False, failure=False):
        path = Path(argv[argv.index("-o") + 1])
        report = {"phase": argv[0], "created_at": "2026-09-19T12:00:00+00:00", "result": {"findings": [{"title": argv[0]}]}}
        path.write_text("bad JSON" if corrupt else json.dumps(report), encoding="utf-8")
        return 1 if failure else 0

    def test_success_combines_reports_and_keeps_phase_artifacts(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), patch.object(cli, "main", side_effect=self.fake_phase):
            result = workflow.run(self.args(["192.0.2.10"], Path(directory) / "run.json"))
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["counts"]["reports"], 2)
            self.assertEqual(result["counts"]["findings"], 2)
            self.assertTrue(all(Path(step["report"]).is_file() for step in result["steps"]))

    def test_phase_failure_and_corrupt_reports_are_incomplete(self):
        for mode in ("corrupt", "failure", "missing"):
            def execute(argv):
                return 0 if mode == "missing" else self.fake_phase(argv, corrupt=mode == "corrupt", failure=mode == "failure")
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), patch.object(cli, "main", side_effect=execute):
                result = workflow.run(self.args(["192.0.2.10"], Path(directory) / "run.json"))
                self.assertEqual(result["status"], "completed_with_errors")

    def test_interrupt_stops_remaining_phases(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()), patch.object(cli, "main", return_value=130) as execute:
            result = workflow.run(self.args(["test.test"], Path(directory) / "run.json"))
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(result["status"], "completed_with_errors")


class InstallerTests(unittest.TestCase):
    def test_install_update_and_launcher_outside_checkout(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()):
            base = Path(directory)
            launcher = installer.install(ROOT, base / "app space", base / "bin")
            completed = subprocess.run([sys.executable, str(launcher), "--version"], cwd=str(base), capture_output=True, text=True)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout.strip(), __version__)
            self.assertEqual(installer.install(ROOT, base / "app space", base / "bin"), launcher)
            self.assertNotIn(b"\r\n", launcher.read_bytes())

    def test_unmanaged_launcher_and_directory_are_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / "bin").mkdir()
            launcher = base / "bin" / "cehkit"
            launcher.write_text("unrelated application", encoding="utf-8")
            with self.assertRaises(ValueError):
                installer.install(ROOT, base / "app", base / "bin")
            self.assertEqual(launcher.read_text(), "unrelated application")
            destination = base / "app" / __version__
            destination.mkdir(parents=True)
            with self.assertRaises(ValueError):
                installer.install(ROOT, base / "app", base / "other-bin")
            self.assertEqual(list(destination.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
