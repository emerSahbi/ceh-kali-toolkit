"""One CLI with separate commands for each assessment phase."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from . import __version__
from .common import report_path, write_report


def parser():
    from . import recon, scanning, assessment, web_audit, traffic, system_audit, crypto, reporting, doctor, vulnerability, workflow
    root = argparse.ArgumentParser(prog="cehkit", description="Kali reconnaissance, enumeration and assessment toolkit")
    root.add_argument("--version", action="version", version=__version__)
    phases = root.add_subparsers(dest="command", required=True)
    for module in (workflow, recon, scanning, assessment, vulnerability, web_audit, traffic, system_audit, crypto, reporting, doctor):
        module.register(phases)
    phases.add_parser("menu", help="Open the interactive all-in-one menu")
    for command in phases.choices.values():
        command.add_argument("-o", "--output", type=Path, help="JSON output; matching Markdown saved alongside")
    return root


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if (not argv and sys.stdin.isatty()) or argv == ["menu"]:
        from .menu import run_menu
        return run_menu()
    arguments = parser()
    if not argv:
        arguments.print_help()
        return 0
    args = arguments.parse_args(argv)
    if args.command == "menu":
        arguments.error("menu does not accept output options")
    try:
        output = report_path(args.command, args.output)
        args.output_path = output
        result = args.handler(args)
        if getattr(args, "dry_run", False):
            print(json.dumps(result, indent=2, ensure_ascii=False))
            return 0
        envelope = {"toolkit_version": __version__, "phase": args.command,
                    "created_at": datetime.now(timezone.utc).isoformat(), "result": result}
        write_report(output, envelope)
        print("Saved {} and {}".format(output, output.with_suffix(".md")))
        return 1 if result.get("error") or result.get("status") in ("error", "failed", "partial", "mismatch", "completed_with_errors") else 0
    except (ValueError, OSError, argparse.ArgumentTypeError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. Existing Nmap artifacts remain available.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
