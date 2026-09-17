"""One CLI with separate commands for each assessment phase."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
from . import __version__
from .common import report_path, write_report


def parser():
    from . import recon, scanning, assessment, web_audit, traffic, system_audit, crypto, reporting, doctor, vulnerability
    root = argparse.ArgumentParser(prog="cehkit", description="Kali reconnaissance, enumeration and assessment toolkit")
    root.add_argument("--version", action="version", version=__version__)
    phases = root.add_subparsers(dest="command", required=True)
    for module in (recon, scanning, assessment, vulnerability, web_audit, traffic, system_audit, crypto, reporting, doctor):
        module.register(phases)
    for command in phases.choices.values():
        command.add_argument("-o", "--output", type=Path, help="JSON output; matching Markdown saved alongside")
    return root


def main(argv=None):
    arguments = parser()
    args = arguments.parse_args(argv)
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
    except (ValueError, OSError) as error:
        print("Error: " + str(error), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Interrupted. Existing Nmap artifacts remain available.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
