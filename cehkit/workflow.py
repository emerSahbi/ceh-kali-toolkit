"""One-command assessment with phase reports and a combined evidence report."""
from pathlib import Path
import ipaddress
from . import footprint, vulnerability
from .common import positive_int, timestamp


def register(subparsers):
    parser = subparsers.add_parser("run", help="Run a target-aware assessment and combine its reports")
    parser.add_argument("target")
    parser.add_argument("--type", choices=("auto", "web", "host", "firewall", "tls"), default="auto", dest="target_type")
    parser.add_argument("--registration-domain", type=footprint.domain_name)
    parser.add_argument("--ports", type=footprint.port_list)
    parser.add_argument("--allowed-tcp", help="Firewall expected ports or none")
    parser.add_argument("--skip-host-discovery", action="store_true")
    parser.add_argument("--max-hosts", type=positive_int, default=256)
    parser.add_argument("--command-timeout", type=positive_int, default=600)
    parser.add_argument("--host-timeout", type=positive_int, default=300)
    parser.add_argument("--dry-run", action="store_true")
    parser.set_defaults(handler=run)


def make_plan(args):
    from .cli import parser
    root = parser()
    directory = Path(args.output_path).parent / (Path(args.output_path).stem + "_phases_" + timestamp())
    options = ["--type", args.target_type, "--max-hosts", str(args.max_hosts),
               "--command-timeout", str(args.command_timeout), "--host-timeout", str(args.host_timeout)]
    if args.ports:
        options += ["--ports", args.ports]
    if args.allowed_tcp is not None:
        options += ["--allowed-tcp", args.allowed_tcp]
    if args.skip_host_discovery:
        options.append("--skip-host-discovery")
    vuln_argv = ["vuln", args.target] + options + ["-o", str(directory / "vuln.json")]
    vuln_args = root.parse_args(vuln_argv)
    vuln_args.output_path = directory / "vuln.json"
    validated = vulnerability.build_plan(vuln_args)
    target, kind = validated["target"], validated["target_type"]
    try:
        ipaddress.ip_network(target, strict=False)
        domain = False
    except ValueError:
        domain = True
    if args.registration_domain and not domain:
        raise ValueError("--registration-domain requires a domain target")
    steps = []
    if domain:
        recon = ["recon", target, "-o", str(directory / "recon.json")]
        if args.registration_domain:
            recon += ["--registration-domain", args.registration_domain]
        steps.append(recon)
    # vuln already discovers ports, identifies services, and runs the selected
    # profile scripts. A separate enumerate pass adds value only for host scans.
    if kind == "host":
        enum = ["enumerate", target, "--max-hosts", str(args.max_hosts),
                "--command-timeout", str(args.command_timeout), "--host-timeout", str(args.host_timeout),
                "-o", str(directory / "enumerate.json")]
        if args.ports:
            enum += ["--ports", args.ports]
        if args.skip_host_discovery:
            enum.append("--skip-host-discovery")
        steps.append(enum)
    steps.append(vuln_argv)
    return {"target": target, "target_type": kind, "directory": str(directory), "steps": steps,
            "note": "Recon for domain targets; host enumeration where applicable; target-specific vulnerability checks; combined report."}


def run(args):
    from .cli import main
    from .reporting import run as combine
    from argparse import Namespace
    plan = make_plan(args)
    if args.dry_run:
        return dict(plan, dry_run=True)
    directory = Path(plan["directory"])
    directory.mkdir(parents=True, exist_ok=True)
    results, reports = [], []
    for argv in plan["steps"]:
        print("\n=== {} ===".format(argv[0]), flush=True)
        try:
            code = main(argv)
        except SystemExit as error:
            code = error.code
        path = Path(argv[argv.index("-o") + 1])
        results.append({"phase": argv[0], "exit_code": code, "report": str(path) if path.exists() else None})
        if path.exists():
            reports.append(path)
        if code == 130:
            break
    combined = combine(Namespace(inputs=reports)) if reports else {"findings": [], "errors": ["No phase reports were produced"]}
    incomplete = (bool(combined.get("errors")) or len(reports) != len(plan["steps"])
                  or any(x["exit_code"] != 0 for x in results))
    combined.update({"target": plan["target"], "target_type": plan["target_type"], "directory": str(directory),
                     "steps": results, "status": "completed_with_errors" if incomplete else "completed"})
    return combined
