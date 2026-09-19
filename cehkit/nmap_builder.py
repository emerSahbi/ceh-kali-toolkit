"""Explicit Nmap command builder for authorized reconnaissance work."""
from pathlib import Path
import os
import shlex
from . import footprint
from .common import positive_int, report_path, timestamp

SCAN_TYPES = {"sS":"-sS", "sT":"-sT", "sU":"-sU", "sN":"-sN", "sF":"-sF", "sX":"-sX", "sA":"-sA", "sW":"-sW", "sM":"-sM"}

def register(subparsers):
    p = subparsers.add_parser("nmap", help="Build and run an explicit Nmap reconnaissance scan")
    p.add_argument("target", type=footprint.target_value)
    p.add_argument("--scan-type", choices=tuple(SCAN_TYPES), default="sT", help="Nmap probe type")
    p.add_argument("--ports", type=footprint.port_list)
    p.add_argument("--top-ports", type=positive_int)
    p.add_argument("--udp", action="store_true", help="Add UDP scan (-sU)")
    p.add_argument("--ping", choices=("default","Pn","PE","PP","PM","PR","none"), default="default", help="Host discovery method")
    p.add_argument("--fragment", action="store_true", help="Fragment IP packets (-f)")
    p.add_argument("--decoys", help="Comma-separated decoy addresses (-D)")
    p.add_argument("--source-ip", help="Spoof source address (-S)")
    p.add_argument("--interface", help="Network interface (-e)")
    p.add_argument("--source-port", type=positive_int, help="Source port (-g)")
    p.add_argument("--timing", choices=tuple("T"+str(i) for i in range(6)), default="T3")
    p.add_argument("--version-detect", action="store_true")
    p.add_argument("--os-detect", action="store_true")
    p.add_argument("--scripts", help="NSE script/category expression")
    p.add_argument("--script-args")
    p.add_argument("--reason", action="store_true")
    p.add_argument("--traceroute", action="store_true")
    p.add_argument("--ipv6", action="store_true")
    p.add_argument("--resolve-dns", action="store_true", help="Resolve hostnames (-R); default is -n")
    p.add_argument("--max-hosts", type=positive_int, default=256)
    p.add_argument("--command-timeout", type=positive_int, default=900)
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(handler=run)

def build_command(args, artifacts):
    if args.udp and args.scan_type == "sU":
        raise ValueError("Choose --scan-type sU or --udp, not both")
    if args.scan_type in ("sS", "sU", "sN", "sF", "sX", "sA", "sW", "sM") and hasattr(os, "geteuid") and os.geteuid() != 0 and not args.dry_run:
        raise ValueError("This scan type normally requires root on Kali; use sudo or preview with --dry-run")
    if args.source_ip and args.interface is None:
        raise ValueError("--source-ip should be paired with --interface")
    if args.top_ports and args.ports:
        raise ValueError("Choose --ports or --top-ports, not both")
    if "/" in args.target and __import__("ipaddress").ip_network(args.target).num_addresses > args.max_hosts:
        raise ValueError("Target network exceeds --max-hosts")
    command = ["nmap", "-R" if args.resolve_dns else "-n", "-" + args.timing, SCAN_TYPES[args.scan_type]]
    if args.udp: command.append("-sU")
    if args.ping == "Pn": command.append("-Pn")
    elif args.ping in ("PE","PP","PM","PR"): command.append("-" + args.ping)
    elif args.ping == "none": command.append("-sn")
    if args.fragment: command.append("-f")
    if args.decoys: command += ["-D", args.decoys]
    if args.source_ip: command += ["-S", args.source_ip]
    if args.interface: command += ["-e", args.interface]
    if args.source_port: command += ["-g", str(args.source_port)]
    if args.version_detect: command.append("-sV")
    if args.os_detect: command.append("-O")
    if args.scripts: command += ["--script", args.scripts]
    if args.script_args: command += ["--script-args", args.script_args]
    if args.reason: command.append("--reason")
    if args.traceroute: command.append("--traceroute")
    if args.ipv6: command.append("-6")
    if args.ports: command += ["-p", args.ports]
    elif args.top_ports: command += ["--top-ports", str(args.top_ports)]
    command += ["-oA", str(artifacts), args.target]
    return command

def run(args):
    artifacts = Path(args.output_path).parent / (Path(args.output_path).stem + "_artifacts_" + timestamp()) / "nmap"
    command = build_command(args, artifacts)
    result = {"target": args.target, "command": command, "shell_command": " ".join(shlex.quote(x) for x in command), "artifacts": str(artifacts)}
    if args.dry_run:
        result["dry_run"] = True
        return result
    artifacts.parent.mkdir(parents=True, exist_ok=True)
    print("Running: " + result["shell_command"], flush=True)
    scan = footprint.capture(footprint.execute_nmap, command, args.command_timeout)
    result["scan"] = scan
    result["status"] = "completed_with_errors" if scan.get("error") else "completed"
    return result
