"""Separate network scanning and service enumeration phases."""
import ipaddress
import os
from pathlib import Path
import shlex
from . import footprint
from .common import positive_int, timestamp

SERVICES = {
    "web": "http-title,http-headers,ssl-cert", "ssh": "ssh-hostkey",
    "ftp": "ftp-anon", "smtp": "smtp-commands",
    "smb": "smb-os-discovery,smb-protocols,smb-enum-shares,smb-enum-users",
    "ldap": "ldap-rootdse", "rdp": "rdp-ntlm-info", "mysql": "mysql-info",
    "nfs": "rpcinfo,nfs-showmount",
}


def add_options(parser):
    parser.add_argument("target", type=footprint.target_value)
    parser.add_argument("--ports", type=footprint.port_list)
    parser.add_argument("--top-ports", type=positive_int, default=1000)
    parser.add_argument("--skip-host-discovery", action="store_true")
    parser.add_argument("--udp", action="store_true")
    parser.add_argument("--udp-top-ports", type=positive_int, default=20)
    parser.add_argument("--os-detect", action="store_true")
    parser.add_argument("--traceroute", action="store_true")
    parser.add_argument("--nameserver", type=lambda value: str(ipaddress.ip_address(value)))
    parser.add_argument("--host-timeout", type=positive_int, default=180)
    parser.add_argument("--command-timeout", type=positive_int, default=900)
    parser.add_argument("--max-hosts", type=positive_int, default=256)
    parser.add_argument("--dry-run", action="store_true")
    parser.set_defaults(handler=run)


def register(subparsers):
    scan = subparsers.add_parser("scan", help="Host discovery, TCP/UDP ports and service versions")
    add_options(scan)
    scan.set_defaults(profile="discover", services="all")
    enum = subparsers.add_parser("enumerate", help="Service-specific Nmap enumeration")
    add_options(enum)
    enum.add_argument("--services", default="all", help="all or comma-separated: " + ",".join(SERVICES))
    enum.set_defaults(profile="full")


def run(args):
    if args.top_ports > 65535 or args.udp_top_ports > 65535:
        raise ValueError("Port counts cannot exceed 65535")
    if "/" in args.target and ipaddress.ip_network(args.target).num_addresses > args.max_hosts:
        raise ValueError("Target network exceeds --max-hosts")
    if (args.udp or args.os_detect or args.traceroute) and not args.dry_run and hasattr(os, "geteuid") and os.geteuid() != 0:
        raise ValueError("UDP, OS detection and traceroute require sudo on Kali")
    selected = list(SERVICES) if args.services == "all" else list(dict.fromkeys(args.services.split(",")))
    unknown = set(selected) - set(SERVICES)
    if unknown:
        raise ValueError("Unknown services: " + ", ".join(sorted(unknown)))
    output = Path(args.output_path)
    artifacts = output.parent / (output.stem + "_artifacts_" + timestamp())
    commands = footprint.nmap_commands(args, artifacts)
    if args.profile == "full":
        for name, command in commands:
            if name == "tcp_services":
                command[command.index("--script") + 1] = ",".join(SERVICES[name] for name in selected)
    result = {"target": args.target, "scans": {}, "artifacts": str(artifacts)}
    if args.profile == "full":
        result["services"] = selected
        if args.udp:
            result["udp_scripts"] = footprint.UDP_SCRIPTS.split(",")
    if args.dry_run:
        result.update({"dry_run": True, "commands": dict(commands)})
        return result
    artifacts.mkdir(parents=True, exist_ok=True)
    for name, command in commands:
        print("Running: " + " ".join(shlex.quote(part) for part in command), flush=True)
        result["scans"][name] = footprint.capture(footprint.execute_nmap, command, args.command_timeout)
    result["status"] = "completed_with_errors" if any(
        scan.get("error") or scan.get("results", {}).get("error")
        for scan in result["scans"].values()) else "completed"
    return result
