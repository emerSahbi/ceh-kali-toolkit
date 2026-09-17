"""Read-only dependency checks."""
import importlib.util
import platform
import shutil
import sys


def register(subparsers):
    parser = subparsers.add_parser("doctor", help="Check Python, DNS library and Kali utilities")
    parser.set_defaults(handler=run)


def run(args):
    dns_present = importlib.util.find_spec("dns") is not None
    tools = {name: shutil.which(name) for name in ("nmap", "tshark")}
    return {"platform": platform.platform(), "python": sys.version.split()[0], "dnspython": dns_present,
            "tools": tools, "core_ready": sys.version_info >= (3, 9) and dns_present and bool(tools["nmap"]),
            "kali_install": "sudo apt install python3 python3-dnspython nmap",
            "optional_traffic_install": "sudo apt install tshark"}
