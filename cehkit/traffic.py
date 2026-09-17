"""Bounded offline packet metadata summaries using TShark."""

import argparse
from collections import Counter
import ipaddress
from pathlib import Path
import shutil
import subprocess


def _packet_limit(value):
    value = int(value)
    if not 1 <= value <= 100000:
        raise argparse.ArgumentTypeError("max-packets must be between 1 and 100000")
    return value


def _timeout(value):
    value = int(value)
    if not 1 <= value <= 3600:
        raise argparse.ArgumentTypeError("timeout must be between 1 and 3600 seconds")
    return value


def register(subparsers):
    parser = subparsers.add_parser(
        "traffic", help="Summarize protocols and endpoints in an existing packet capture",
        description="Read a local pcap/pcapng capture with tshark. Outputs protocol and IP "
                    "endpoint counts, without extracting packet payloads or credentials.",
    )
    parser.add_argument("capture", type=Path, help="Existing pcap or pcapng file")
    parser.add_argument("--max-packets", type=_packet_limit, default=10000,
                        help="Maximum packets to read (1-100000; default: 10000)")
    parser.add_argument("--timeout", type=_timeout, default=120,
                        help="TShark runtime limit in seconds (default: 120)")
    parser.set_defaults(handler=run)
    return parser


def summarize_rows(output):
    protocols, sources, destinations = Counter(), Counter(), Counter()
    packet_count = 0
    malformed_rows = 0
    for line in output.splitlines():
        if not line:
            continue
        fields = line.split("\t")
        if len(fields) != 5:
            malformed_rows += 1
            continue
        packet_count += 1
        # Count each layer once per packet, including tunneled packets.
        protocols.update(set(name for name in fields[0].split(":") if name))
        for counter, indexes in ((sources, (1, 2)), (destinations, (3, 4))):
            seen = set()
            for index in indexes:
                address = fields[index]
                if not address:
                    continue
                try:
                    address = str(ipaddress.ip_address(address))
                except ValueError:
                    continue
                if address not in seen:
                    counter[address] += 1
                    seen.add(address)
    endpoints = sources + destinations
    return {
        "packets_summarized": packet_count, "malformed_rows": malformed_rows,
        "protocols": [{"protocol": name, "packets": count}
                      for name, count in protocols.most_common()],
        "unique_ip_endpoints": len(endpoints),
        "endpoints": [{"address": address, "source_packets": sources[address],
                       "destination_packets": destinations[address], "appearances": count}
                      for address, count in endpoints.most_common(100)],
        "endpoint_rows_truncated": len(endpoints) > 100,
    }


def run(args):
    path = Path(args.capture)
    result = {"status": "failed", "source": str(path)}
    if not path.is_file():
        return dict(result, error="Capture does not exist or is not a regular file")
    try:
        limit = _packet_limit(args.max_packets)
        timeout = _timeout(args.timeout)
    except (ValueError, TypeError, argparse.ArgumentTypeError) as error:
        return dict(result, error=str(error))
    executable = shutil.which("tshark")
    if not executable:
        return dict(result, error="tshark is not installed; install with: sudo apt install tshark")
    command = [
        executable, "-n", "-r", str(path.resolve()), "-c", str(limit),
        "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
        "-e", "frame.protocols", "-e", "ip.src", "-e", "ipv6.src",
        "-e", "ip.dst", "-e", "ipv6.dst",
    ]
    try:
        completed = subprocess.run(command, shell=False, capture_output=True, text=True,
                                   encoding="utf-8", errors="replace", timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        return dict(result, error="tshark exceeded the {} second runtime limit".format(timeout))
    except OSError as error:
        return dict(result, error="Unable to execute tshark: {}".format(error))
    result.update(summarize_rows(completed.stdout))
    result.update({
        "status": "completed" if completed.returncode == 0 else "failed",
        "max_packets": limit,
        "packet_limit_reached": result["packets_summarized"] >= limit,
        "limitations": [
            "Summaries cover only the first max-packets packets and only the supplied capture.",
            "Protocol counts overlap because a packet contains multiple protocol layers.",
            "Only the first occurrence of each IP field is counted; tunneled packets may contain more addresses.",
            "Endpoint appearances count both source and destination roles; only the top 100 endpoints are listed.",
            "No packet payloads, credentials, or live traffic are collected.",
        ],
    })
    if completed.returncode != 0:
        detail = completed.stderr.strip()[:2000]
        result["error"] = "tshark exited with code {}: {}".format(completed.returncode, detail or "no diagnostic output")
    elif result["malformed_rows"]:
        result["status"] = "partial"
        result["error"] = "Some tshark rows could not be parsed"
    return result
