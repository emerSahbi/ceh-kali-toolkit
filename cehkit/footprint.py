#!/usr/bin/env python3
"""Kali-compatible footprinting, host discovery, and service enumeration."""
import argparse
import concurrent.futures
import html
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.error import HTTPError
from urllib.parse import urlsplit, urljoin, urldefrag, quote
from urllib.request import Request, urlopen, build_opener, HTTPRedirectHandler

MAX_BYTES = 1024 * 1024
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}")


def domain_name(value):
    value = value.strip().replace(r"\.", ".").rstrip(".")
    if "://" in value:
        raise argparse.ArgumentTypeError("Enter a domain name, without a URL scheme or path")
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise argparse.ArgumentTypeError("Invalid international domain name")
    if len(value) > 253 or "." not in value or any(
        not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
        for label in value.split(".")
    ):
        raise argparse.ArgumentTypeError("Invalid domain name")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise argparse.ArgumentTypeError("Enter a domain, not an IP address")


def capture(function, *args):
    try:
        return function(*args)
    except Exception as error:
        return {"error": "{}: {}".format(type(error).__name__, error)}


def dns_lookup(domain, timeout, nameserver=None):
    try:
        import dns.resolver
        import dns.reversename
    except ImportError:
        return {"error": "DNS collection requires: python -m pip install dnspython"}
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    records = {}
    queries = [(domain, kind) for kind in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")]
    queries.append(("_dmarc." + domain, "TXT"))
    for name, kind in queries:
        key = "{} {}".format(name, kind)
        records[key] = capture(lambda: [r.to_text() for r in resolver.resolve(name, kind, lifetime=timeout, search=False)])
    reverse = {}
    for kind in ("A", "AAAA"):
        addresses = records.get("{} {}".format(domain, kind), [])
        if isinstance(addresses, list):
            for address in addresses:
                reverse[address] = capture(lambda: [r.to_text() for r in resolver.resolve(dns.reversename.from_address(address), "PTR", lifetime=timeout)])
    return {"records": records, "reverse_dns": reverse}


def whois_query(server, domain, timeout):
    deadline = time.monotonic() + timeout
    chunks = []
    size = 0
    with socket.create_connection((server, 43), timeout=timeout) as connection:
        connection.sendall((domain + "\r\n").encode("ascii"))
        while size < MAX_BYTES:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("WHOIS response deadline exceeded")
            connection.settimeout(remaining)
            chunk = connection.recv(min(65536, MAX_BYTES - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    return {"server": server, "text": b"".join(chunks).decode("utf-8", "replace"), "possibly_truncated": size == MAX_BYTES}


def whois_lookup(domain, timeout):
    responses = [whois_query("whois.iana.org", domain.rsplit(".", 1)[-1], timeout)]
    referral = re.search(r"^refer:\s*(\S+)", responses[0]["text"], re.M | re.I)
    if not referral:
        return {"responses": responses, "error": "No WHOIS server published by IANA for this suffix"}
    server = referral.group(1)
    for _ in range(2):
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", server):
            break
        result = capture(whois_query, server, domain, timeout)
        responses.append(result)
        if "error" in result:
            break
        referral = re.search(r"^(?:Registrar WHOIS Server|whois):\s*(\S+)", result["text"], re.M | re.I)
        if not referral or referral.group(1).lower() in {r.get("server", "").lower() for r in responses}:
            break
        server = referral.group(1)
    return {"responses": responses}


class SameHostRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        original, redirected = urlsplit(request.full_url), urlsplit(newurl)
        if redirected.scheme not in ("http", "https") or original.hostname != redirected.hostname:
            raise ValueError("Redirect outside target host blocked: " + newurl)
        return super().redirect_request(request, fp, code, msg, headers, newurl)


def fetch(url, timeout, same_host=False):
    request = Request(url, headers={"User-Agent": "DomainFootprint/1.0", "Accept-Encoding": "identity"})
    try:
        response = (build_opener(SameHostRedirect()).open(request, timeout=timeout)
                    if same_host else urlopen(request, timeout=timeout))
    except HTTPError as error:
        response = error
    with response:
        data = response.read(MAX_BYTES + 1)
        encoding = response.headers.get_content_charset() or "utf-8"
        try:
            body = data[:MAX_BYTES].decode(encoding, "replace")
        except LookupError:
            body = data[:MAX_BYTES].decode("utf-8", "replace")
        title = re.search(r"<title\b[^>]*>(.*?)</title>", body, re.I | re.S)
        return {"requested_url": url, "final_url": response.geturl(), "status": response.status,
                "headers": dict(response.headers.items()), "title": html.unescape(title.group(1).strip()) if title else None,
                "body": body, "truncated": len(data) > MAX_BYTES}


class PageLinks(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self.links.extend(value for name, value in attrs if name == "href" and value)


def website_lookup(domain, timeout, max_pages=5):
    attempts = []
    for scheme in ("https", "http"):
        root = scheme + "://" + ("[" + domain + "]" if ":" in domain else domain)
        page = capture(fetch, root + "/", timeout, True)
        attempts.append(page)
        if "error" not in page:
            pages = {"homepage": page}
            for path in ("robots.txt", "sitemap.xml", ".well-known/security.txt"):
                pages[path] = capture(fetch, root + "/" + path, timeout, True)
            queue = [page]
            visited = {p.get("final_url") for p in pages.values()}
            while queue and len([k for k in pages if k.startswith("linked_")]) < max_pages - 1:
                current = queue.pop(0)
                links = PageLinks()
                links.feed(current.get("body", ""))
                for link in links.links:
                    url = urldefrag(urljoin(current["final_url"], link))[0]
                    parsed = urlsplit(url)
                    if (parsed.scheme not in ("http", "https") or parsed.hostname != domain
                            or parsed.username or parsed.password or parsed.query or url in visited):
                        continue
                    if Path(parsed.path).suffix.lower() in (".pdf", ".zip", ".jpg", ".png", ".mp4", ".exe", ".svg"):
                        continue
                    visited.add(url)
                    result = capture(fetch, url, timeout, True)
                    pages["linked_" + str(len(pages))] = result
                    content_type = next((v for k, v in result.get("headers", {}).items() if k.lower() == "content-type"), "")
                    if "error" not in result and "text/html" in content_type.lower():
                        queue.append(result)
                    if len([k for k in pages if k.startswith("linked_")]) >= max_pages - 1:
                        break
            return {"attempts": attempts, "pages": pages}
    return {"attempts": attempts}


def tls_lookup(domain, timeout):
    context = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as connection:
            return {"version": connection.version(), "cipher": connection.cipher(), "certificate": connection.getpeercert()}


def emails_from(report):
    found = {}
    sources = []
    for item in report.get("whois", {}).get("responses", []):
        sources.append(("whois:" + item.get("server", "unknown"), item.get("text", "")))
    for item in report.get("website", {}).get("pages", {}).values():
        sources.append((item.get("final_url", "unknown"), item.get("body", "")))
    for source, text in sources:
        for address in EMAIL.findall(html.unescape(text)):
            found.setdefault(address, set()).add(source)
    return [{"address": address, "sources": sorted(sources)} for address, sources in sorted(found.items())]


ENUM_SCRIPTS = (
    "http-title,http-headers,ssl-cert,ssh-hostkey,ftp-anon,smtp-commands,"
    "smb-os-discovery,smb-protocols,smb-enum-shares,smb-enum-users,"
    "ldap-rootdse,rdp-ntlm-info,mysql-info,rpcinfo,nfs-showmount"
)
COMMON_NAMES = "www mail webmail smtp pop imap ns1 ns2 ftp vpn remote portal intranet dev staging test api admin".split()
UDP_SCRIPTS = "dns-recursion,snmp-info,ntp-info,rpcinfo"


def target_value(value):
    value = value.strip()
    try:
        return str(ipaddress.ip_network(value, strict=False) if "/" in value else ipaddress.ip_address(value))
    except ValueError:
        return domain_name(value)


def port_list(value):
    if value == "-":
        return value
    for part in value.split(","):
        if not re.fullmatch(r"\d+(?:-\d+)?", part):
            raise argparse.ArgumentTypeError("Ports must be e.g. 22,80,443 or 1-65535 or -")
        ends = [int(p) for p in part.split("-")]
        if not all(1 <= p <= 65535 for p in ends) or ends[0] > ends[-1]:
            raise argparse.ArgumentTypeError("Invalid port range")
    return value


def rdap_lookup(domain, timeout):
    response = fetch("https://rdap.org/domain/" + quote(domain), timeout)
    if response["status"] != 200:
        return {"status": response["status"], "error": "RDAP lookup failed"}
    return {"url": response["final_url"], "record": json.loads(response["body"])}


def subdomain_lookup(domain, timeout, nameserver, wordlist, limit):
    import dns.resolver
    resolver = dns.resolver.Resolver()
    if nameserver:
        resolver.nameservers = [nameserver]
    words = COMMON_NAMES
    if wordlist:
        with open(wordlist, encoding="utf-8") as stream:
            words = []
            for line in stream:
                label = line.strip().lower()
                if label and not label.startswith("#"):
                    words.append(label)
                if len(words) >= limit:
                    break
    candidates = []
    for word in words[:limit]:
        candidates.append(domain_name(word + "." + domain))

    def resolve(name):
        addresses, errors = set(), []
        for kind in ("A", "AAAA"):
            try:
                addresses.update(r.to_text() for r in resolver.resolve(name, kind, lifetime=timeout, search=False))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                pass
            except Exception as error:
                errors.append(str(error))
        return {"name": name, "addresses": sorted(addresses), "errors": errors}

    wildcard = resolve("probe-" + uuid.uuid4().hex + "." + domain)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(resolve, dict.fromkeys(candidates)))
    return {"zone": domain, "tested": len(results), "wildcard_probe": wildcard,
            "note": "Wildcard DNS can produce false positives; discovered names are not automatically port scanned.",
            "found": [r for r in results if r["addresses"]],
            "errors": [r for r in results if r["errors"]]}


def parse_nmap(path):
    root = ET.parse(str(path)).getroot()
    hosts = []
    for node in root.findall("host"):
        host = {"status": node.find("status").attrib if node.find("status") is not None else {},
                "addresses": [x.attrib for x in node.findall("address")],
                "hostnames": [x.attrib for x in node.findall("hostnames/hostname")], "ports": [],
                "scripts": [x.attrib for x in node.findall("hostscript/script")],
                "os_matches": [x.attrib for x in node.findall("os/osmatch")],
                "trace": [x.attrib for x in node.findall("trace/hop")]}
        for port in node.findall("ports/port"):
            state, service = port.find("state"), port.find("service")
            host["ports"].append({"port": int(port.get("portid")), "protocol": port.get("protocol"),
                                  "state": state.attrib if state is not None else {},
                                  "service": service.attrib if service is not None else {},
                                  "scripts": [x.attrib for x in port.findall("script")]})
        hosts.append(host)
    finished = root.find("runstats/finished")
    return {"hosts": hosts, "finished": finished.attrib if finished is not None else {}}


def nmap_commands(args, artifact_dir):
    common = ["nmap", "-n", "-T3", "--max-retries", "2", "--host-timeout", str(args.host_timeout) + "s"]
    if ":" in args.target:
        common.append("-6")
    if args.nameserver:
        common += ["--dns-servers", args.nameserver]
    commands = [("host_discovery", common + ["-sn", "-oA", str(artifact_dir / "hosts"), args.target])]
    scan = common + ["-sT", "-sV", "--version-light"]
    if args.skip_host_discovery:
        scan += ["-Pn"]
    scan += ["-p", args.ports] if args.ports else ["--top-ports", str(args.top_ports)]
    if args.profile == "full":
        scan += ["--script", ENUM_SCRIPTS, "--script-timeout", "30s"]
    if args.os_detect:
        scan += ["-O", "--osscan-limit"]
    if args.traceroute:
        scan += ["--traceroute"]
    commands.append(("tcp_services", scan + ["-oA", str(artifact_dir / "tcp"), args.target]))
    if args.udp:
        udp = common + ["-sU", "-sV", "--version-light", "--top-ports", str(args.udp_top_ports)]
        if args.skip_host_discovery:
            udp.append("-Pn")
        if args.profile == "full":
            udp += ["--script", UDP_SCRIPTS, "--script-timeout", "30s"]
        commands.append(("udp_services", udp + ["-oA", str(artifact_dir / "udp"), args.target]))
    return commands


def execute_nmap(command, timeout):
    if not shutil.which(command[0]):
        return {"command": command, "error": "nmap is missing. On Kali: sudo apt install nmap"}
    prefix = Path(command[command.index("-oA") + 1])
    result = {"command": command, "artifacts": {ext: str(prefix.with_suffix("." + ext)) for ext in ("nmap", "xml", "gnmap")}}
    log = prefix.with_suffix(".log")
    try:
        with log.open("w", encoding="utf-8") as output:
            completed = subprocess.run(command, stdout=output, stderr=subprocess.STDOUT, timeout=timeout, check=False)
        result["returncode"] = completed.returncode
        if completed.returncode:
            result["error"] = "Nmap returned {}; inspect the log".format(completed.returncode)
    except subprocess.TimeoutExpired:
        result["error"] = "Command timed out after {} seconds; raw output may be partial".format(timeout)
    result["log"] = str(log)
    if prefix.with_suffix(".xml").exists():
        result["results"] = capture(parse_nmap, prefix.with_suffix(".xml"))
    return result


def save_report(report, output):
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    temporary.replace(output)
    lines = ["# Discovery report", "", "Target: `{}`".format(report["target"]), "", "Profile: " + report["profile"], ""]
    for name, result in report.items():
        if isinstance(result, dict) and "error" in result:
            lines.append("- {}: {}".format(name, result["error"]))
    for name, scan in report.get("scans", {}).items():
        lines += ["", "## " + name, ""]
        if scan.get("error"):
            lines.append(scan["error"])
        for host in scan.get("results", {}).get("hosts", []):
            addresses = ", ".join(x.get("addr", "") for x in host["addresses"])
            lines += ["", "Host: " + addresses + " (" + host["status"].get("state", "unknown") + ")", ""]
            for port in host["ports"]:
                if port["state"].get("state") in ("open", "open|filtered"):
                    service = port["service"]
                    lines.append("- {}/{} {}: {} {} {}".format(port["port"], port["protocol"], port["state"].get("state"), service.get("name", ""), service.get("product", ""), service.get("version", "")))
    lines += ["", "## Published emails", ""]
    lines.extend("- " + item["address"] for item in report.get("published_emails", []))
    lines += ["", "Full evidence, lookup failures, commands, and enumeration output are in the JSON and Nmap artifacts.", ""]
    output.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target", nargs="?", type=target_value, help="Domain, IP address, or CIDR")
    parser.add_argument("--profile", choices=("footprint", "discover", "full"), default="footprint")
    parser.add_argument("--registration-domain", type=domain_name, help="Registered domain / DNS zone, e.g. example.co.uk")
    parser.add_argument("--nameserver", type=lambda v: str(ipaddress.ip_address(v)), help="DNS server IP; configure system DNS too for web/TLS resolution")
    parser.add_argument("--timeout", type=float, default=5, help="Per lookup/socket timeout")
    parser.add_argument("--command-timeout", type=int, default=900, help="Maximum seconds per Nmap command")
    parser.add_argument("--host-timeout", type=int, default=180, help="Nmap maximum seconds per host")
    parser.add_argument("--ports", type=port_list, help="TCP ports: 22,80,443 or 1-65535 or -")
    parser.add_argument("--top-ports", type=int, default=1000, help="Most common TCP ports, unless --ports is set")
    parser.add_argument("--skip-host-discovery", action="store_true", help="Use -Pn for port scans when ping probes are blocked")
    parser.add_argument("--udp", action="store_true", help="Add UDP scan; requires root on Kali")
    parser.add_argument("--udp-top-ports", type=int, default=20)
    parser.add_argument("--os-detect", action="store_true", help="Add OS fingerprinting; requires root on Kali")
    parser.add_argument("--traceroute", action="store_true", help="Add Nmap traceroute; requires root on Kali")
    parser.add_argument("--subdomains", action="store_true", help="Resolve common DNS names; included in full profile")
    parser.add_argument("--wordlist", type=Path, help="Subdomain labels, one per line; enables subdomain discovery")
    parser.add_argument("--max-subdomains", type=int, default=100, help="Maximum wordlist candidates")
    parser.add_argument("--max-pages", type=int, default=5, help="Homepage plus linked pages; metadata paths are additional")
    parser.add_argument("--max-hosts", type=int, default=256, help="Maximum addresses allowed in a CIDR target")
    parser.add_argument("--dry-run", action="store_true", help="Print module and Nmap plans without network traffic")
    parser.add_argument("-o", "--output", type=Path, help="JSON report path; Markdown and raw artifacts are saved alongside")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.target is None:
        try:
            args.target = target_value(input("Target domain, IP, or CIDR: "))
        except (ValueError, argparse.ArgumentTypeError) as error:
            parser.error(str(error))
    for name in ("timeout", "command_timeout", "host_timeout", "top_ports", "udp_top_ports", "max_subdomains", "max_pages", "max_hosts"):
        value = getattr(args, name)
        if not math.isfinite(value) or value <= 0:
            parser.error("--{} must be positive and finite".format(name.replace("_", "-")))
    if args.top_ports > 65535 or args.udp_top_ports > 65535:
        parser.error("Port counts cannot exceed 65535")
    if args.wordlist and not args.wordlist.is_file():
        parser.error("Subdomain wordlist does not exist")
    try:
        network = ipaddress.ip_network(args.target, strict=False)
        is_domain = False
    except ValueError:
        network, is_domain = None, True
    is_subnet = "/" in args.target
    if is_subnet and network.num_addresses > args.max_hosts:
        parser.error("CIDR contains {} addresses; --max-hosts is {}".format(network.num_addresses, args.max_hosts))
    if args.profile == "footprint" and (is_subnet or args.udp or args.os_detect or args.traceroute or args.ports or args.skip_host_discovery):
        parser.error("CIDRs and scan options require --profile discover or --profile full")
    if not is_domain and (args.subdomains or args.wordlist or args.registration_domain):
        parser.error("DNS zone and subdomain options require a domain target")
    if (args.udp or args.os_detect or args.traceroute) and not args.dry_run and hasattr(os, "geteuid") and os.geteuid() != 0:
        parser.error("UDP, OS detection, and traceroute require root; run with sudo or omit these options")
    zone = args.registration_domain or (args.target[4:] if args.target.startswith("www.") else args.target)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = (args.output or Path("reports") / (re.sub(r"[^a-zA-Z0-9.-]", "_", args.target) + "_" + stamp + ".json")).absolute()
    if output.suffix.lower() != ".json":
        parser.error("Output path must end in .json")
    artifact_dir = output.parent / (output.stem + "_artifacts_" + stamp)
    jobs = {}
    if not is_subnet:
        jobs.update({"website": (website_lookup, args.target, args.timeout, args.max_pages), "tls": (tls_lookup, args.target, args.timeout)})
    if is_domain:
        jobs.update({"dns": (dns_lookup, args.target, args.timeout, args.nameserver),
                     "whois": (whois_lookup, zone, args.timeout), "rdap": (rdap_lookup, zone, args.timeout)})
        if zone != args.target:
            jobs["zone_dns"] = (dns_lookup, zone, args.timeout, args.nameserver)
        if args.subdomains or args.wordlist or args.profile == "full":
            jobs["subdomains"] = (subdomain_lookup, zone, args.timeout, args.nameserver, args.wordlist, args.max_subdomains)
    commands = nmap_commands(args, artifact_dir) if args.profile != "footprint" else []
    if args.dry_run:
        print(json.dumps({"target": args.target, "modules": list(jobs), "commands": {k: v for k, v in commands}, "output": str(output)}, indent=2))
        return
    report = {"target": args.target, "profile": args.profile, "registration_domain": zone if is_domain else None,
              "collected_at": datetime.now(timezone.utc).isoformat(), "status": "running", "scans": {}}
    save_report(report, output)
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(capture, *job): name for name, job in jobs.items()}
            for future in concurrent.futures.as_completed(futures):
                name = futures[future]
                report[name] = future.result()
                print("Collected {}{}".format(name, " (see error in report)" if "error" in report[name] else ""), flush=True)
                save_report(report, output)
        report["published_emails"] = emails_from(report)
        if commands:
            artifact_dir.mkdir(parents=True, exist_ok=True)
        for name, command in commands:
            print("Running: " + " ".join(shlex.quote(x) for x in command), flush=True)
            report["scans"][name] = capture(execute_nmap, command, args.command_timeout)
            save_report(report, output)
        report["status"] = "completed"
    except KeyboardInterrupt:
        report["status"] = "interrupted"
        print("Interrupted; saving completed modules.")
    finally:
        report["published_emails"] = emails_from(report)
        save_report(report, output)
    print("Saved {} and {}".format(output, output.with_suffix(".md")))


if __name__ == "__main__":
    main()
