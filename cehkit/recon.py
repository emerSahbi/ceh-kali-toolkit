"""Footprinting phase, with independently selectable DNS name discovery."""
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
from pathlib import Path
from . import footprint
from .common import positive_float, positive_int


def register(subparsers):
    parser = subparsers.add_parser("recon", help="DNS, registration, public web and email footprinting")
    parser.add_argument("target", type=footprint.domain_name)
    parser.add_argument("--registration-domain", type=footprint.domain_name)
    parser.add_argument("--nameserver", type=lambda value: str(ipaddress.ip_address(value)))
    parser.add_argument("--timeout", type=positive_float, default=5)
    parser.add_argument("--subdomains", action="store_true")
    parser.add_argument("--wordlist", type=Path)
    parser.add_argument("--max-subdomains", type=positive_int, default=100)
    parser.add_argument("--max-pages", type=positive_int, default=5)
    parser.add_argument("--dry-run", action="store_true")
    parser.set_defaults(handler=run)


def collection_errors(name, value):
    """Separate expected absent DNS records from operational collection failures."""
    if value.get("error"):
        return [value["error"]]
    errors = []
    if name in ("dns", "zone_dns"):
        for group in ("records", "reverse_dns"):
            for key, record in value.get(group, {}).items():
                if isinstance(record, dict) and record.get("error"):
                    error = record["error"]
                    if error.split(":", 1)[0] not in ("NXDOMAIN", "NoAnswer"):
                        errors.append("{}: {}".format(key, error))
    elif name == "whois":
        errors.extend(item["error"] for item in value.get("responses", []) if item.get("error"))
    elif name == "website":
        pages = value.get("pages", {})
        observations = pages.values() if pages else value.get("attempts", [])
        errors.extend(item["error"] for item in observations if item.get("error"))
    elif name == "subdomains":
        for item in value.get("errors", []) + [value.get("wildcard_probe", {})]:
            errors.extend(item.get("errors", []))
    return errors


def run(args):
    if args.wordlist and not args.wordlist.is_file():
        raise ValueError("Subdomain wordlist does not exist")
    zone = args.registration_domain or (args.target[4:] if args.target.startswith("www.") else args.target)
    jobs = {
        "dns": (footprint.dns_lookup, args.target, args.timeout, args.nameserver),
        "whois": (footprint.whois_lookup, zone, args.timeout),
        "rdap": (footprint.rdap_lookup, zone, args.timeout),
        "website": (footprint.website_lookup, args.target, args.timeout, args.max_pages),
        "tls": (footprint.tls_lookup, args.target, args.timeout),
    }
    if zone != args.target:
        jobs["zone_dns"] = (footprint.dns_lookup, zone, args.timeout, args.nameserver)
    if args.subdomains or args.wordlist:
        jobs["subdomains"] = (footprint.subdomain_lookup, zone, args.timeout, args.nameserver, args.wordlist, args.max_subdomains)
    if args.dry_run:
        return {"target": args.target, "registration_domain": zone, "modules": list(jobs), "dry_run": True}
    result = {"target": args.target, "registration_domain": zone}
    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(footprint.capture, *job): name for name, job in jobs.items()}
        for future in as_completed(futures):
            name = futures[future]
            result[name] = future.result()
            print("Collected " + name, flush=True)
    result["published_emails"] = footprint.emails_from(result)
    result["module_errors"] = {name: errors for name in jobs
                               for errors in [collection_errors(name, result[name])] if errors}
    result["status"] = "completed_with_errors" if result["module_errors"] else "completed"
    return result
