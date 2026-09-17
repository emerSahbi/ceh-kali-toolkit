"""Review existing Nmap evidence for service exposure and configuration risks."""

import argparse
import ipaddress
from pathlib import Path
import xml.etree.ElementTree as ET

from .footprint import parse_nmap


MAX_XML_BYTES = 32 * 1024 * 1024
DATABASE_SERVICES = {
    "mysql", "mysqlx", "postgresql", "ms-sql-s", "oracle", "oracle-tns",
    "mongodb", "redis", "memcached", "couchdb", "cassandra", "elasticsearch",
}
PLAINTEXT_SERVICES = {"ftp", "telnet", "rlogin", "login", "shell", "exec"}
OPTIONAL_TLS_SERVICES = {"smtp", "submission", "pop3", "imap"}


def register(subparsers):
    parser = subparsers.add_parser(
        "assess", help="Review existing Nmap XML for evidence of service exposure",
        description="Offline exposure review. Findings are observations and review items; "
                    "service banners alone do not establish vulnerabilities or CVEs.",
    )
    parser.add_argument("xml", type=Path, help="Existing Nmap XML report")
    parser.set_defaults(handler=run)
    return parser


def _address_scope(addresses):
    scopes = []
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        scopes.append("global" if parsed.is_global else "non-global")
    return "global" if "global" in scopes else "non-global" if scopes else "unknown"


def review(scan):
    """Return findings grounded in open-port and explicit NSE output evidence."""
    findings = []
    open_ports = 0
    for host in scan.get("hosts", []):
        addresses = [item.get("addr", "") for item in host.get("addresses", [])
                     if item.get("addrtype") in {"ipv4", "ipv6"}]
        hostnames = [item.get("name", "") for item in host.get("hostnames", [])]
        host_label = ", ".join(addresses or hostnames) or "unknown host"
        scope = _address_scope(addresses)
        for port in host.get("ports", []):
            if port.get("state", {}).get("state") != "open":
                continue
            open_ports += 1
            service = port.get("service", {})
            name = service.get("name", "unknown").lower()
            tunnel = service.get("tunnel", "").lower()
            endpoint = "{} {}/{}".format(host_label, port.get("port"), port.get("protocol"))
            base_evidence = {
                "host": host_label, "addresses": addresses,
                "address_scope": scope, "port": port.get("port"),
                "protocol": port.get("protocol"), "state": "open", "service": service,
            }

            def add(rule, title, detail, recommendation, evidence=None):
                findings.append({
                    "id": rule, "title": title, "severity": "review",
                    "endpoint": endpoint, "detail": detail,
                    "recommendation": recommendation,
                    "evidence": dict(base_evidence, **(evidence or {})),
                })

            if name in PLAINTEXT_SERVICES and tunnel not in {"ssl", "tls"}:
                add(
                    "plaintext-remote-service", "Remote service with plaintext capability",
                    "Nmap identified {} without a TLS tunnel. This observation does not "
                    "prove that credentials were transmitted or that optional TLS is disabled.".format(name),
                    "Verify encryption requirements and access controls; use an encrypted "
                    "alternative where plaintext authentication or content is permitted.",
                )
            elif name in OPTIONAL_TLS_SERVICES and tunnel not in {"ssl", "tls"}:
                add(
                    "mail-transport-encryption-review", "Mail service encryption requires review",
                    "Nmap identified {} without implicit TLS. STARTTLS support and enforcement "
                    "cannot be determined from this service entry.".format(name),
                    "Check STARTTLS support and require encryption before authentication.",
                )
            elif name == "http" and tunnel not in {"ssl", "tls"}:
                add(
                    "http-transport-review", "HTTP endpoint requires transport review",
                    "An HTTP service was reachable. Its redirects, content, and authentication "
                    "requirements have not been evaluated by this review.",
                    "Confirm sensitive content and authentication use HTTPS and review HTTP redirects.",
                )

            if name in DATABASE_SERVICES:
                add(
                    "database-exposure-review", "Database or data service reachable from scanner",
                    "Nmap identified {} on an open port (address scope: {}). Reachability "
                    "from the scan location does not establish Internet exposure, missing "
                    "authentication, or a confirmed vulnerability.".format(name, scope),
                    "Confirm the service is required, restrict allowed clients, and review "
                    "authentication, encryption, and patch status with the service owner.",
                )

            for script in port.get("scripts", []):
                output = script.get("output", "")
                if (script.get("id") == "ftp-anon"
                        and "anonymous ftp login allowed" in output.lower()):
                    add(
                        "anonymous-ftp-access", "Anonymous FTP login reported by Nmap",
                        "The ftp-anon script explicitly reported successful anonymous login. "
                        "Whether this access is intended requires review.",
                        "Confirm anonymous access is intentional and review permissions and exposed files.",
                        {"script": "ftp-anon", "output": output},
                    )
        for script in host.get("scripts", []):
            output = script.get("output", "")
            if (script.get("id") in {"smb-security-mode", "smb2-security-mode"}
                    and any(phrase in output.lower() for phrase in (
                        "message_signing: disabled", "message signing disabled",
                        "message signing enabled but not required",
                    ))):
                findings.append({
                    "id": "smb-signing-review", "title": "SMB signing requires review",
                    "severity": "review", "endpoint": host_label,
                    "detail": "Nmap reported SMB message signing disabled or not required.",
                    "recommendation": "Review compatibility and require SMB signing where supported.",
                    "evidence": {"host": host_label, "script": script.get("id"), "output": output},
                })
    return {
        "status": "completed", "hosts_reviewed": len(scan.get("hosts", [])),
        "open_ports_reviewed": open_ports, "findings": findings,
        "finding_count": len(findings),
        "limitations": [
            "This is an offline configuration and exposure review, not vulnerability validation.",
            "Nmap service identifications may be port-based guesses; review service evidence.",
            "No findings means no implemented review rules matched, not that the target is secure.",
            "Address scope does not prove public Internet reachability.",
        ],
    }


def run(args):
    path = Path(args.xml)
    try:
        if not path.is_file():
            raise ValueError("Nmap XML file does not exist or is not a regular file")
        if path.stat().st_size > MAX_XML_BYTES:
            raise ValueError("Nmap XML exceeds the 32 MiB input limit")
        # Nmap includes a harmless DOCTYPE; custom entity declarations are unnecessary.
        if b"<!ENTITY" in path.read_bytes().upper():
            raise ValueError("XML entity declarations are not accepted")
        tree = ET.parse(str(path))
        if tree.getroot().tag != "nmaprun":
            raise ValueError("XML root must be nmaprun")
        result = review(parse_nmap(path))
        result["source"] = str(path)
        return result
    except (OSError, ET.ParseError, ValueError, TypeError) as error:
        return {"status": "failed", "source": str(path), "error": str(error), "findings": []}
