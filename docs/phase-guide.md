# CEH phase guide

This guide maps the toolkit to practical lab activities. CEH spans more topics than a discovery toolkit can implement. The commands below produce observations for review and preserve evidence; they do not replace manual validation.

## 1. Reconnaissance and footprinting

```bash
python3 -m cehkit recon www.test.test --registration-domain test.test
python3 -m cehkit recon test.test --subdomains --wordlist candidates.txt \
  --max-subdomains 100 --max-pages 5 --timeout 5
```

Use a hostname or domain as the target. `www\.test.test` is normalized to `www.test.test`. `--registration-domain` identifies the domain to query for registration data when the website is a subdomain. Public registration services may redact contact data or have no entry for a private lab domain.

DNS observations include A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, DMARC, and reverse DNS records. TXT records can expose published SPF policies. Website observations include HTTP metadata, TLS information where available, robots.txt, sitemap.xml, security.txt, and published email addresses. Optional subdomain discovery checks candidate names and performs a wildcard probe; it is not guaranteed to discover every hostname. Wildcard DNS can make a candidate appear to exist.

`--nameserver IP` selects a DNS server for explicit DNS lookups. Website requests and TLS connections may still depend on the machine's resolver: configure Kali's DNS or hosts file so the lab website resolves there too. A hosts entry does not create MX, TXT, NS, or other DNS records.

Emails extracted from pages or public registration data are observed strings. The toolkit does not establish that each address belongs to a real, active mailbox.

## 2. Host discovery and scanning

```bash
python3 -m cehkit scan 192.168.56.0/24 --top-ports 100 --max-hosts 256
python3 -m cehkit scan 192.168.56.101 --ports 22,80,443,445
```

Targets can be domains, IP addresses, or bounded CIDR subnets. A default TCP connect scan can run as a regular user. Host discovery may miss systems whose network filters drop the probes; use `--skip-host-discovery` when a known in-scope host is being missed.

```bash
sudo python3 -m cehkit scan 192.168.56.101 \
  --udp --udp-top-ports 20 --os-detect --traceroute
```

Optional UDP, operating-system detection, and traceroute need root privileges. UDP can be slow and its `open|filtered` result is ambiguous. OS guesses depend on reachable ports and response characteristics. CIDR host bounds prevent accidentally treating an unexpectedly large subnet as a small lab target.

Control runtime with `--host-timeout SECONDS` and `--command-timeout SECONDS`. A timeout can leave partial results. Preserve the raw Nmap artifacts and read recorded errors before concluding that a service is absent.

## 3. Service enumeration

```bash
python3 -m cehkit enumerate 192.168.56.101 --services web,ssh,smb
python3 -m cehkit enumerate 192.168.56.101 --services all
```

Supported service groups are `web`, `ssh`, `ftp`, `smtp`, `smb`, `ldap`, `rdp`, `mysql`, and `nfs`. Enumeration selects Nmap scripts for service information and configuration observations. Results depend on open ports, installed Nmap scripts, the target's access controls, and responses to unauthenticated requests.

| Service group | Selected observations |
| --- | --- |
| `web` | HTTP title and headers; TLS certificates |
| `ssh` | Advertised SSH host keys |
| `ftp` | Anonymous FTP access and listing where allowed |
| `smtp` | Advertised SMTP commands |
| `smb` | OS hints, protocol versions, shares, and user information where allowed |
| `ldap` | LDAP root DSE metadata |
| `rdp` | RDP NTLM identity information |
| `mysql` | MySQL server greeting |
| `nfs` | RPC information and NFS export listing |

`--services` chooses TCP enumeration scripts, not the TCP port list. Use `--ports` for services on unusual ports. With `--udp`, enumeration also selects DNS recursion, SNMP, NTP, and RPC information scripts; the UDP selection is independent of `--services`.

Treat service identities and banners as observations. A hidden banner, disabled anonymous listing, or access-denied response is an expected result rather than proof that the service does not exist. FTP and SMB checks may establish anonymous or guest sessions; SMB user enumeration can generate multiple requests. Enumeration does not attempt to log into accounts using guessed passwords. SMTP checks retrieve advertised capabilities and do not verify email addresses.

Use `--dry-run` to see the planned work. Other scanning controls, including custom ports, host bounds, and runtime limits, also apply to enumeration.

## 4. Vulnerability review

```bash
python3 -m cehkit assess /path/to/scan.xml
```

Assessment reads an existing Nmap XML file and highlights service exposure and configuration indicators. It does not contact the scanned host. Preserve the source scan when evaluating findings.

These checks are a starting point for manual review. They do not provide exhaustive CVE matching, authenticated patch inventory, exploitation, or proof of impact. Confirm the actual software build and configuration before reporting a suspected weakness as a verified vulnerability.

## 5. Web and session posture

```bash
python3 -m cehkit web-audit https://www.test.test --timeout 5
```

The web review inspects the response available at the supplied URL, including headers, cookies, and transport-related observations. Findings are specific to that response and its context. A cookie attribute check cannot determine whether the whole authentication or session management flow is secure.

The command does not replace a full web application assessment. Business logic, authorization, account recovery, browser behavior, and server-side input handling require additional review.

## 6. Traffic analysis

```bash
python3 -m cehkit traffic /path/to/lab.pcapng --max-packets 10000 --timeout 60
```

The command uses TShark to read an existing capture and summarize the protocols and IP endpoints in the packets it analyzes. Install it with `bash scripts/install-kali.sh --with-tshark`. Defaults are 10,000 packets and 120 seconds; the example above overrides the runtime to 60 seconds. Packet and runtime limits keep analysis bounded, so the summary may cover only part of a large capture.

Captures can contain sensitive network information. The repository ignores common capture extensions. This command does not start a live packet capture, change interface settings, or decrypt encrypted application traffic.

## 7. Local system hardening

```bash
python3 -m cehkit system-audit
python3 -m cehkit system-audit --root /path/to/mounted-root
```

Local checks review Linux settings available to the current user. `--root` selects a filesystem tree for supported configuration checks; it is useful with a mounted lab filesystem. Observations can be incomplete when files are absent or unreadable.

The report provides hardening indicators. It does not modify system configuration, establish runtime state for an offline filesystem, or guarantee that configuration files match effective daemon settings.

## 8. Evidence integrity

```bash
python3 -m cehkit hash /path/to/lab.pcapng --algorithm sha256
python3 -m cehkit hash /path/to/lab.pcapng --algorithm sha512 --expected DIGEST
```

Replace `DIGEST` with a previously recorded hash. Store digests and collection notes with the report. A matching digest establishes that the bytes match the expected digest; it does not establish the origin, trustworthiness, or chain of custody of the file by itself.

## 9. Reporting

```bash
python3 -m cehkit report reports/recon.json reports/scan.json reports/web.json \
  --output reports/combined.json
```

Each phase writes JSON for later processing and Markdown for reading. Combining reports provides a shared record of collected results; review individual failures, timestamps, target scope, and source evidence before making conclusions.

Use separate output directories for unrelated labs. Default reports and raw artifacts are excluded from Git. If you intentionally publish an example report, remove real target data and credentials first.

## Topics outside this toolkit

This release does not automate social engineering, malware creation, denial of service, credential attacks, exploitation, persistence, or removal of logs. Wireless, mobile, cloud, container, and IoT security need platform-specific labs and tools. The toolkit's local configuration and integrity checks support defensive study but do not implement every activity associated with those CEH topics.

For each exercise, document the authorized target range, the command used, what was observed, what remains uncertain, and the next manual validation step. Keeping those distinctions clear makes the output useful as assessment evidence.
