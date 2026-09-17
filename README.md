# CEH Kali Toolkit

A Python toolkit for practical reconnaissance, host and service discovery, enumeration, and evidence reporting in Kali Linux. Each phase has its own command and produces structured results you can keep together in an engagement folder.

The toolkit covers the discovery and assessment work described below. It is not an implementation of every CEH topic or a complete vulnerability scanner. See the [phase guide](docs/phase-guide.md) for coverage and limitations.

## Install on Kali

```bash
git clone https://github.com/emerSahbi/ceh-kali-toolkit.git
cd ceh-kali-toolkit
bash scripts/install-kali.sh
python3 -m cehkit doctor
```

For a private repository, clone through an authenticated GitHub CLI session or an SSH key that has access to the repository. Do not put an account password or access token in a clone URL or a command saved to shell history.

The installer installs `python3`, `python3-dnspython`, and `nmap` through APT. Run commands from the repository directory. Python 3.9 or newer is required. To install dependencies manually:

```bash
sudo apt update
sudo apt install -y python3 python3-dnspython nmap
```

Optional offline packet capture analysis uses TShark:

```bash
bash scripts/install-kali.sh --with-tshark
```

This option installs TShark without changing packet capture privileges or adding users to groups. Existing capture files can be analyzed without enabling live capture.

To install the `cehkit` command in a virtual environment instead:

```bash
sudo apt install -y python3-venv nmap
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
cehkit doctor
```

If a privileged scan is needed from a virtual environment, use its interpreter explicitly, for example `sudo .venv/bin/python -m cehkit scan ...`.

## Commands by phase

| Phase | Command | Purpose |
| --- | --- | --- |
| Footprinting and reconnaissance | `recon DOMAIN` | DNS, registration information, website metadata, and published email addresses; optional subdomain discovery |
| Host and port discovery | `scan TARGET` | Nmap host discovery, TCP ports, and service information; optional UDP, OS hints, and traceroute |
| Service enumeration | `enumerate TARGET` | Selected Nmap scripts for web, SSH, FTP, SMTP, SMB, LDAP, RDP, MySQL, and NFS |
| Vulnerability review | `assess SCAN.xml` | Review saved Nmap results for exposed services and configuration indicators |
| Web and session posture | `web-audit URL` | Review HTTP response headers, cookies, and transport configuration |
| Traffic analysis | `traffic CAPTURE` | Summarize an existing packet capture using TShark |
| Local system review | `system-audit` | Inspect local Linux configuration for hardening indicators |
| Evidence integrity | `hash FILE` | Calculate SHA-256 or SHA-512 and optionally compare an expected digest |
| Reporting | `report REPORT.json ...` | Combine saved toolkit reports |
| Environment checks | `doctor` | Check the interpreter and supporting tools |

Use `python3 -m cehkit --help` and `python3 -m cehkit COMMAND --help` for the full interface. Every command accepts `-o PATH` / `--output PATH` for its JSON report.

Separate scripts are also available in `scripts/`: `recon.py`, `scan.py`, `enumerate.py`, `assess.py`, `web_audit.py`, `traffic.py`, `system_audit.py`, `hash.py`, and `report.py`. They use the same arguments as their corresponding commands. For example:

```bash
python3 scripts/recon.py www.test.test --registration-domain test.test
python3 scripts/scan.py 192.168.56.101 --top-ports 100
python3 scripts/enumerate.py 192.168.56.101 --services web,ssh,smb
```

## Example workflow

Replace the example domain, IP address, and subnet with your lab targets. `test.test` and `www.test.test` need a working lab DNS server; they are not public Internet domains.

```bash
# 1. Footprinting. The escaped input from the original script also works.
python3 -m cehkit recon 'www\.test.test' \
  --registration-domain test.test \
  -o reports/lab-recon.json

# Use a lab DNS server and optional candidate subdomains.
python3 -m cehkit recon test.test --nameserver 192.168.56.1 \
  --subdomains --max-subdomains 50 -o reports/lab-subdomains.json

# 2. Inspect a scan plan before contacting the target.
python3 -m cehkit scan 192.168.56.101 --top-ports 100 --dry-run

# 3. Scan a single host, then enumerate selected services.
python3 -m cehkit scan 192.168.56.101 \
  --ports 21,22,25,53,80,111,139,443,445,389,636,2049,3306,3389 \
  -o reports/lab-scan.json
python3 -m cehkit enumerate 192.168.56.101 \
  --services web,ssh,smb,ldap -o reports/lab-enumeration.json

# 4. Review the website and local Kali configuration.
python3 -m cehkit web-audit https://www.test.test -o reports/lab-web.json
python3 -m cehkit system-audit -o reports/kali-system.json

# 5. Combine the saved results.
python3 -m cehkit report reports/lab-recon.json reports/lab-scan.json \
  reports/lab-enumeration.json reports/lab-web.json \
  -o reports/lab-summary.json
```

Additional examples:

```bash
# Scan a bounded lab subnet.
python3 -m cehkit scan 192.168.56.0/24 --top-ports 100 --max-hosts 256

# Hosts that block discovery probes may need this option.
python3 -m cehkit scan 192.168.56.101 --skip-host-discovery

# UDP, OS detection, and traceroute require root privileges.
sudo python3 -m cehkit scan 192.168.56.101 \
  --udp --udp-top-ports 20 --os-detect --traceroute

# Inspect an existing Nmap XML file. Use the raw XML path from a scan report.
python3 -m cehkit assess /path/to/scan.xml -o reports/lab-review.json

# Analyze an existing capture and record its integrity hash.
python3 -m cehkit traffic /path/to/lab.pcapng --max-packets 10000
python3 -m cehkit hash /path/to/lab.pcapng --algorithm sha256
```

## Output and interpretation

The default output is a timestamped JSON report and a readable Markdown companion under `reports/`. An explicit `--output` must end in `.json`; the Markdown companion is written alongside it. Reusing an explicit destination replaces its previous report. Scans and enumeration also save raw Nmap artifacts in a timestamped directory beside their reports. Dry runs print their plans to the terminal without writing reports or contacting targets.

Reconnaissance contacts DNS, registration services, and the target website. Subdomain discovery and enumeration make additional requests. Published email discovery collects visible addresses; an address appearing in a page or record does not confirm that its mailbox exists. A successful command can contain individual lookup or service errors, so inspect the report as well as the command's exit status.

The default TCP scan uses Nmap connect scanning and does not require root. Subnet size, DNS and HTTP timeouts, page count, candidate count, and scan runtime are bounded by command options. Scan and enumeration accept `--host-timeout` and `--command-timeout` in seconds. `--dry-run` is available on `recon`, `scan`, and `enumerate` for reviewing work before network requests. Traffic analysis defaults to 10,000 packets and a 120-second runtime limit.

Findings from service banners, headers, and local settings are review indicators. A detected version or an open port alone does not prove a vulnerability. Firewall filtering, authentication, TLS failures, and insufficient local permissions can limit observations.

## Scope and data handling

Use the tools on systems covered by your lab or assessment scope. The toolkit focuses on discovery, configuration review, and reporting; it does not automate exploitation, persistence, or evidence deletion.

No GitHub credentials are stored by the toolkit. Generated reports, capture files, environment files, and common private-key formats are excluded by `.gitignore`. Keep actual target findings out of source commits even when the repository is private.

## Development

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -m unittest discover -s tests -v
```

CI runs the offline unit tests on Python 3.9, 3.12, and 3.13. It does not scan external targets. A Kali VM is still needed to validate the tools against your network, installed Nmap scripts, privilege settings, and lab services.
