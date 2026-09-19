# CEH Kali Toolkit

An all-in-one Python tool for reconnaissance, host and service discovery, enumeration, vulnerability checks, and evidence reporting in Kali Linux. Launch `cehkit` to choose a phase from an interactive menu, or use `cehkit run` for a combined assessment. Individual commands remain available for scripting.

The toolkit covers the discovery and assessment work described below. It is not an implementation of every CEH topic or a complete vulnerability scanner. See the [phase guide](docs/phase-guide.md) for coverage and limitations.

## Install on Kali

```bash
git clone https://github.com/emerSahbi/ceh-kali-toolkit.git
cd ceh-kali-toolkit
bash scripts/install-kali.sh --all
cehkit
```

For a private repository, clone through an authenticated GitHub CLI session or an SSH key that has access to the repository. Do not put an account password or access token in a clone URL or a command saved to shell history.

The installer installs Python, dnspython, and Nmap through APT, copies the application into `/opt/ceh-kali-toolkit/<version>`, and creates `/usr/local/bin/cehkit`. `--all` also installs Nikto and TShark for website scanning and capture analysis. The command works from any directory; reports are saved relative to your current directory. Python 3.9 or newer is required.

For core features only, omit `--all`. To update an existing installation, run `git pull` in the checkout and rerun the installer. Installed versions are snapshots of the checkout; older version directories are retained. You can also run `python3 -m cehkit` directly from the checkout without installing the launcher. To install core dependencies manually:

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
| Interactive menu | `menu` or just `cehkit` | Choose a phase and enter its settings interactively |
| Guided assessment | `run TARGET --type auto\|web\|host\|firewall\|tls` | Run applicable phases and produce one combined report |
| Footprinting and reconnaissance | `recon DOMAIN` | DNS, registration information, website metadata, and published email addresses; optional subdomain discovery |
| Host and port discovery | `scan TARGET` | Nmap host discovery, TCP ports, and service information; optional UDP, OS hints, and traceroute |
| Custom Nmap reconnaissance | `nmap TARGET` | Combine probe type, `-Pn`, fragmentation, timing, scripts, ports, OS/version detection, and output options |
| Service enumeration | `enumerate TARGET` | Selected Nmap scripts for web, SSH, FTP, SMTP, SMB, LDAP, RDP, MySQL, and NFS |
| Vulnerability review | `assess SCAN.xml` | Review saved Nmap results for exposed services and configuration indicators |
| Active vulnerability checks | `vuln TARGET --type web\|host\|firewall\|tls` | Run target-specific scanners and optionally compare firewall reachability with expected allowed ports |
| Web and session posture | `web-audit URL` | Review HTTP response headers, cookies, and transport configuration |
| Traffic analysis | `traffic CAPTURE` | Summarize an existing packet capture using TShark |
| Local system review | `system-audit` | Inspect local Linux configuration for hardening indicators |
| Evidence integrity | `hash FILE` | Calculate SHA-256 or SHA-512 and optionally compare an expected digest |
| Reporting | `report REPORT.json ...` | Combine saved toolkit reports |
| Environment checks | `doctor` | Check the interpreter and supporting tools |

Use `cehkit --help` and `cehkit COMMAND --help` for the full interface. Assessment commands accept `-o PATH` / `--output PATH` for their JSON reports. With no arguments, `cehkit` opens the menu in a terminal and prints help when input is redirected. `cehkit menu` explicitly opens the menu.

## One-command assessment

Choose menu option **1** or run:

```bash
cehkit run https://www.test.test --registration-domain test.test -o reports/website.json
cehkit run 192.168.56.101 --type host --ports 22,80,443 -o reports/server.json
cehkit run 192.168.56.1 --type firewall --allowed-tcp 80,443 --skip-host-discovery
cehkit run www.test.test --type tls --ports 8443
cehkit run https://www.test.test --dry-run
```

URLs select the web profile automatically; domains and IPs select the host profile unless you choose another type. Domains first receive reconnaissance. Host assessments then run service enumeration; every profile runs its selected vulnerability checks. The tool combines the phase results into JSON and Markdown, retaining individual reports and raw scanner output in a sibling directory. Missing tools or incomplete phases produce a nonzero exit status and remain visible in the combined report.

Firewall mode tests reachable services from your Kali machine and can compare them with the ports you expect to be allowed. It cannot infer a firewall's role or read its rules. Offline files, packet captures, hashes, and local system audits are separate menu choices because they need their own inputs. Subdomain discovery is optional under reconnaissance rather than automatically broadening a guided assessment.

Separate scripts are also available in `scripts/`: `recon.py`, `scan.py`, `enumerate.py`, `assess.py`, `web_audit.py`, `traffic.py`, `system_audit.py`, `hash.py`, and `report.py`. They use the same arguments as their corresponding commands. For example:

```bash
python3 scripts/recon.py www.test.test --registration-domain test.test
python3 scripts/scan.py 192.168.56.101 --top-ports 100
python3 scripts/enumerate.py 192.168.56.101 --services web,ssh,smb
```

## Vulnerability scans by target type

Update an existing checkout with `git pull`, then install the website scanner:

```bash
bash scripts/install-kali.sh --with-nikto

# A URL automatically selects the website profile.
python3 -m cehkit vuln https://www.test.test -o reports/web-vuln.json

# A server: selected Nmap vulnerability and configuration checks.
python3 -m cehkit vuln 192.168.56.101 --type host -o reports/host-vuln.json

# A firewall: inspect reachability from this machine and compare your policy.
python3 -m cehkit vuln 192.168.56.1 --type firewall \
  --ports 22,23,80,443,8080,8443 --allowed-tcp 80,443 \
  --skip-host-discovery -o reports/firewall-vuln.json

# A TLS service, including a nonstandard port.
python3 -m cehkit vuln www.test.test --type tls --ports 8443

# Preview selected commands without sending probes.
python3 -m cehkit vuln https://www.test.test --dry-run
```

The website profile runs Nikto's file/configuration/information/software/service/administration checks, plus Nmap HTTP/TLS checks and the built-in web audit. The host profile checks selected TLS issues, SMB MS17-010, SMB signing, and anonymous FTP where matching services are reachable. The TLS profile checks certificates, cipher/protocol support, Heartbleed and CCS injection.

The firewall profile checks selected TCP services and TLS exposure. `--allowed-tcp` is your expected list of reachable ports from this location; open ports outside it are reported as policy mismatches. Omit it for an exposure inventory, or use `--allowed-tcp none` when no tested TCP port should be reachable. This does not read appliance rules or automatically detect every vendor-specific firewall vulnerability. See [vulnerability scan details](docs/vulnerability-scanning.md) for coverage, defaults, and limitations.

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

The default TCP scan uses Nmap connect scanning and does not require root. Subnet size, DNS and HTTP timeouts, page count, candidate count, and scan runtime are bounded by command options. Scan and enumeration accept `--host-timeout` and `--command-timeout` in seconds. `--dry-run` is available on `run`, `recon`, `scan`, `enumerate`, and `vuln` for reviewing work before network requests. Traffic analysis defaults to 10,000 packets and a 120-second runtime limit.

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
