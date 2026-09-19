"""Interactive front door to the toolkit's existing command handlers."""
import shlex

OPTIONS = (
    ("1", "Guided assessment (recon + selected scans + report)", "run"),
    ("2", "Reconnaissance / footprinting", "recon"),
    ("3", "Host and port scanning", "scan"),
    ("4", "Service enumeration", "enumerate"),
    ("5", "Vulnerability / firewall / TLS checks", "vuln"),
    ("6", "Web headers and cookies", "web-audit"),
    ("7", "Review saved Nmap XML", "assess"),
    ("8", "Analyze a packet capture", "traffic"),
    ("9", "Local Linux system audit", "system-audit"),
    ("10", "Hash or verify a file", "hash"),
    ("11", "Combine saved reports", "report"),
    ("12", "Check installed tools", "doctor"),
)


def ask(label, default=None):
    suffix = " [{}]".format(default) if default is not None else ""
    value = input(label + suffix + ": ").strip()
    return value or (default if default is not None else "")


def yes(label, default=False):
    while True:
        value = ask(label + " (y/n)", "y" if default else "n").lower()
        if value in ("y", "yes", "n", "no"):
            return value in ("y", "yes")
        print("Enter y or n.")


def choose_type():
    while True:
        value = ask("Target type: auto, web, host, firewall, tls", "auto").lower()
        if value in ("auto", "web", "host", "firewall", "tls"):
            return value
        print("Choose one of the listed target types.")


def build_arguments(command):
    argv = [command]
    if command in ("run", "vuln"):
        kind = choose_type()
        target = ask("Target domain, IP, CIDR or website URL")
        if not target:
            raise ValueError("A target is required")
        argv += [target, "--type", kind]
        web = kind == "web" or (kind == "auto" and "://" in target)
        if not web:
            ports = ask("TCP ports (blank = profile defaults)")
            if ports:
                argv += ["--ports", ports]
        if kind == "firewall":
            allowed = ask("Expected reachable TCP ports (blank = inventory, none = no ports)")
            if allowed:
                argv += ["--allowed-tcp", allowed]
        if yes("Skip initial host discovery probes", False):
            argv.append("--skip-host-discovery")
        if command == "run":
            zone = ask("Registered domain / DNS zone (blank = automatic)")
            if zone:
                argv += ["--registration-domain", zone]
    elif command in ("scan", "enumerate"):
        argv.append(ask("Target domain, IP or CIDR"))
        ports = ask("TCP ports (blank = top 1000)")
        if ports:
            argv += ["--ports", ports]
        if command == "enumerate":
            argv += ["--services", ask("Services: all, or web,ssh,smb,ldap,ftp,smtp,rdp,mysql,nfs", "all")]
        if yes("Skip initial host discovery probes", False):
            argv.append("--skip-host-discovery")
    elif command == "recon":
        argv.append(ask("Domain name"))
        zone = ask("Registered domain / DNS zone (blank = automatic)")
        if zone:
            argv += ["--registration-domain", zone]
        if yes("Discover common subdomains", False):
            argv.append("--subdomains")
    elif command in ("web-audit", "assess", "traffic", "hash"):
        labels = {"web-audit": "HTTP(S) URL", "assess": "Nmap XML file", "traffic": "Capture file", "hash": "File to hash"}
        argv.append(ask(labels[command]))
        if command == "hash":
            argv += ["--algorithm", ask("Algorithm", "sha256")]
            expected = ask("Expected digest (blank = calculate only)")
            if expected:
                argv += ["--expected", expected]
    elif command == "report":
        print("Enter one report path per line. Press Enter on an empty line to finish.")
        while True:
            path = ask("Report JSON file")
            if not path:
                break
            argv.append(path)
        if len(argv) == 1:
            raise ValueError("At least one report is required")
    elif command == "system-audit":
        argv += ["--root", ask("Linux filesystem root", "/")]
    if command in ("run", "recon", "scan", "enumerate", "vuln") and yes("Preview commands only", False):
        argv.append("--dry-run")
    if "--dry-run" not in argv:
        output = ask("Output JSON path (blank = timestamped report)")
        if output:
            argv += ["-o", output]
    return argv


def run_menu(execute=None):
    if execute is None:
        from .cli import main
        execute = main
    from . import __version__
    choices = {key: command for key, _, command in OPTIONS}
    while True:
        print("\nCEH Kali Toolkit {}\n".format(__version__))
        for key, label, _ in OPTIONS:
            print("  {:>2}. {}".format(key, label))
        print("   0. Exit\n")
        try:
            choice = ask("Choose an option", "0")
            if choice in ("0", "q", "quit", "exit"):
                return 0
            if choice not in choices:
                print("Choose a listed option.")
                continue
            argv = build_arguments(choices[choice])
            print("\nCommand: cehkit " + " ".join(shlex.quote(x) for x in argv) + "\n")
            try:
                status = execute(argv)
            except SystemExit as error:
                status = error.code
            print("\nFinished (exit code {}). Reports are saved in the paths printed above.".format(status))
        except EOFError:
            print("\nInput closed.")
            return 0
        except KeyboardInterrupt:
            print("\nCancelled. Returning to menu.")
        except ValueError as error:
            print("Error: " + str(error))
