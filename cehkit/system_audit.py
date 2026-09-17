"""Read-only, bounded local Linux configuration and permission observations."""

import platform
import shlex
import stat
from pathlib import Path


INSPECT_PATHS = (
    "etc/passwd", "etc/group", "etc/shadow", "etc/gshadow",
    "etc/sudoers", "etc/ssh/sshd_config", "tmp", "var/tmp",
)
SSH_DIRECTIVES = {
    "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
    "permitemptypasswords", "x11forwarding", "maxauthtries", "allowtcpforwarding",
    "authenticationmethods", "loglevel", "usepam",
}


def local_path(root, relative):
    """Return an in-root path; do not follow intermediate symlinks."""
    root = Path(root).resolve()
    if Path(relative).is_absolute() or Path(relative).drive:
        raise ValueError("Expected a relative path inside the audit root")
    candidate = root
    for part in Path(relative).parts:
        if part in ("..", "/", "\\"):
            raise ValueError("Expected a relative path inside the audit root")
        candidate = candidate / part
        if candidate != root / relative and candidate.is_symlink():
            raise ValueError("Intermediate symlink was not followed")
    return candidate


def inspect_permissions(root, relative):
    entry = {"path": "/" + relative.replace("\\", "/")}
    try:
        path = local_path(root, relative)
        info = path.lstat()
    except FileNotFoundError:
        return dict(entry, status="missing")
    except (OSError, ValueError) as exc:
        return dict(entry, status="unavailable", error=type(exc).__name__)
    if stat.S_ISLNK(info.st_mode):
        return dict(entry, status="symlink", note="Symlink was not followed")
    mode = stat.S_IMODE(info.st_mode)
    entry.update({"status": "ok", "mode": format(mode, "04o"), "owner_uid": info.st_uid, "group_gid": info.st_gid, "findings": []})
    findings = entry["findings"]
    if stat.S_ISREG(info.st_mode) and mode & stat.S_IWOTH:
        findings.append("File is writable by other users")
    if relative in ("etc/shadow", "etc/gshadow", "etc/sudoers") and mode & stat.S_IROTH:
        findings.append("Sensitive configuration is readable by other users")
    if relative.startswith("etc/") and mode & stat.S_IWGRP:
        findings.append("Configuration is writable by its group; review group membership")
    if stat.S_ISDIR(info.st_mode) and mode & stat.S_IWOTH and not mode & stat.S_ISVTX:
        findings.append("Directory is writable by other users and lacks the sticky bit")
    return entry


def inspect_sshd(root):
    result = {"path": "/etc/ssh/sshd_config", "status": "ok", "directives": [], "include_present": False, "findings": []}
    result["limitation"] = "Only explicit directives in this file are shown. Includes, defaults, command-line overrides and Match evaluation are not resolved; this is not the effective sshd configuration."
    try:
        path = local_path(root, "etc/ssh/sshd_config")
        if path.is_symlink():
            return dict(result, status="symlink", note="Symlink was not followed")
        if not path.is_file():
            return dict(result, status="missing")
        with path.open("r", encoding="utf-8", errors="replace") as stream:
            source = stream.read(65537)
        result["truncated"] = len(source) > 65536
        source = source[:65536]
        if result["truncated"]:
            # Do not treat a partially read last directive as a complete observation.
            source = source.rsplit("\n", 1)[0] if "\n" in source else ""
    except (OSError, ValueError) as exc:
        return dict(result, status="unavailable", error=type(exc).__name__)
    context = "global"
    first_global = set()
    for number, line in enumerate(source.splitlines(), 1):
        try:
            tokens = shlex.split(line, comments=True)
        except ValueError:
            continue
        if not tokens:
            continue
        key = tokens[0].lower()
        if key == "include":
            result["include_present"] = True
            continue
        if key == "match":
            context = "conditional"
            continue
        if key not in SSH_DIRECTIVES or len(tokens) < 2:
            continue
        value = " ".join(tokens[1:])
        first = context == "global" and key not in first_global
        if context == "global":
            first_global.add(key)
        result["directives"].append({"name": key, "value": value, "line": number, "context": context, "first_global_in_file": first})
        if key == "permitemptypasswords" and value.lower() == "yes":
            result["findings"].append({"line": number, "message": "An explicit directive permits empty passwords; whether it applies depends on the full sshd configuration"})
        elif key == "permitrootlogin" and value.lower() == "yes":
            result["findings"].append({"line": number, "message": "An explicit directive permits root login; whether it applies depends on the full sshd configuration"})
    return result


def audit_system(root="/"):
    path = Path(root).expanduser().resolve()
    if not path.is_dir():
        raise ValueError("Audit root must be an existing directory")
    result = {"module": "system-audit", "root": str(path), "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()}}
    if platform.system() != "Linux" and str(root) == "/":
        return dict(result, status="unsupported", reason="Default local-system audit requires Linux; --root can inspect an extracted Linux filesystem")
    result["status"] = "ok"
    result["permissions"] = [inspect_permissions(path, relative) for relative in INSPECT_PATHS]
    result["sshd"] = inspect_sshd(path)
    result["limitation"] = "A selected-path audit, not a complete hardening assessment. Password databases and private keys are never read."
    return result


def run(args):
    return audit_system(args.root)


def register(subparsers):
    parser = subparsers.add_parser("system-audit", help="Read-only Linux permissions and explicit SSH policy observations")
    parser.add_argument("--root", default="/", help="Linux filesystem root (default: /)")
    parser.set_defaults(handler=run)
    return parser
