"""Shared input validation and evidence output."""
import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import re


def positive_int(value):
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("Value must be positive")
    return number


def positive_float(value):
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise argparse.ArgumentTypeError("Value must be positive and finite")
    return number


def timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")


def report_path(phase, value=None):
    path = Path(value) if value else Path("reports") / (phase + "_" + timestamp() + ".json")
    if path.suffix.lower() != ".json":
        raise ValueError("--output must end with .json")
    return path.absolute()


def write_report(path, envelope):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".json.tmp")
    temp.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)
    result = envelope["result"]
    lines = ["# CEH toolkit: " + envelope["phase"], "", "Collected: " + envelope["created_at"], ""]
    for key in ("target", "source", "url", "status", "error", "note"):
        if key in result:
            lines.append("{}: {}".format(key.replace("_", " ").title(), result[key]))
    for name, scan in result.get("scans", {}).items():
        lines += ["", "## " + name, ""]
        if scan.get("error"):
            lines.append(scan["error"])
        for host in scan.get("results", {}).get("hosts", []):
            lines += ["", "Host: " + ", ".join(a.get("addr", "") for a in host.get("addresses", [])), ""]
            for port in host.get("ports", []):
                if port.get("state", {}).get("state") in ("open", "open|filtered"):
                    service = port.get("service", {})
                    lines.append("- {}/{} {} {} {}".format(port["port"], port["protocol"], port["state"]["state"], service.get("name", ""), service.get("product", "")))
    findings = result.get("findings", [])
    if findings:
        lines += ["", "## Review findings", ""]
        for item in findings:
            if isinstance(item, dict):
                item = item.get("finding", item)
            if not isinstance(item, dict):
                lines.append("- " + str(item))
                continue
            title = item.get("title", item.get("item", item.get("id", "Observation")))
            detail = item.get("description", item.get("detail", item.get("message", item.get("evidence", ""))))
            lines.append("- **{}**: {}".format(title, detail))
    # A variable fence length prevents evidence text from breaking Markdown fences.
    evidence = json.dumps(result, indent=2, ensure_ascii=False)
    fence = "`" * max(3, max((len(part) for part in re.findall(r'`+', evidence)), default=0) + 1)
    lines += ["", "## Evidence", "", fence + "json", evidence, fence, ""]
    path.with_suffix(".md").write_text("\n".join(lines), encoding="utf-8")
