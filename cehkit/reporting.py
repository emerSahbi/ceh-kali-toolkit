"""Validate and combine phase reports without running additional scans."""

import json
from collections import Counter
from datetime import datetime
from pathlib import Path


MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_REPORTS = 64


def _reject_nonfinite(value):
    raise ValueError("Non-finite numeric literal is not valid JSON: " + value)


def register(subparsers):
    parser = subparsers.add_parser(
        "report", help="Combine toolkit JSON phase reports",
        description="Combine existing reports, preserving their source and phase. "
                    "Malformed inputs are reported explicitly and valid inputs are still included.",
    )
    parser.add_argument("inputs", nargs="+", type=Path, help="One or more toolkit JSON reports (up to 64)")
    parser.set_defaults(handler=run)
    return parser


def _validate_envelope(data):
    if not isinstance(data, dict):
        raise ValueError("Report must be a JSON object")
    if not isinstance(data.get("phase"), str) or not data["phase"].strip():
        raise ValueError("Report must contain a nonempty string phase")
    if not isinstance(data.get("created_at"), str):
        raise ValueError("Report must contain a string created_at")
    try:
        datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("Report created_at must be an ISO 8601 date/time")
    if not isinstance(data.get("result"), dict):
        raise ValueError("Report must contain an object result")


def _extract(result):
    findings, evidence = [], []
    pending = [result]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key == "findings" and isinstance(value, list):
                    findings.extend(value)
                if key == "evidence":
                    evidence.extend(value if isinstance(value, list) else [value])
                if isinstance(value, (dict, list)):
                    pending.append(value)
        elif isinstance(item, list):
            pending.extend(value for value in item if isinstance(value, (dict, list)))
    return findings, evidence


def run(args):
    if len(args.inputs) > MAX_REPORTS:
        return {"status": "failed", "errors": [{"error": "At most 64 reports may be combined"}],
                "reports": [], "findings": [], "evidence": []}
    reports, errors, findings, evidence = [], [], [], []
    phases = Counter()
    seen_sources = set()
    for source in args.inputs:
        path = Path(source)
        try:
            resolved = path.resolve()
            if resolved in seen_sources:
                raise ValueError("Duplicate report input")
            seen_sources.add(resolved)
            if not path.is_file():
                raise ValueError("Report does not exist or is not a regular file")
            if path.stat().st_size > MAX_REPORT_BYTES:
                raise ValueError("Report exceeds the 32 MiB input limit")
            with path.open("r", encoding="utf-8-sig") as stream:
                data = json.load(stream, parse_constant=_reject_nonfinite)
            _validate_envelope(data)
            extracted_findings, extracted_evidence = _extract(data["result"])
            context = {"source": str(path), "phase": data["phase"]}
            findings.extend(dict(context, finding=item) for item in extracted_findings)
            evidence.extend(dict(context, observation=item) for item in extracted_evidence)
            reports.append(dict(context, created_at=data["created_at"], result=data["result"]))
            phases[data["phase"]] += 1
        except (OSError, ValueError, UnicodeError, RecursionError) as error:
            errors.append({"source": str(path), "error": str(error)})
    return {
        "status": "partial" if errors and reports else "failed" if errors else "completed",
        "counts": {"inputs": len(args.inputs), "reports": len(reports),
                   "invalid_inputs": len(errors), "phases": len(phases),
                   "findings": len(findings), "evidence": len(evidence)},
        "phases": [{"phase": name, "reports": count} for name, count in sorted(phases.items())],
        "reports": reports, "findings": findings, "evidence": evidence, "errors": errors,
        "limitations": [
            "Findings and evidence are copied from source reports and are not independently verified.",
            "Counts represent reported entries; overlapping targets or nested aggregate reports may repeat findings.",
            "Successful aggregation does not imply that the source scans completed successfully; inspect their status.",
        ],
    }
