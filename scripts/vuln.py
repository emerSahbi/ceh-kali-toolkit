#!/usr/bin/env python3
"""Standalone target-aware vulnerability scanner."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cehkit.cli import main

if __name__ == "__main__":
    raise SystemExit(main(["vuln"] + sys.argv[1:]))
