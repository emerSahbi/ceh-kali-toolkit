"""Streaming integrity digests; this module does not recover passwords."""

import hashlib
import hmac
import re
from pathlib import Path


def hash_file(filename, algorithm="sha256", expected=None):
    if algorithm not in ("sha256", "sha512"):
        raise ValueError("Choose sha256 or sha512")
    digest = hashlib.new(algorithm)
    if expected is not None:
        expected = expected.strip().lower()
        if not re.fullmatch(r"[0-9a-f]{" + str(digest.digest_size * 2) + r"}", expected):
            raise ValueError("Expected digest must be a complete hexadecimal " + algorithm + " digest")
    path = Path(filename).expanduser().resolve()
    if not path.is_file():
        raise ValueError("Hash input must be a regular file")
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            total += len(chunk)
    value = digest.hexdigest()
    result = {"module": "hash", "file": str(path), "algorithm": algorithm, "bytes_read": total, "digest": value}
    if expected is not None:
        result["expected_digest"] = expected
        result["matches_expected"] = hmac.compare_digest(value, expected)
        result["status"] = "ok" if result["matches_expected"] else "mismatch"
    else:
        result["status"] = "ok"
    return result


def run(args):
    return hash_file(args.file, args.algorithm, args.expected)


def register(subparsers):
    parser = subparsers.add_parser("hash", help="Compute or verify a file's SHA-256 or SHA-512 digest")
    parser.add_argument("file", help="Local regular file to hash")
    parser.add_argument("--algorithm", choices=("sha256", "sha512"), default="sha256")
    parser.add_argument("--expected", help="Expected hexadecimal digest for integrity verification")
    parser.set_defaults(handler=run)
    return parser
