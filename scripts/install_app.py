#!/usr/bin/env python3
"""Install the local toolkit and a single launcher, without system pip."""
import argparse
from pathlib import Path
import re
import shutil
import tempfile

MARKER = "CEH_KALI_TOOLKIT_MANAGED_INSTALL"


def install(source, prefix, bin_dir):
    source, prefix, bin_dir = (Path(value).absolute() for value in (source, prefix, bin_dir))
    package = source / "cehkit"
    version_match = re.search(r'__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', (package / "__init__.py").read_text(encoding="utf-8"))
    if not version_match:
        raise ValueError("Cannot determine toolkit version")
    destination = prefix / version_match.group(1)
    launcher = bin_dir / "cehkit"
    if launcher.is_symlink() or (launcher.exists() and
            (not launcher.is_file() or MARKER not in launcher.read_text(encoding="utf-8"))):
        raise ValueError("Existing cehkit launcher is not managed by this installer")
    marker = destination / ".cehkit-install"
    if destination.is_symlink() or (destination.exists() and
            (not marker.is_file() or marker.read_text(encoding="utf-8").strip() != MARKER)):
        raise ValueError("Existing application directory is not managed by this installer")
    destination.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    (destination / ".cehkit-install").write_text(MARKER + "\n", encoding="utf-8")
    shutil.copytree(str(package), str(destination / "cehkit"), dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for filename in ("README.md", "pyproject.toml"):
        shutil.copy2(str(source / filename), str(destination / filename))
    shutil.copytree(str(source / "docs"), str(destination / "docs"), dirs_exist_ok=True)
    content = ("#!/usr/bin/python3\n# " + MARKER + "\n"
               "import sys\n" + "sys.path.insert(0, " + repr(str(destination)) + ")\n"
               "from cehkit.cli import main\nraise SystemExit(main())\n")
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n", dir=str(bin_dir), delete=False) as stream:
        temporary = Path(stream.name)
        stream.write(content)
    temporary.chmod(0o755)
    temporary.replace(launcher)
    print("Installed {}\nApplication: {}".format(launcher, destination))
    return launcher


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prefix", type=Path, default=Path("/opt/ceh-kali-toolkit"))
    parser.add_argument("--bin-dir", type=Path, default=Path("/usr/local/bin"))
    args = parser.parse_args()
    install(Path(__file__).resolve().parents[1], args.prefix, args.bin_dir)


if __name__ == "__main__":
    main()
