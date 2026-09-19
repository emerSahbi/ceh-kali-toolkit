#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/install-kali.sh [--all] [--with-tshark] [--with-nikto]

Install dependencies and the cehkit command in /usr/local/bin.
--all         Include both Nikto and TShark for all menu features.
--with-tshark  Also install TShark for reading existing capture files.
              This script does not configure capture privileges.
--with-nikto   Also install Nikto for website vulnerability scanning.
USAGE
}

with_tshark=0
with_nikto=0
while (($#)); do
  case "$1" in
    --all) with_tshark=1; with_nikto=1 ;;
    --with-tshark) with_tshark=1 ;;
    --with-nikto) with_nikto=1 ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done

if ! command -v apt-get >/dev/null 2>&1; then
  printf 'This installer requires APT on Kali or another Debian-based Linux system.\n' >&2
  exit 1
fi

privilege=()
if ((EUID != 0)); then
  if ! command -v sudo >/dev/null 2>&1; then
    printf 'Run this installer as root, or install sudo first.\n' >&2
    exit 1
  fi
  privilege=(sudo)
fi

packages=(python3 python3-dnspython nmap)
if ((with_tshark)); then
  packages+=(tshark)
fi
if ((with_nikto)); then
  packages+=(nikto)
fi

"${privilege[@]}" apt-get update
"${privilege[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"

python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else "Python 3.9 or newer is required.")'
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
"${privilege[@]}" python3 "$script_dir/install_app.py"
printf '\nReady. Run from any directory:\n'
printf '  cehkit\n'
printf '  cehkit doctor\n'
printf '  cehkit --help\n'
