#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/install-kali.sh [--with-tshark] [--with-nikto]

Install Python 3, dnspython, and Nmap using APT.
--with-tshark  Also install TShark for reading existing capture files.
              This script does not configure capture privileges.
--with-nikto   Also install Nikto for website vulnerability scanning.
USAGE
}

with_tshark=0
with_nikto=0
while (($#)); do
  case "$1" in
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
printf '\nDependencies installed. From the repository directory, run:\n'
printf '  python3 -m cehkit doctor\n'
printf '  python3 -m cehkit --help\n'
