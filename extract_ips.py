#!/usr/bin/env python3
"""
extract_ips.py - Extract IPv4 addresses from a text file using a regular
expression and write them to a new file, one address per line.

The output can be fed straight into ip_lookup.py:

    python ip_lookup.py -f extracted_ips.txt

Usage:
  python extract_ips.py firewall.log
  python extract_ips.py firewall.log -o ips.txt
  python extract_ips.py access.log -o ips.txt --sort --global-only

Install:
  (standard library only - no pip packages required)
"""
import argparse
import ipaddress
import os
import re
import sys

# ------------------------------------------------------------------- regex
# One IPv4 octet (0-255, no leading zeros):
OCTET = r"(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])"

IPV4_RE = re.compile(
    r"(?<![\w.])"                  # not preceded by letter/digit/underscore/'.'
    + OCTET                        # 1st octet
    + r"(?:\." + OCTET + r"){3}"   # "." + octet, repeated 3 times
    + r"(?!\.?[0-9])"              # not followed by a digit or ".<digit>"
)


# ------------------------------------------------------------------ helpers
def extract_from_file(path: str) -> list:
    """Return every IPv4 address found in *path* (duplicates included)."""
    matches = []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:                     # line by line -> low memory use
            matches.extend(IPV4_RE.findall(line))
    return matches


# -------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(
        description="Extract IPv4 addresses from a text file (regex-based)")
    ap.add_argument("input", help="text file to scan (any format, e.g. logs)")
    ap.add_argument("-o", "--output",
                    help="output file (default: <input>_ips.txt)")
    ap.add_argument("--keep-duplicates", action="store_true",
                    help="write every occurrence instead of unique IPs")
    ap.add_argument("--sort", action="store_true",
                    help="sort IPs numerically (default: order of appearance)")
    ap.add_argument("--global-only", action="store_true",
                    help="keep only globally routable addresses "
                         "(drop private/reserved ones like 192.168.x.x)")
    args = ap.parse_args()

    try:
        matches = extract_from_file(args.input)
    except OSError as e:
        sys.exit(f"Error: cannot read {args.input}: {e}")

    ips = matches
    if not args.keep_duplicates:
        ips = list(dict.fromkeys(ips))      # dedupe, preserve order
    if args.global_only:
        ips = [ip for ip in ips if ipaddress.ip_address(ip).is_global]
    if args.sort:
        ips = sorted(ips, key=ipaddress.ip_address)

    if not ips:
        sys.exit(f"No IPv4 addresses found in {args.input}")

    out_path = args.output or os.path.splitext(args.input)[0] + "_ips.txt"
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(ips) + "\n")

    print(f"Found {len(matches)} occurrence(s), "
          f"wrote {len(ips)} IP address(es) to {out_path}")


if __name__ == "__main__":
    main()