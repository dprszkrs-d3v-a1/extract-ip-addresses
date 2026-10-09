Extracts IPv4 addresses from a text file using a regular
expression and write them to a new file, one address per line.

The output can be fed straight into ip_lookup.py:

    python ip_lookup.py -f extracted_ips.txt
ip_lookup.py can be found here:
https://github.com/dprszkrs-d3v-a1/whoisthis
Usage:
  python extract_ips.py firewall.log
  python extract_ips.py firewall.log -o ips.txt
  python extract_ips.py access.log -o ips.txt --sort --global-only

Install:
  (standard library only - no pip packages required)
