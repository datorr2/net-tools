#!/usr/bin/env python


"""sort-ip.py - A script to parse and sort IP addresses."""

from __future__ import print_function

__author__  = "Damian Torres"
__email__   = "datorr2@gmail.com"
__version__ = "1.0"

import sys
import os
import argparse
import re
import ipaddress

# # # # # # #
# Constants #
# # # # # # #
SCRIPT_NAME                 = os.path.basename(__file__)
USAGE_HELP                  = """Usage: {} [-hV] [file]

Parse and sort IP addresses.

Optional arguments:
  file                      input filename (default: stdin)

Other options
  -h, --help                display this help and exit
  -V, --version             output version information and exit
""".format(SCRIPT_NAME)
IPV4_VALIDATION_REGEX       = re.compile("(?<!\d)(?:(?:(?:22[0-3]|2[01]\d|1[" \
    + "79][013-9]|16[0-8]|12[0-68-9]|1[013-58]\d|[2-9]\d|1?[1-9])\.(?:25[0-5" \
    + "]|2[0-4]\d|1\d{2}|[1-9]?\d))|(?:172\.(?:25[0-5]|2[0-4]\d|1\d{2}|[4-9]" \
    + "\d|3[2-9]|1[0-5]|\d))|(?:192\.(?:25[0-5]|2[0-4]\d|16[0-79]|1[0-57-9][" \
    + "0-9]|[1-9]?\d))|(?:169\.(?:25[0-35]|2[0-4]\d|1\d{2}|[1-9]?\d)))(?:\.(" \
    + "?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){2}(?!\d)")
IPV6_VALIDATION_REGEX       = re.compile("(?<![0-9a-f:])(?:[0-9a-f]{1,4}(?::" \
    + "[0-9a-f]{1,4}){7}|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{" \
    + "1,4}:){1,7}:|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{1,4}:)" \
    + "{2}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){3}(?::[0-9a-f]{1,4}){1," \
    + "4}|(?:[0-9a-f]{1,4}:){4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){5}" \
    + "(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){6}:[0-9a-f]{1,4})(?![0-9a-" \
    + "f:])")


# # # # # # #
# Functions #
# # # # # # #

# Error print function
def eprint(*args, **kwargs):
    print (*args, file=sys.stderr, **kwargs)


# Print usage
def usage():
    print(USAGE_HELP)
    return


# Handle command-line options and arguments
def optionsHandler():
    parser = argparse.ArgumentParser(add_help=True,
      description="Parse and lookup IPv4 address netblocks and their " \
      + "respective owners")
    parser.add_argument("-V", "--version", action="version",
      help="output version information and exit")
    parser.add_argument('filename', metavar='file', type=str, nargs="?",
      help="input filename (default: stdin)")

    args = parser.parse_args()

    return args.filename


# Parse IPv4 Addresses out of file or STDIN
def parseIPv4Addresses(fn):
    if not fn:
        fh = sys.stdin
    else:
        fh = open(fn, 'r')

    dictObj = {}

    for line in fh:
        matches = IPV4_VALIDATION_REGEX.findall(line)
        for match in matches:
            ipObj = ipaddress.IPv4Address(unicode(match))
            dictObj[ipObj] = 1

    myArr = list(dictObj.keys())

    return myArr


# Parse IPv6 Addresses out of file or STDIN
def parseIPv6Addresses(fn):
    if not fn:
        fh = sys.stdin
    else:
        fh = open(fn, 'r')

    dictObj = {}

    for line in fh:
        matches = IPV6_VALIDATION_REGEX.findall(line)
        for match in matches:
            ipObj = ipaddress.IPv6Address(unicode(match))
            dictObj[ipObj] = 1

    myArr = list(dictObj.keys())

    return myArr


# Main function
def main():
    # Grab our options
    fn = optionsHandler()

    # Go parse addresses from our input file or stdin
    ipv4_addys = parseIPv4Addresses(fn)
    ipv6_addys = parseIPv6Addresses(fn)

    for addy in sorted(ipv4_addys):
        print(addy)

    for addy in sorted(ipv6_addys):
        print(addy)

    return


if __name__ == "__main__":
    main()

