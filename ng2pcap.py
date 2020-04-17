#!/usr/bin/env python3

"""ng2pcap.py - A script to convert pcapng files to pcap format.

Requires:
 - python-magic (0.4.15)

"""

__author__  = "Damian Torres"
__email__   = "datorr2@gmail.com"
__version__ = "0.1"

import sys
from pathlib import Path
import argparse
import magic


# # # # # # #
# Constants #
# # # # # # #
SCRIPT_NAME = Path(__file__).name
USAGE_HELP  = f"""Usage: {SCRIPT_NAME} [-k] FILE...

Convert pcapng files to pcap format.

Mandatory arguments:
  FILE...                   file or files to convert

Optional arguments:
  -k, --keep                keep source files (do not delete)
  -r, --recurse             recurse into subdirectories

Other options
  -h, --help                display this help and exit
  -V, --version             output version information and exit

""".format(SCRIPT_NAME)


# # # # # # #
# Functions #
# # # # # # #

# Error print function
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# Return version information
def version():
    return """csv.py - v{version}
Written by {author} ({email})""".format(**{
        "version"   : __version__,
        "author"    : __author__,
        "email"     : __email__
    })


# Return usage information
def usage():
    return USAGE_HELP


# Handle command-line options and arguments
def optionsHandler():
    parser = argparse.ArgumentParser(add_help=False, usage=usage(),
      description="Convert pcapng files to pcap format.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-h", "--help", action="store_true",
      help="display this help and exit")
    group.add_argument("-V", "--version", action="store_true",
      help="output version information and exit")
    parser.add_argument('files', metavar='FILE...', type=str, nargs="+",
      help="file or files to convert")
    group.add_argument("-k", "--keep", action="store_true",
      help="keep source files (do not delete)")
    group.add_argument("-r", "--recurse", action="store_true",
      help="keep source files (do not delete)")

    args = parser.parse_args()

    if args.version:
        print(version())
        exit(0)

    if args.help:
        print(usage())
        exit(0)

    return args


def convertFile(fn):
    if Path(fn).is_dir(): return

    mgc = ""
    with Path(fn).open("rb") as fh:
        mgc = magic.from_buffer(fh.read(16))

    if "pcap-ng" in mgc:
        # Convert the file, change extention to .pcap
        # If pcap-ng file was already named .pcap, rename old file to
        #  .pcapng and name the new file .pcap, maybe show some stderr
        #  warnings.
        print("This is a pcap-ng file.")

        if not args.keep:
            print(f"Removing old file \"{fn}\"")
    else:
        eprint(f"File \"{fn}\" is not a pcap-ng file -- Skipping")

    return


def main():
    # Grab our args
    global args
    args = optionsHandler()

    while args.files:
        f = args.files.pop(0)
        if not Path(f).exists():
            eprint(f"File \"{f}\" does not exist.")
        elif args.recurse and Path(f).is_dir():
            for fr in Path(f).glob("**/*"):
                if Path(fr).is_file():
                    convertFile(fr)
        else:
            convertFile(f)

    print("\nThe End.\n")
    return


if __name__ == "__main__":
    main()

