#!/usr/bin/env python


"""netblock.py - A script to parse and lookup IP address netblocks and
their respective owners."""

from __future__ import print_function

__author__  = "Damian Torres"
__email__   = "datorr2@gmail.com"
__version__ = "1.0"

import sys
import os
import argparse
import re
import json
import ipaddress
import urllib3
from time import mktime
from datetime import datetime, timedelta
from pprint import pprint
if sys.version_info > (3, 0):
    import _pickle as pickle
else:
    import cPickle as pickle
urllib3.disable_warnings()

# # # # # # #
# Constants #
# # # # # # #
SCRIPT_NAME                 = os.path.basename(__file__)
USAGE_HELP                  = """Usage: {} [-hVv] [-4 | -6] [file]

Parse and lookup IP address netblocks and their respective owners.

Optional arguments:
  file                      input filename (default: stdin)
  -v, --verbose             enable verbose messages to stderr
  -4                        only parse IPv4 addresses (default: both)
  -6                        only parse IPv6 addresses (default: both)

Other options
  -h, --help                display this help and exit
  -V, --version             output version information and exit
""".format(SCRIPT_NAME)
LOCAL_DATABASE              = "netblock.db"
PICKLE_FILE                 = "netblock.pkl"
MAX_CONNECTIONS             = 100
STALE_AGE                   = 7
USER_AGENT                  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) App" \
    + "leWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Safari/537.36"
GLOBAL_HEADERS              = { "Accept": "application/json",
                                "User-Agent": USER_AGENT
                            }
IPV4_VALIDATION_REGEX       = re.compile("(?<!\d)(?:(?:(?:22[0-3]|2[01]\d|1[" \
    + "79][013-9]|16[0-8]|12[0-68-9]|1[013-58]\d|[2-9]\d|1?[1-9])\.(?:25[0-5" \
    + "]|2[0-4]\d|1\d{2}|[1-9]?\d))|(?:172\.(?:25[0-5]|2[0-4]\d|1\d{2}|[4-9]" \
    + "\d|3[2-9]|1[0-5]|\d))|(?:192\.(?:25[0-5]|2[0-4]\d|16[0-79]|1[0-57-9][" \
    + "0-9]|[1-9]?\d))|(?:169\.(?:25[0-35]|2[0-4]\d|1\d{2}|[1-9]?\d)))(?:\.(" \
    + "?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){2}(?!\d)")
IPV4_RANGE_REGEX            = re.compile("(?<!\d)(?:(?:(?:22[0-3]|2[01]\d|1[" \
    + "79][013-9]|16[0-8]|12[0-68-9]|1[013-58]\d|[2-9]\d|1?[1-9])\.(?:25[0-5" \
    + "]|2[0-4]\d|1\d{2}|[1-9]?\d))|(?:172\.(?:25[0-5]|2[0-4]\d|1\d{2}|[4-9]" \
    + "\d|3[2-9]|1[0-5]|\d))|(?:192\.(?:25[0-5]|2[0-4]\d|16[0-79]|1[0-57-9][" \
    + "0-9]|[1-9]?\d))|(?:169\.(?:25[0-35]|2[0-4]\d|1\d{2}|[1-9]?\d)))(?:\.(" \
    + "?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){2}(?!\d)\ *-\ *(?<!\d)(?:(?:(?:2" \
    + "2[0-3]|2[01]\d|1[79][013-9]|16[0-8]|12[0-68-9]|1[013-58]\d|[2-9]\d|1?" \
    + "[1-9])\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d))|(?:172\.(?:25[0-5]|2[0-" \
    + "4]\d|1\d{2}|[4-9]\d|3[2-9]|1[0-5]|\d))|(?:192\.(?:25[0-5]|2[0-4]\d|16" \
    + "[0-79]|1[0-57-9][0-9]|[1-9]?\d))|(?:169\.(?:25[0-35]|2[0-4]\d|1\d{2}|" \
    + "[1-9]?\d)))(?:\.(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){2}(?!\d)")
IPV6_VALIDATION_REGEX       = re.compile("(?<![0-9a-f:])(?:[0-9a-f]{1,4}(?::" \
    + "[0-9a-f]{1,4}){7}|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{" \
    + "1,4}:){1,7}:|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{1,4}:)" \
    + "{2}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){3}(?::[0-9a-f]{1,4}){1," \
    + "4}|(?:[0-9a-f]{1,4}:){4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){5}" \
    + "(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){6}:[0-9a-f]{1,4})(?![0-9a-" \
    + "f:])")
IPV6_RANGE_REGEX            = re.compile("(?<![0-9a-f:])(?:[0-9a-f]{1,4}(?::" \
    + "[0-9a-f]{1,4}){7}|::[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{" \
    + "1,4}:){1,7}:|[0-9a-f]{1,4}:(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{1,4}:)" \
    + "{2}(?::[0-9a-f]{1,4}){1,5}|(?:[0-9a-f]{1,4}:){3}(?::[0-9a-f]{1,4}){1," \
    + "4}|(?:[0-9a-f]{1,4}:){4}(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){5}" \
    + "(?::[0-9a-f]{1,4}){1,2}|(?:[0-9a-f]{1,4}:){6}:[0-9a-f]{1,4})(?![0-9a-" \
    + "f:])\ *-\ *(?<![0-9a-f:])(?:[0-9a-f]{1,4}(?::[0-9a-f]{1,4}){7}|::[0-9" \
    + "a-f]{1,4}(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{1,4}:){1,7}:|[0-9a-f]{1," \
    + "4}:(?::[0-9a-f]{1,4}){0,6}|(?:[0-9a-f]{1,4}:){2}(?::[0-9a-f]{1,4}){1," \
    + "5}|(?:[0-9a-f]{1,4}:){3}(?::[0-9a-f]{1,4}){1,4}|(?:[0-9a-f]{1,4}:){4}" \
    + "(?::[0-9a-f]{1,4}){1,3}|(?:[0-9a-f]{1,4}:){5}(?::[0-9a-f]{1,4}){1,2}|" \
    + "(?:[0-9a-f]{1,4}:){6}:[0-9a-f]{1,4})(?![0-9a-f:])")
RIRs    = { "ARIN"      : {
                "NAME"      : "ARIN",
                "HOST"      : "whois.arin.net",
                "URL"       : "/rest/ip/{}",
                "BROWSER"   : None,     # We set this later
                "QUERY"     : None      # We set this later
            },
            "RIPE"      : {
                "NAME"      : "RIPE",
                "HOST"      : "rest.db.ripe.net",
                "URL"       : "/search?query-string={}",
                "BROWSER"   : None,     # We set this later
                "QUERY"     : None      # We set this later
            },
            "APNIC"     : {
                "NAME"      : "APNIC",
                "HOST"      : "whois.arin.net",
                "URL"       : "/rest/ip/{}",
                "BROWSER"   : None,     # We set this later
                "QUERY"     : None      # We set this later
            },
            "AFRINIC"   : {
                "NAME"      : "AFRINIC",
                "HOST"      : "whois.arin.net",
                "URL"       : "/rest/ip/{}",
                "BROWSER"   : None,     # We set this later
                "QUERY"     : None      # We set this later
            },
            "LACNIC"    : {
                "NAME"      : "LACNIC",
                "HOST"      : "whois.arin.net",
                "URL"       : "/rest/ip/{}",
                "BROWSER"   : None,     # We set this later
                "QUERY"     : None      # We set this later
            }
        }
for R in RIRs:
    RIRs[R]["BROWSER"] = urllib3.HTTPSConnectionPool(
      RIRs[R]["HOST"], cert_reqs="CERT_NONE")


# # # # # # #
# Functions #
# # # # # # #

# Error print function
def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


# Print usage
def usage():
    #print(USAGE_HELP)
    return USAGE_HELP


# Handle command-line options and arguments
def optionsHandler():
    global VERBOSE
    global FOUR
    global SIX

    parser = argparse.ArgumentParser(add_help=False, usage=usage(),
      description="Parse and lookup IPv4 address netblocks and their " \
      + "respective owners")
    parser.add_argument("-h", "--help", action="store_true",
      help="display this help and exit")
    parser.add_argument("-V", "--version", action="version",
      help="output version information and exit")
    parser.add_argument("-v", "--verbose", action="store_true",
      help="print verbose information to stderr")
    parser.add_argument('filename', metavar='file', type=str, nargs="?",
      help="input filename (default: stdin)")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-4", action="store_true",
      help="only parse IPv4 addresses (default: both)")
    group.add_argument("-6", action="store_true",
      help="only parse IPv6 addresses (default: both)")

    args = parser.parse_args()

    if args.help:
        eprint(usage())
        exit(0)

    argVars = vars(args)
    VERBOSE = argVars["verbose"]
    FOUR = argVars["4"]
    SIX = argVars["6"]

    return args.filename


# Convert IP range string to a network object
def rangeToCidr(s):
    if not SIX and IPV4_RANGE_REGEX.match(s):
        func = ipaddress.IPv4Address
    elif not FOUR and IPV6_RANGE_REGEX.match(s):
        func = ipaddress.IPv6Address
    else:
        return None

    tmp = s.split("-")

    net = [ip for ip in ipaddress.summarize_address_range(
      func(tmp[0].strip()), func(tmp[1].strip()))][0]

    return net


# Parse IP Addresses out of file or STDIN
def parseIPs(fn):
    if not fn:
        fh = sys.stdin
    else:
        fh = open(fn, 'r')

    dictObj = {}

    if not SIX:
        for line in fh:
            matches = IPV4_VALIDATION_REGEX.findall(line)
            for match in matches:
                ipObj = ipaddress.IPv4Address(unicode(match))
                dictObj[ipObj] = 1

    if not FOUR:
        for line in fh:
            matches = IPV6_VALIDATION_REGEX.findall(line)
            for match in matches:
                ipObj = ipaddress.IPv6Address(unicode(match))
                dictObj[ipObj] = 1

    myArr = list(dictObj.keys())

    if VERBOSE:
        eprint("+ Parsed {} addresses.".format(len(myArr)))

    return myArr


# Basic HTTP Request/Response
def httpReq(b, h, u):
    if VERBOSE:
        eprint(" \\ Browsing to: https://{}{}".format(h,u))

    resp = b.request("GET", u, headers=GLOBAL_HEADERS)

    if VERBOSE:
        eprint("  \\ Received {} from server.".format(resp.status))

    return resp


# Generic query function
def runQuery(rir, addy):
    return httpReq(rir["BROWSER"], rir["HOST"], rir["URL"].format(addy))


# Perform RIPE Lookup
def queryRIPE(ipObj):
    resp = runQuery(RIRs["RIPE"], ipObj)
    n = None
    o = None
    d = None

    if resp.status == 200:
        j = json.loads(resp.data)
        for i in j["objects"]["object"]:
            if i["type"] == "inetnum":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "netname":
                        if re.match("NON-RIPE-NCC-MANAGED", ii["value"]):
                            print("Not managed by RIPE!")
                    elif ii["name"] == "descr":
                        d = ii["value"]
                    elif ii["name"] == "inetnum":
                        netnum = ii["value"]
            elif i["type"] == "route":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "route":
                        n = ipaddress.ip_network(ii["value"])
            elif i["type"] == "organisation":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "org-name":
                        o = ii["value"]
        if not n and re.match(
          r"\d{1,3}(?:\.\d{1,3}){3}\ *-\ *\d{1,3}(?:\.\d{1,3}){3}", netnum):
            n = rangeToCidr(netnum)
    else:
        print("Error")

    return n, o or d


# Perform APNIC Lookup
def queryAPNIC(ipObj):
    resp = runQuery(RIRs["APNIC"], ipObj)
    n = None
    o = None

    if resp.status == 200:
        j = json.loads(resp.data)
        for i in j["objects"]["object"]:
            if i["type"] == "inetnum":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "netname":
                        if re.match("NON-RIPE-NCC-MANAGED", ii["value"]):
                            print("Not managed by RIPE!")
            elif i["type"] == "route":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "route":
                        n = ii["value"]
            elif i["type"] == "organisation":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "org-name":
                        o = ii["value"]
    else:
        print("Error")

    return n, o


# Perform AFRINIC Lookup
def queryAFRINIC(ipObj):
    resp = runQuery(RIRs["AFRINIC"], ipObj)
    n = None
    o = None

    if resp.status == 200:
        j = json.loads(resp.data)
        for i in j["objects"]["object"]:
            if i["type"] == "inetnum":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "netname":
                        if re.match("NON-RIPE-NCC-MANAGED", ii["value"]):
                            print("Not managed by RIPE!")
            elif i["type"] == "route":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "route":
                        n = ii["value"]
            elif i["type"] == "organisation":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "org-name":
                        o = ii["value"]
    else:
        print("Error")

    return n, o


# Perform LACNIC Lookup
def queryLACNIC(ipObj):
    resp = runQuery(RIRs["LACNIC"], ipObj)
    n = None
    o = None

    if resp.status == 200:
        j = json.loads(resp.data)
        for i in j["objects"]["object"]:
            if i["type"] == "inetnum":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "netname":
                        if re.match("NON-RIPE-NCC-MANAGED", ii["value"]):
                            print("Not managed by RIPE!")
            elif i["type"] == "route":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "route":
                        n = ii["value"]
            elif i["type"] == "organisation":
                for ii in i["attributes"]["attribute"]:
                    if ii["name"] == "org-name":
                        o = ii["value"]
    else:
        print("Error")

    return n, o


# Perform ARIN lookup
def queryARIN(obj):
    n, o = None, None

    if isinstance(obj, ipaddress._BaseAddress):
        resp = runQuery(RIRs["ARIN"], obj)
    elif isinstance(obj, (str, unicode)) and (
      re.match(r"https?:\/\/.+\/NET-", obj)):
        resp = httpReq(RIRs["ARIN"]["BROWSER"], RIRs["ARIN"]["HOST"], obj)
    else:
        e = "type '{}' received; expected ipaddress or url".format(type(obj))
        raise TypeError(e)
    
    if resp.status == 200:
        j = json.loads(resp.data)
        if isinstance(obj, (ipaddress._BaseAddress)):
            start = ipaddress.ip_address(j["net"]["startAddress"]["$"])
            end = ipaddress.ip_address(j["net"]["endAddress"]["$"])
            for net in ipaddress.summarize_address_range(start, end):
                if obj in net:
                    n = net
                    break
        if "orgRef" in j["net"]:
            h = j["net"]["orgRef"]["@handle"]
            if h in ("RIPE","APNIC","AFRINIC","LACNIC"):
                if VERBOSE:
                    print("+ Received referral to {}".format(h))
                func = RIRs[h]["QUERY"]
                n, o = func(obj)
            else:
                o = j["net"]["orgRef"]["@name"]
        elif "parentNetRef" in j["net"]:
            pnrUrl = j["net"]["parentNetRef"]["$"]
            if VERBOSE:
                s1 = "+ Received parent network reference.\n"
                s2 = " \\ URL: {}\n  \\ Recursing..."
                s = s1 + s2
                eprint(s.format(pnrUrl))
            null, o = queryARIN(pnrUrl)
        else:
            print("Error!")
    else:
        print("Error!")
    
    return n, o


# Binary search the pickle
def queryPickle(q, l=None, r=None):
    l = l if l is not None else 0
    r = r if r is not None else len(pklIndex)-1

    if len(pklIndex) == 0:
        #eprint("No items in index")
        #pklIndex.append(i)
        #RECURSION_COUNTER = 0
        return
    elif l < 0 or r < 0:
        #eprint("Out of bounds, left side; inserting at beginning of list.")
        #pklIndex.insert(0, i)
        #RECURSION_COUNTER = 0
        #return True
        null = 0
    elif l >= len(pklIndex) or r > len(pklIndex):
        #eprint("Out of bounds, right side; appending to end of list.")
        #pklIndex.append(i)
        #RECURSION_COUNTER = 0
        #return True
        null = 0
    elif l > r:
        #eprint("l > r ({0} > {1}); inserting at position {0}.".format(l,r))
        #pklIndex.insert(l, i)
        #RECURSION_COUNTER = 0
        #return True
        null = 0
    else:
        m = l + int((r - l)/ 2)
        if q in pklIndex[m]:
            return pklIndex[m]
        elif q < pklIndex[m].network_address:
            return queryPickle(q, l, m-1)
        elif q > pklIndex[m].broadcast_address:
            return queryPickle(q, m+1, r)
        #if i.broadcast_address < pklIndex[m].network_address:
        #    #eprint("Value lower than mid; recursing into lower range")
        #    #RECURSION_COUNTER += 1
        #    return insertPickle(i, l, m-1)
        #elif i.network_address > pklIndex[m].broadcast_address:
        #    #eprint("Value greater than mid; recursing into upper range")
        #    #RECURSION_COUNTER += 1
        #    return insertPickle(i, m+1, r)
        #else:
        #    #s1 = "Value neither greater nor lower than mid. "
        #    #s2 = "Inserting at position {}.".format(m)
        #    #s = s1 + s2
        #    #eprint(s)
        #    null = 0


    # Do we even have entries yet?
    #if len(pklIndex) > 0:
    #    #eprint("n > 0 ({})".format(n))
    #    #eprint("pklIndex = {}".format(pklIndex))
    #    # Yes we do. Let's search!
    #    #m = l + int((r - l)/ 2)
    #    #eprint("l = {} // m = {} // r = {}".format(l,m,r))
    #    if q in pklIndex[m]:
    #        return pklIndex[m]
    #    elif q < pklIndex[m].network_address:
    #        return queryPickle(q, l, m-1)
    #    elif q > pklIndex[m].broadcast_address:
    #        return queryPickle(q, m+1, r)

    #eprint("queryPickle() Returning none")
    return


# Sorted insert network into the pickle
def insertPickle(i, l=None, r=None):
    #global RECURSION_COUNTER
    #eprint("RECURSION_COUNTER == {}".format(RECURSION_COUNTER))
    #if RECURSION_COUNTER >= MAX_RECURSION:
    #    eprint("Maximum recursion reached.  Exiting.")
    #    exit(1)
    

    #if l is None and r is None:
    #    DEBUG = -1
    #else:
    #    DEBUG = 1
    
    #if DEBUG == 1:
    #    eprint("Called insertPickle({}, {}, {})".format(i, l, r))

    l = l if l is not None else 0
    r = r if r is not None else len(pklIndex)-1

    #if DEBUG == -1:
    #    eprint("Called insertPickle({})".format(i))

    #n = r - l + 1   # Number of items
    #eprint("n = {}".format(n))

    #m = l + int((r - l)/ 2)
    #eprint("l = {} // m = {} // r = {}".format(l,m,r))
    if len(pklIndex) == 0:
        #eprint("No items in index; appending.")
        pklIndex.append(i)
        #RECURSION_COUNTER = 0
        return True
    elif l < 0 or r < 0:
        #eprint("Out of bounds, left side; inserting at beginning of list.")
        pklIndex.insert(0, i)
        #RECURSION_COUNTER = 0
        return True
    elif l >= len(pklIndex) or r > len(pklIndex):
        #eprint("Out of bounds, right side; appending to end of list.")
        pklIndex.append(i)
        #RECURSION_COUNTER = 0
        return True
    elif l > r:
        #eprint("l > r ({0} > {1}); inserting at position {0}.".format(l,r))
        pklIndex.insert(l, i)
        #RECURSION_COUNTER = 0
        return True
    else:
        m = l + int((r - l)/ 2)
        if i.broadcast_address < pklIndex[m].network_address:
            #eprint("Value lower than mid; recursing into lower range")
            #RECURSION_COUNTER += 1
            return insertPickle(i, l, m-1)
        elif i.network_address > pklIndex[m].broadcast_address:
            #eprint("Value greater than mid; recursing into upper range")
            #RECURSION_COUNTER += 1
            return insertPickle(i, m+1, r)
        else:
            #s1 = "Value neither greater nor lower than mid. "
            #s2 = "Inserting at position {}.".format(m)
            #s = s1 + s2
            #eprint(s)
            null = 0

    #RECURSION_COUNTER = 0
    return False


# Main function
def main():
    global MAX_RECURSION
    global RECURSION_COUNTER
    MAX_RECURSION = 10
    RECURSION_COUNTER = 0

    # Declare globals
    global pklData
    global pklIndex
    pklData = {}
    pklIndex = []

    # Setup pointers to query functions first
    RIRs["ARIN"]["QUERY"]       = queryARIN
    RIRs["RIPE"]["QUERY"]       = queryRIPE
    RIRs["APNIC"]["QUERY"]      = queryAPNIC
    RIRs["AFRINIC"]["QUERY"]    = queryAFRINIC
    RIRs["LACNIC"]["QUERY"]     = queryLACNIC

    output = {}

    # Grab our options
    fn = optionsHandler()

    # Load pickle file
    if os.path.isfile(PICKLE_FILE):
        with open(PICKLE_FILE, "rb") as rf:
            pklData = pickle.load(rf) or {}

    pklIndex = list(pklData.keys())
    pklIndex.sort()

    # Go parse addresses from our input file or stdin
    addys = parseIPs(fn)

    for ip in addys:
        #eprint("========================================================")
        idx = queryPickle(ip)

        if idx:
            if VERBOSE:
                s = "+ Found IP address '{}' in the database!"
                eprint(s.format(ip))
            then = datetime.utcfromtimestamp(pklData[idx]["timestamp"])
        else:
            if VERBOSE:
                s = "+ IP address '{}' was not found in the database."
                eprint(s.format(ip))
            then = None

        now = datetime.now()
        if not then or now - then > timedelta(STALE_AGE):
            net, owner = queryARIN(ip)
            ts = mktime(now.timetuple())
            pklData[net] = { "owner": owner, "timestamp": ts }
            if not insertPickle(net):
                s = "Error storing '{}' into database."
                eprint(s.format(net))
            #pprint(pklIndex)
            output[ip] = (net, owner)
        else:
            output[ip] = (idx, pklData[idx]["owner"])

    for x in sorted(output):
        print("{} => {} :: {}".format(x, output[x][0], output[x][1]))

    with open(PICKLE_FILE, "wb") as wf:
        pickle.dump(pklData, wf)

    return


if __name__ == "__main__":
    main()

