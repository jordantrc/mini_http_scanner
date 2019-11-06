#!/bin/env/python
#
# security_headers.py
#
# Usage: 
# security_headers.py [OPTIONS] URL
#
# URL is a single URL provided as an argument, or a list
# of URLs in a file, one per line 
#
# Valid options:
#   -s              simple output, everything on one line
#   -h, --headers   comma-separated list of headers to check
#   -t, --threads   number of threads to use, default is 1
#   -w, --wait      seconds to wait for response, default is 10
#   -r, --redirects follow redirects
#   -o, --output    output to file rather than STDOUT, appends by default if file exists
#

import argparse
import os
import requests
import sys


def header_check(url, single_line_output, headers, redirects, wait):
    '''performs the header check'''
    


def main():
    '''main function, gathers arguments, runs the scan'''
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('url', help='URL to connect to')
    parser.add_argument('-s', default=False)
    parser.add_argument('-h', '--headers', default='')
    parser.add_argument('-r', '--redirects', default=False)
    parser.add_argument('-o', '--out', default=sys.stdout)
    parser.add_argument('-w', '--wait', type=int, default=10)
    args = parser.parse_args()

    url_raw = args.url
    single_line_output = args.s
    headers_raw = args.headers
    redirects = args.redirects
    output = args.out
    wait = args.wait

    # determine which headers to include in results
    if len(headers_raw) == 0:
        headers = []
    else:
        headers = headers_raw.split(',')

    # determine if URL is a file or a URL
    if os.path.exists(url_raw):
        with open(url, 'r') as url_fd:
            urls = url_fd.read().splitlines()
    else:
        urls = [url_raw]

    # setup output
    if output != sys.stdout:
        if os.path.exists(output) and os.path.isfile(output):
            output = open(output, 'a+')
        else:
            output = open(output)

    # scan and write the results
    for u in urls:
        result = header_check(url)
        output.write(result + "\n")


if __name__ == '__main__':
    main()

with open(sys.argv[1], 'r') as fd:
    for line in fd.read().splitlines():
        r = requests.get(line)
        print("%s [status = %s]" % (line, r.status_code))
        if 'Strict-Transport-Security' in r.headers.keys():
            print("Strict-Transport-Security header found, value = %s" % (r.headers['Strict-Transport-Security']))
        else:
            print("Strict-Transport-Security header missing")
        sys.stdout.flush()