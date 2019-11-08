# mini_http_scanner.py
#
# Quickly scans a set of IP addresses on a set of ports
# looking for a valid response for a particular URL.
#
# Usage: mini_http_scanner.py [OPTIONS] host(s)
# Valid options:
#   -h, --help      show this help and exit
#   -p, --ports     a comma-separated list of ports to scan, defaults to 80 and 443
#   -u, --url       a URL to scan those hosts for, defaults to "/"
#   -t, --threads   number of threads to use for scanning
#   -o, --out       name of output file, defaults to STDOUT
#   -w, --wait      time to wait for a response in seconds, default is 10 seconds
#   
#   host(s) is one of the following:
#       - a single IP address (e.g. 192.168.2.1)
#       - a range of IP addresses (e.g. 192.168.2.10-192.168.2.12)
#       - a network ID and subnet mask (e.g. 192.168.2.0/24)
#       - a file containing a list of hosts/network ids and subnet masks, one per line
#

import argparse
import ipaddress
import os
import requests
import sys
import threading
import time
import urllib3

# disable urllib3 warnings
urllib3.disable_warnings()


class HTTPScan():

    def __init__(self, url=None, ports=None, threads=None, hosts=None, wait=None, match=None):
        '''initializes the object'''
        self.url = url
        self.ports = self.create_port_list(ports)
        self.threads = threads
        self.hosts = self.create_host_set(hosts)
        self.wait = wait
        self.num_ports = len(self.ports)
        self.num_hosts = len(self.hosts)
        self.match = match

    @staticmethod
    def create_port_list(ports):
        '''parse the ports input'''
        port_list = []
        if ',' in ports:
            port_list = ports.split(',')
            port_list = [ int(x) for x in port_list ]
        else:
            # single port
            port_list = [int(ports)]

        return port_list

    @staticmethod
    def create_host_set(hosts):
        '''parse the hosts input, returns a set of ipaddress objects'''

        host_list_raw = []
        host_list = set()

        # assume the input is a file name
        if os.path.isfile(hosts):
            # open and parse the hosts file
            with open(hosts, 'r') as host_fd:
                host_list_raw = host_fd.read().splitlines()
        else:
            host_list_raw = [hosts]
        
        # parse the host_list_raw list
        for r in host_list_raw:
            if "-" in r:
                # range
                start, end = r.split('-')
                start_ip = ipaddress.IPv4Address(start)
                if "." in end:
                    end_ip = ipaddress.IPv4Address(end)
                else:
                    assert False, "[-] end IP address must be in dotted decimal form (e.g. 192.168.2.10)"

                expanded_ips = ipaddress.summarize_address_range(start_ip, end_ip)
                for ip in expanded_ips:
                    host_list.add(ip)

            elif "/" in r:
                # network id and mask
                network = ipaddress.IPv4Network(r)
                for ip in network.hosts():
                    host_list.add(ip)

            else:
                # single host
                ip = ipaddress.IPv4Address(r)
                host_list.add(r)

        return host_list

    # worker function
    def scan_worker(self, host, ports, url, results, index):
        '''performs a scan against a single host on all ports'''
        result = []
        for p in ports:
            if p == 80:
                protocol = ['http']
            elif p == 443:
                protocol = ['https']
            else:
                # try both
                protocol = ['http', 'https']

            for proto in protocol:
                try:
                    full_url = '%s://%s:%d%s' % (proto, host, p, url)
                    r = requests.get(full_url, verify=False, timeout=self.wait)

                    string_match = None
                    if self.match is not None:
                        # determine if the content contains the match string
                        # content is bytes, convert to string first
                        string_match = False
                        if self.match in str(r.content):
                            string_match = True

                    # add result
                    if r.url == full_url:
                        if string_match is None:
                            result.append('[*] %s - status: %d' % (r.url, r.status_code))
                        else:
                            result.append('[*] %s - status: %d, string match: %s' % (r.url, r.status_code, string_match))
                    else:
                        if string_match is None:
                            result.append('[*] REDIRECT %s to %s - status: %d' % (full_url, r.url, r.status_code))
                        else:
                            result.append('[*] REDIRECT %s to %s - status: %d, string match: %s' % (full_url, r.url, r.status_code, string_match))
                except:
                    result.append('[-] could not connect to %s:%s' % (host, p))

        results[index] = result

    def scan(self, output_fd):
        '''performs scan, reports results'''

        # create list from host set
        host_list = list(self.hosts)
        num_hosts_scanned = 0

        while len(host_list) > 0:
            # special case, last iteration
            if len(host_list) < self.threads:
                num_threads = len(host_list)
            else:
                num_threads = self.threads
            
            # create and start threads
            num_hosts_scanned += num_threads
            threads = []
            results = [None] * num_threads
            for i in range(num_threads):
                host = host_list.pop()
                t = threading.Thread(target=self.scan_worker, args=(host, self.ports, self.url, results, i,))
                threads.append(t)
                t.start()

            # wait for threads to finish
            for i in range(len(threads)):
                threads[i].join()

            for r in results:
                for s in r:
                    output_fd.write(s + "\n")


def main():
    '''main function'''
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('hosts', help='a list of hosts to scan')
    parser.add_argument('-p', '--ports', default='80,443')
    parser.add_argument('-u', '--url', default='/')
    parser.add_argument('-t', '--threads', type=int, default=1)
    parser.add_argument('-o', '--out', default=sys.stdout)
    parser.add_argument('-w', '--wait', type=int, default=10)
    parser.add_argument('-m', '--match-string')
    args = parser.parse_args()

    # gather arguments
    url = args.url
    ports = args.ports
    threads = args.threads
    hosts = args.hosts
    output = args.out
    wait = args.wait
    match = args.match_string
    if output != sys.stdout:
        if os.path.isfile(output):
            assert False, "[-] file %s already exists, exiting" % output
        else:
            output = open(output, 'w')

    # create scanner object and scan
    scanner = HTTPScan(url, ports, threads, hosts, wait, match)
    output.write("[*] scanning %s hosts on %s ports\n" % (scanner.num_hosts, scanner.num_ports))
    start_time = time.time()
    scanner.scan(output)
    end_time = time.time()
    output.write("[*] scanned %s hosts in %03f seconds\n" % (len(scanner.hosts), end_time - start_time))


def print_help():
    '''print help'''
    print("""Valid options:
   -h, --help       show this help and exit
   -p, --ports      a comma-separated list of ports to scan, defaults to 80 and 443
   -u, --url        a URL to scan those hosts for, defaults to "/"
   -t, --threads    number of threads to use for scanning
   -o, --out        name of output file, defaults to STDOUT
   -w, --wait       time to wait for a response in seconds, default is 10 seconds
   -m, --match-string
                    the scan results will indicate whether the content of the 
                    HTTP response received includes the provided string

   
   host(s) is one of the following:
       - a single IP address (e.g. 192.168.2.1)
       - a range of IP addresses (e.g. 192.168.2.1-192.168.2.12)
       - a network ID and subnet mask (e.g. 192.168.2.0/24)
       - a file containing a list of hosts/network ids and subnet masks, one per line""")


if __name__ == "__main__":
    main()
