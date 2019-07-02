# Mini HTTP Scanner

Simple script that scans web ports for particular URLs.

# Usage

<pre>mini_http_scanner.py [OPTIONS] host(s)
Valid options:
   -h, --help      show this help and exit
   -p, --ports=    a comma-separated list of ports to scan, defaults to 80 and 443
   -u, --url=      a URL to scan those hosts for, defaults to "/"
   -t, --threads   number of threads to use for scanning
   -o, --out       name of output file, defaults to STDOUT
   
   host(s) is one of the following:
       - a single IP address (e.g. 192.168.2.1)
       - a range of IP addresses (e.g. 192.168.2.10-192.168.2.12)
       - a network ID and subnet mask (e.g. 192.168.2.0/24)
       - a file containing a list of hosts/network ids and subnet masks, one per line
</pre>
