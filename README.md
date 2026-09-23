#TCP Port Scanner
A multithreaded TCP port scanner built in Python with banner grabbing and automatic CVE lookup.
##Features include
-scan mode: common full , custom port(start and ending of the port scanning)
-service detection using banner grabbing.
-Automatic CVE lookup using NVD API
-Json and text report generation
-configurable thread count
-Hostname resolution
#Requirements
-pip install requests
#Usage Examples
\```
python scanner.py -t scanme.nmap.org -m common
python scanner.py -t 192.168.1.1 -m full -p 1-1000
python scanner.py -t target.com -m custom -c "22 80 443"
\```
##LEGAL TERMS
-only scan system you own or have permission for doing so.

