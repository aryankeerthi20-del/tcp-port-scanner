import socket
import argparse
import sys
import csv
from concurrent.futures import ThreadPoolExecutor
import time
import requests
import json
common_port=[21,22,23,25,53,80,443,3306,3389,8080]
def portscanner(ip,i):
    with socket.socket() as s:
        s.settimeout(5)
        try:
            s.connect((ip,i))
            try:
                banner = s.recv(1024).decode().strip()
            except (socket.timeout,UnicodeDecodeError):
                banner = "no banner"
        
        except ConnectionRefusedError:
            return "closed",""
        except socket.timeout :
            return "Time out",""
        else:
            return "open" , banner
def cve_lookup(banner):
    cves = []
    if not banner or banner == "no banner":
        return []
    try:
        version = banner.split("_")[1].split(" ")[0].split("p")[0]
        service = banner.split("_")[0].split("-")[-1]
        search_term = service
    except IndexError:
        return []
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": search_term, "resultsPerPage": 5}
    try:
        response = requests.get(url, params=params, timeout=10)
        data = response.json()
        for item in data["vulnerabilities"]:
            cves.append(item["cve"]["id"])
    except Exception:
        return []
    return cves
parser = argparse.ArgumentParser(description="TCP Port Scanner")
parser.add_argument("-t", "--target", required=True, help="Target IP or hostname")
parser.add_argument("-m", "--mode", required=True, help="Scan mode: common, full, custom")
parser.add_argument("-p","--ports", help="range of the port")
parser.add_argument("-c","--custom",help="custom ports")
parser.add_argument("--threads",type=int,default=100)
args=parser.parse_args()
ip=args.target
try:
    ip = socket.gethostbyname(ip)
except socket.gaierror:
    print("Could not resolve hostname. Exiting.")
    sys.exit()
if args.mode == "common":
    ports = common_port
elif args.mode == "custom":
    if not args.custom:
        print("Error: custom mode requires -c flag")
        sys.exit()
    ports = list(map(int, args.custom.split()))
elif args.mode == "full":
    if not args.ports:
        print("Error: full mode requires -p flag e.g. 1-1000")
        sys.exit()
    parts = args.ports.split("-")
    stport = int(parts[0])
    edport = int(parts[1])
    if stport < 1 or edport > 65535 or stport > edport:
        print("Error: invalid port range")
        sys.exit()
    ports = range(stport, edport + 1)
else:
    print("Error: invalid mode. Choose common, full, or custom")
    sys.exit()
start = time.time()
with ThreadPoolExecutor(max_workers=args.threads) as executor:
    results = executor.map(lambda port: portscanner(ip, port), ports)
    open_ports=[]
    for port,(status,banner) in zip(ports, results):
        if status=="open":
            cves=cve_lookup(banner)
            open_ports.append({"port": port, "banner": banner, "cves":cves})
            print(port,"is the open port with banner: ",banner)
            if cves:
                print("cves found : ",cves)
        
end=time.time()
print("Target IP:",ip,"\nports scanned: ",len(list(ports)),"\nopen ports found :",len(open_ports))
print(f"Time taken: {end-start:.2f} seconds")
report = {
    "target": ip,
    "ports_scanned": len(list(ports)),
    "open_ports_found": len(open_ports),
    "time_taken": round(end - start, 2),
    "open_ports": open_ports
}
r=input("Enter whether report is required: ")
if r=="Yes" or r=="yes" or r=="y":
    with open("report.txt", "w") as f:
        f.write(f"Target IP: {ip}\n")
        f.write(f"Time taken: {end-start:.2f} seconds\n")
        for entry in open_ports:
            f.write(f"Port: {entry['port']} -- Banner: {entry['banner']}\n")
            f.write(f"CVEs: {entry['cves']}\n")        
z=input("Enter whether jsn report is required: ")
if z=="Yes" or z=="yes" or z=="y":
     with open("report.json", "w") as f:
        json.dump(report, f, indent=4)
x=input("Enter whethe csv report is required: ")

if x=="Yes" or x=="yes" or x=="y":
    
    with open("report.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["port", "banner", "cves"])
        for entry in open_ports:
            writer.writerow([entry["port"], entry["banner"], ", ".join(entry["cves"])])
