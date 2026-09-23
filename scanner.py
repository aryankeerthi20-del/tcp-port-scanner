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
def cve_lookup(banner: str, api_key: str = None) -> list:
    if not banner or banner.strip().lower() == "no banner":
        return []
    try:
        parts = banner.split("_")
        service_part = parts[0]
        service = service_part.split("-")[0].lower()
        raw_version = service_part.split("-")[-1]
        version = raw_version.split("p")[0]
    except (IndexError, AttributeError):
        return []
    url = "https://nist.gov"
    cpe_match = f"cpe:2.3:a:*:{service}:{version}"

    params = {
        "virtualMatchString": cpe_match, 
        "resultsPerPage": 10
    }
    
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = requests.get(url, params=params, headers=headers, timeout=5)
        if response.status_code != 200:
            return []
            
        data = response.json()
        return [item["cve"]["id"] for item in data.get("vulnerabilities", [])]
        
    except (requests.RequestException, KeyError, ValueError):
        return []
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
