import nmap
import argparse
import requests
import json


def scan_target(target, ports="1-1000"):
    nm = nmap.PortScanner()
    nm.scan(hosts=target, arguments=f"-p {ports} -sV")
    
    
    def check_vulnerabilities(services):
        with open("vuln_db.json", "r") as f:
            vuln_db = json.load(f)
        
        for port, service in services:
            if service in vuln_db:
                print(f"\nVulnerability detected for {service} on the port {port} : {', '.join(vuln_db[service])}")

    
    results = []
    for host in nm.all_hosts():
        print(f"\n[+] Results for {host}:")
        for proto in nm[host].all_protocols():
            print(f"  > Protocol : {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]['name']
                print(f"  - Port {port}: {service} | Vulnerabilities", check_vulnerabilities([(port, service)]))
                results.append((port, service))
    return results


target = input("Enter the target IP : ")
ports = input("Enter the ports to scan (default: 1-1000) : ")

if ports == "":
    ports = "1-1000"

scan_target(target, ports)