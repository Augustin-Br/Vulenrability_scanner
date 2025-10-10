
import nmap
import requests
import json
import argparse
import os
from fpdf import FPDF
from fpdf.enums import XPos, YPos
import datetime
import time

# --- Configuration ---
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REPORT_FILE = "vulnerability_report.pdf"
NVD_API_KEY = os.getenv("NVD_API_KEY")  # Get API key from environment variable

# --- Helper Functions ---

def get_cve_details_by_cpe(cpe_string):
    """Fetches all CVEs for a given CPE from the NVD API."""
    headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
    params = {'cpeName': cpe_string, 'resultsPerPage': 200}
    vulnerabilities = []
    
    try:
        print(f"[*] Querying NVD for CPE: {cpe_string}")
        response = requests.get(NVD_API_URL, params=params, headers=headers, timeout=30)
        response.raise_for_status()
        data = response.json()
        
        total_results = data.get('totalResults', 0)
        if total_results == 0:
            return []

        for vuln in data.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id', 'N/A')
            summary = "No summary available."
            for desc in cve.get('descriptions', []):
                if desc.get('lang') == 'en':
                    summary = desc.get('value', summary)
                    break
            
            cvss_score = None
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            elif 'cvssMetricV2' in metrics:
                cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']

            vulnerabilities.append({
                "id": cve_id,
                "summary": summary,
                "cvss": cvss_score
            })
        
        # NVD API has a delay in publishing, so we add a small sleep to avoid rate limiting
        time.sleep(1) # Be a good internet citizen
        return vulnerabilities

    except requests.exceptions.RequestException as e:
        print(f"[-] Error fetching CVEs for CPE {cpe_string}: {e}")
        return []

def scan_target(target, ports=None):
    """
    Scans the target using nmap to identify services, versions, and CPEs,
    then fetches vulnerabilities for those CPEs.
    """
    print(f"[*] Starting advanced scan on {target}...")
    nm = nmap.PortScanner()
    arguments = "-sV -T4 --script vulners,vuln"
    if ports:
        arguments = f"-p {ports} {arguments}"

    nm.scan(hosts=target, arguments=arguments)

    results = {"host": target, "ports": []}
    
    if not nm.all_hosts():
        print(f"[-] Host {target} not found or is not responding.")
        return None

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in sorted(lport):
                service_info = nm[host][proto][port]
                
                port_info = {
                    "port": port,
                    "protocol": proto,
                    "service": service_info.get('name', 'unknown'),
                    "product": service_info.get('product', ''),
                    "version": service_info.get('version', ''),
                    "vulnerabilities": []
                }

                # Attempt to find CPE and get vulnerabilities
                if 'cpe' in service_info and service_info['cpe']:
                    # Nmap can return multiple CPEs, we'll use the first one and format it for the API
                    cpe_raw = service_info['cpe'].split(' ')[0]
                    # Convert to cpe:2.3 format if it's in the older format
                    if cpe_raw.startswith('cpe:/'):
                        cpe = 'cpe:2.3:' + cpe_raw[5:] + ':*:*:*:*:*:*:*'
                    else:
                        cpe = cpe_raw

                    vulns = get_cve_details_by_cpe(cpe)
                    if vulns:
                        print(f"[!] Found {len(vulns)} vulnerabilities for {port_info['product']} on port {port}")
                        port_info["vulnerabilities"].extend(vulns)
                
                results["ports"].append(port_info)
    
    print("[*] Scan finished.")
    return results

# --- Scoring Functions ---

def calculate_score(results):
    """Calculates a security score out of 100 based on CVSS scores."""
    if not results:
        return 100

    max_score = 100
    total_penalty = 0
    
    for port in results.get("ports", []):
        for vuln in port.get("vulnerabilities", []):
            cvss = vuln.get("cvss")
            if isinstance(cvss, (int, float)):
                total_penalty += cvss ** 2
            else:
                total_penalty += 25 

    normalized_penalty = min(100, (total_penalty / 1000) * 100)
    
    final_score = max(0, max_score - normalized_penalty)
    return round(final_score, 2)

# --- PDF Report Generation Functions (Identical to previous version) ---

class PDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 10, 'Vulnerability Scan Report', new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.set_font('Helvetica', '', 8)
        self.cell(0, 10, f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', align='C')

    def chapter_title(self, title):
        self.set_font('Helvetica', 'B', 12)
        self.cell(0, 10, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        self.ln(4)

    def chapter_body(self, body):
        self.set_font('Helvetica', '', 10)
        self.multi_cell(0, 5, body)
        self.ln()

    def add_vulnerability_details(self, port_info):
        self.set_font('Helvetica', 'B', 10)
        self.cell(0, 10, f"Port {port_info['port']}/{port_info['protocol']} - {port_info['product']} {port_info['version']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='L')
        
        if not port_info['vulnerabilities']:
            self.set_font('Helvetica', '', 10)
            self.set_text_color(0, 128, 0) # Green
            self.cell(0, 5, "  No known vulnerabilities found based on detected CPE.")
            self.set_text_color(0, 0, 0) # Black
            self.ln()
            return

        for vuln in port_info['vulnerabilities']:
            cvss = vuln.get("cvss")
            
            if isinstance(cvss, (int, float)):
                if cvss >= 9.0: self.set_text_color(255, 0, 0)       # Critical
                elif cvss >= 7.0: self.set_text_color(255, 165, 0)   # High
                elif cvss >= 4.0: self.set_text_color(255, 255, 0)   # Medium
                else: self.set_text_color(0, 0, 0)                   # Low
            else: self.set_text_color(128, 128, 128)                 # Unknown

            self.set_font('Helvetica', 'B', 10)
            cvss_text = f" | CVSS: {cvss}" if isinstance(cvss, (int, float)) else ""
            self.cell(0, 5, f"  - CVE: {vuln.get('id', 'N/A')}{cvss_text}")
            self.ln()
            
            self.set_text_color(0, 0, 0)
            self.set_font('Helvetica', '', 9)
            summary = vuln.get('summary', 'No summary available.')
            self.multi_cell(0, 5, f"    Summary: {summary}")
            self.ln(2)

def generate_pdf_report(results, score):
    if not results:
        print("[-] No data to include in the report.")
        return

    pdf = PDF()
    pdf.add_page()
    try:
        pdf.add_font("DejaVu", "", "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", uni=True)
        pdf.set_font("DejaVu", size=10)
    except RuntimeError:
        print("[-] DejaVu font not found. Using Helvetica. Non-ASCII characters may not render correctly.")
        pdf.set_font("Helvetica", size=10)

    pdf.chapter_title("Scan Summary")
    pdf.chapter_body(f"Scanned Host: {results['host']}")
    
    pdf.set_font('Helvetica', 'B', 14)
    if score < 50: score_color = (255, 0, 0)
    elif score < 80: score_color = (255, 165, 0)
    else: score_color = (0, 128, 0)
    
    pdf.set_text_color(*score_color)
    pdf.cell(0, 10, f"Overall Security Score: {score}/100", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
    pdf.set_text_color(0, 0, 0)
    pdf.ln(10)

    pdf.chapter_title("Port and Vulnerability Details")
    for port in results.get("ports", []):
        pdf.add_vulnerability_details(port)

    try:
        pdf.output(REPORT_FILE)
        print(f"[+] PDF report generated successfully: '{REPORT_FILE}'")
    except Exception as e:
        print(f"[-] Error generating PDF report: {e}")

# --- Main Execution ---

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="An advanced vulnerability scanner that uses Nmap to find services and queries the NVD for CVEs based on detected CPEs.",
        epilog="For better results, it is recommended to set an NVD_API_KEY environment variable. You can get one from the NVD website."
    )
    parser.add_argument("target", help="The IP address or hostname of the target to scan.")
    parser.add_argument("-p", "--ports", help="Specify ports to scan (e.g., 1-1000, 80, 443). Scans top 1000 ports by default.")
    
    args = parser.parse_args()

    if NVD_API_KEY:
        print("[*] Using NVD API key.")
    else:
        print("[!] NVD_API_KEY environment variable not set. Scans may be slower or rate-limited.")

    scan_results = scan_target(args.target, args.ports)
    
    if scan_results:
        security_score = calculate_score(scan_results)
        print(f"[*] Overall security score: {security_score}/100")
        generate_pdf_report(scan_results, security_score)
