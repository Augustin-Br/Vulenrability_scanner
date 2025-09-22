# Vulnerability Scanner

This project is a simple port and vulnerability scanner in Python. It uses the `nmap` library to scan a target and identifies known vulnerabilities based on a JSON database file.

---

## Project Files

* `scanner.py`: The main script that performs the port and vulnerability scan.
* `vuln_db.json`: The vulnerability database in JSON format. You can update it with new vulnerabilities.
* `.gitattributes`: A configuration file for Git.

---

## Prerequisites

Before running the scanner, you need to install the `python-nmap` library. You can do this with the following command:

```bash
pip install python-nmap
