# Advanced Vulnerability Scanner

A dynamic vulnerability scanner that uses Nmap to identify services and their versions, then queries the National Vulnerability Database (NVD) for all known CVEs based on the detected software (CPE).

## Features

-   **Dynamic CVE Lookup**: Fetches real-time vulnerability data from the official NVD API.
-   **Version-Specific Analysis**: Uses CPE (Common Platform Enumeration) matching to find vulnerabilities that affect the specific versions of services detected.
-   **Automated PDF Reporting**: Generates a clean, color-coded PDF report summarizing the findings.
-   **No Manual Database**: The entire process is automated, requiring no manual updates to a vulnerability list.

## Prerequisites

-   **Python 3.8+**
-   **Nmap**: The scanner requires `nmap` to be installed on the system.

## Quickstart

1.  **Set up the environment and install dependencies:**
    ```bash
    # Create and activate a virtual environment
    python3 -m venv .venv
    source .venv/bin/activate

    # Install the required Python packages
    pip install -r requirements.txt
    ```

2.  **Run a scan:**
    ```bash
    # Default scan (top 1000 ports)
    python scanner.py <target_host>

    # Scan a specific port range
    python scanner.py <target_host> -p 1-500
    ```

## NVD API Key (Recommended)

For faster and more reliable scans, it is highly recommended to obtain a free API key from the [NVD website](https://nvd.nist.gov/developers/request-an-api-key) and set it as an environment variable:
```bash
export NVD_API_KEY="your-key-here"
```

## Full Documentation

For detailed instructions on setup, usage, and configuration, please see **[TUTORIAL.md](TUTORIAL.md)**.