# How to Use the Advanced Vulnerability Scanner

## 1. Introduction

This tool is an advanced vulnerability scanner that automates the process of identifying security risks on a target system. Unlike basic scanners that rely on a manual, static database, this script operates dynamically:

1.  It uses **Nmap** to perform a detailed scan, identifying open ports, running services, and, most importantly, the specific **versions** of that software.
2.  It converts the software version information into a standardized format called **CPE (Common Platform Enumeration)**.
3.  It queries the official **National Vulnerability Database (NVD)** using this CPE to find all publicly known vulnerabilities (CVEs) that affect that specific software version.
4.  Finally, it calculates a security score and generates a detailed **PDF report** with its findings, color-coding vulnerabilities by severity.

## 2. Prerequisites

Before you begin, ensure you have the following installed on your system:

*   **Python 3.8+**
*   **Nmap**: The scanner relies on the `nmap` command-line tool. You must install it separately.
    *   **On Debian/Ubuntu**: `sudo apt-get update && sudo apt-get install nmap`
    *   **On Fedora/CentOS**: `sudo dnf install nmap`
    *   **On macOS (using Homebrew)**: `brew install nmap`

## 3. Setup & Installation

Follow these steps to set up the scanner and its dependencies.

**Step 1: Clone the Repository (if applicable)**
If the project is in a Git repository, clone it:
```bash
git clone <repository_url>
cd <repository_directory>
```
If you just have the files, navigate to the project directory.

**Step 2: Create and Activate a Python Virtual Environment**
It is highly recommended to use a virtual environment to avoid conflicts with system-wide packages.

```bash
# Create the virtual environment
python3 -m venv .venv

# Activate it
# On Linux/macOS:
source .venv/bin/activate
# On Windows:
# .venv\Scripts\activate
```

**Step 3: Install Required Packages**
Use the `requirements.txt` file to install all the necessary Python libraries.
```bash
pip install -r requirements.txt
```

## 4. Configuration: NVD API Key (Recommended)

The scanner queries the National Vulnerability Database (NVD) for CVE information. While it can work without an API key, you may encounter rate limits, which can slow down or block scans. Requesting a free API key is highly recommended for faster and more reliable results.

1.  **Get a Key**: Visit the [NVD API Key Request Page](https://nvd.nist.gov/developers/request-an-api-key) and follow the instructions.
2.  **Set the Environment Variable**: Once you have your key, set it as an environment variable named `NVD_API_KEY`.

    *   **On Linux/macOS (for the current session)**:
        ```bash
        export NVD_API_KEY="your-api-key-here"
        ```
    *   To make it permanent, add the line above to your shell's startup file (e.g., `~/.bashrc`, `~/.zshrc`).

The script will automatically detect and use the API key if the environment variable is set.

## 5. How to Run a Scan

Ensure your virtual environment is activated before running any commands. The basic command structure is:
```bash
python scanner.py <target> [options]
```

**Examples:**

*   **Default Scan (Top 1000 Ports)**
    This is the most common type of scan.
    ```bash
    python scanner.py scanme.nmap.org
    ```

*   **Scan a Specific List of Ports**
    Use the `-p` or `--ports` flag, separating ports with a comma.
    ```bash
    python scanner.py 192.168.1.1 -p 22,80,443
    ```

*   **Scan a Range of Ports**
    ```bash
    python scanner.py 192.168.1.1 -p 1-500
    ```

*   **Scan All Ports (1-65535)**
    **Warning**: This is a very slow and intensive scan that can take a long time.
    ```bash
    python scanner.py 192.168.1.1 -p-
    ```

## 6. Understanding the Output

**In the Terminal:**
While the scan is running, you will see real-time progress, including:
*   The start of the Nmap scan.
*   Notifications when the script queries the NVD for a specific CPE.
*   A summary of vulnerabilities found for each service.
*   The final, calculated security score.

**The PDF Report (`vulnerability_report.pdf`):**
After the scan finishes, a PDF report will be generated in the project directory. It contains:
*   **Scan Summary**: The target host and the date of the scan.
*   **Overall Security Score**: A score from 0 to 100. The score is penalized based on the number and severity (CVSS score) of the vulnerabilities found.
*   **Port and Vulnerability Details**: A list of all scanned ports that were found to be open.
    *   For each service, the report lists all the CVEs found.
    *   **Color Coding**: Vulnerabilities are colored based on their CVSS score for easy identification:
        *   <span style="color:red;">**Red (9.0+)**: Critical</span>
        *   <span style="color:orange;">**Orange (7.0 - 8.9)**: High</span>
        *   <span style="color:yellow;">**Yellow (4.0 - 6.9)**: Medium</span>
        *   **Gray**: Unknown/Not Scored

## 7. Limitations

*   **CPE Identification is Key**: The scanner's effectiveness depends on Nmap's ability to accurately identify a service's version and a corresponding CPE. If a CPE cannot be determined, no vulnerabilities will be fetched for that service.
*   **API Limitations**: The NVD API may not return results for very generic CPEs (e.g., a base Linux kernel).
*   **This is not a replacement for a professional security audit.** It is a powerful automated tool for discovery but should be one part of a comprehensive security strategy.
