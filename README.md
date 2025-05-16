# Reconnaissance Automation Tool

A comprehensive security reconnaissance tool that automates subdomain enumeration, vulnerability scanning, and integrates with Acunetix for thorough security testing.

## Features

- **Subdomain Enumeration**: Discover active subdomains using `subfinder` and `httpx`
- **Vulnerability Scanning**: Automatically scan discovered endpoints with `nuclei`
- **JavaScript Analysis**: Extract and scan JavaScript files for security issues
- **Acunetix Integration**: Automatically upload targets and initiate scans in Acunetix

## Prerequisites

- Python 3.6+
- Required command-line tools:
  - [subfinder](https://github.com/projectdiscovery/subfinder)
  - [httpx](https://github.com/projectdiscovery/httpx)
  - [nuclei](https://github.com/projectdiscovery/nuclei)
  - [katana](https://github.com/projectdiscovery/katana)
  - OR: Alls recon tool [Tools][https://docs.projectdiscovery.io/tools]
- Optional:
  - Acunetix Web Vulnerability Scanner (for automatic scanning)
  - OR: [Github][https://github.com/securi3ytalent/acunetix-13-kali-linux]

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/recon-tool.git
cd recon-tool

# Make the script executable
chmod +x recon_tool.py
```

## Usage

### Basic Usage

```bash
python recon_tool.py example.com
```

This will:
1. Enumerate subdomains for example.com
2. Save active URLs to a file
3. Scan these URLs with Nuclei
4. Extract and analyze JavaScript files
5. Generate a summary of findings

### Command-line Options

```
python recon_tool.py [-h] [--output-dir OUTPUT_DIR] [--templates-path TEMPLATES_PATH]
                      [--workers WORKERS] [--acunetix-url ACUNETIX_URL]
                      [--acunetix-key ACUNETIX_KEY] [--acunetix-profile ACUNETIX_PROFILE]
                      domain
```

Arguments:
- `domain`: Target domain (e.g., example.com or *.example.com)
- `--output-dir`, `-o`: Custom output directory (defaults to domain name)
- `--templates-path`, `-t`: Path to Nuclei templates (default: ~/nuclei-templates)
- `--workers`, `-w`: Maximum number of concurrent workers (default: 5)
- `--acunetix-url`: Acunetix API URL (e.g., https://localhost:3443/api/v1)
- `--acunetix-key`: Acunetix API Key
- `--acunetix-profile`: Acunetix scan profile (default: Full Scan)

### Examples

```bash
# Basic scan with default settings
python recon_tool.py example.com

# Using wildcards for subdomain
python recon_tool.py *.example.com

# Custom output directory
python recon_tool.py example.com -o example_scan_results

# Using a different Nuclei templates path
python recon_tool.py example.com -t /path/to/nuclei-templates

# With Acunetix integration
python recon_tool.py example.com --acunetix-url https://localhost:3443/api/v1 --acunetix-key YOUR_API_KEY
```

## Output Files

All scan results are saved in the output directory (domain name by default):

- `output-subfinder-httpx.txt`: Raw output from subfinder and httpx
- `list-urls.txt`: Extracted URLs for scanning
- `output-nuclei.txt`: Vulnerabilities found by Nuclei
- `js.txt`: JavaScript files discovered
- `js_bugs.txt`: Vulnerabilities found in JavaScript files
- `acunetix_scans.json`: Acunetix scan information (if using the API)
- `summary.txt`: Summary of reconnaissance results
- `recon.log`: Detailed logs of the entire process

## Acunetix Integration

To use the Acunetix integration:

1. Make sure you have access to an Acunetix instance
2. Get your API key from the Acunetix UI
3. Run the tool with the `--acunetix-url` and `--acunetix-key` parameters

```bash
python recon_tool.py example.com --acunetix-url https://acunetix.local:3443/api/v1 --acunetix-key YOUR_API_KEY
```

The tool will:
- Add all discovered URLs as targets in Acunetix
- Start scans for each target
- Save the target and scan IDs to `acunetix_scans.json`

## Workflow

1. The tool first checks if all required tools are installed
2. It enumerates subdomains using subfinder and probes them with httpx
3. URLs are extracted and saved to a file
4. Nuclei is used to scan for common vulnerabilities
5. JavaScript files are extracted and analyzed
6. If Acunetix integration is enabled, targets are added and scans are started
7. A summary of findings is generated

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for security professionals to use for authorized security testing only. Always ensure you have permission to scan the target domains.
