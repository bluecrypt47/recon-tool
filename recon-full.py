class AcunetixAPI:
    """Class to interact with Acunetix API."""
    
    def __init__(self, api_url, api_key, verify_ssl=False):
        """Initialize with Acunetix API URL and API key."""
        self.api_url = api_url.rstrip('/')
        self.headers = {
            'X-Auth': api_key,
            'Content-Type': 'application/json'
        }
        self.verify_ssl = verify_ssl
        
        # Disable SSL warnings if verification is disabled
        if not verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    def test_connection(self):
        """Test API connection."""
        try:
            response = requests.get(
                f"{self.api_url}/me", 
                headers=self.headers, 
                verify=self.verify_ssl
            )
            if response.status_code == 200:
                logger.info("✅ Successfully connected to Acunetix API")
                return True
            else:
                logger.error(f"❌ Failed to connect to Acunetix API: {response.status_code} - {response.text}")
                return False
        except Exception as e:
            logger.error(f"❌ Error connecting to Acunetix API: {str(e)}")
            return False
    
    def add_target(self, target_url, description):
        """Add a target to Acunetix."""
        try:
            payload = {
                "address": target_url,
                "description": description,
                "criticality": 10  # High criticality by default
            }
            response = requests.post(
                f"{self.api_url}/targets", 
                headers=self.headers, 
                data=json.dumps(payload),
                verify=self.verify_ssl
            )
            
            if response.status_code == 201:
                target_data = response.json()
                target_id = target_data.get('target_id')
                logger.info(f"✅ Added target: {target_url} (ID: {target_id})")
                return target_id
            else:
                logger.error(f"❌ Failed to add target: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"❌ Error adding target: {str(e)}")
            return None
    
    def add_targets_from_file(self, url_file, description_prefix="Recon"):
        """Add all targets from a URL file."""
        if not os.path.exists(url_file):
            logger.error(f"❌ URL file not found: {url_file}")
            return []
        
        target_ids = []
        with open(url_file, 'r') as f:
            for i, line in enumerate(f):
                url = line.strip()
                if not url:
                    continue
                
                description = f"{description_prefix} Target #{i+1}: {url}"
                target_id = self.add_target(url, description)
                if target_id:
                    target_ids.append(target_id)
                time.sleep(1)  # Avoid API rate limiting
        
        logger.info(f"✅ Added {len(target_ids)} targets to Acunetix")
        return target_ids
    
    def start_scan(self, target_id, scan_profile="Full Scan"):
        """Start a scan for the given target."""
        try:
            # Get scan profile ID
            profile_id = self._get_scan_profile_id(scan_profile)
            if not profile_id:
                return None
            
            payload = {
                "target_id": target_id,
                "profile_id": profile_id,
                "schedule": {
                    "disable": False,
                    "start_date": None,
                    "time_sensitive": False
                }
            }
            
            response = requests.post(
                f"{self.api_url}/scans", 
                headers=self.headers, 
                data=json.dumps(payload),
                verify=self.verify_ssl
            )
            
            if response.status_code == 201:
                scan_data = response.json()
                scan_id = scan_data.get('scan_id')
                logger.info(f"✅ Started scan for target ID {target_id} (Scan ID: {scan_id})")
                return scan_id
            else:
                logger.error(f"❌ Failed to start scan: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"❌ Error starting scan: {str(e)}")
            return None
    
    def _get_scan_profile_id(self, profile_name):
        """Get the scan profile ID by name."""
        try:
            response = requests.get(
                f"{self.api_url}/scanning_profiles", 
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                profiles = response.json().get('scanning_profiles', [])
                for profile in profiles:
                    if profile.get('name') == profile_name:
                        return profile.get('profile_id')
                
                logger.error(f"❌ Scan profile not found: {profile_name}")
                logger.info(f"Available profiles: {[p.get('name') for p in profiles]}")
                return None
            else:
                logger.error(f"❌ Failed to get scanning profiles: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"❌ Error getting scan profiles: {str(e)}")
            return None
    
    def get_scan_status(self, scan_id):
        """Get the status of a scan."""
        try:
            response = requests.get(
                f"{self.api_url}/scans/{scan_id}", 
                headers=self.headers,
                verify=self.verify_ssl
            )
            
            if response.status_code == 200:
                scan_data = response.json()
                return scan_data.get('current_session', {}).get('status')
            else:
                logger.error(f"❌ Failed to get scan status: {response.status_code} - {response.text}")
                return None
        except Exception as e:
            logger.error(f"❌ Error getting scan status: {str(e)}")
            return None
import os
import subprocess
import re
import argparse
import time
import logging
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import requests
import urllib3

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("recon.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class ReconTool:
    def __init__(self, domain, output_dir=None, max_workers=5, acunetix_config=None):
        """Initialize ReconTool with customizable parameters."""
        self.domain = domain
        
        # Use domain name for the output directory if not specified
        if output_dir is None:
            # Remove wildcards if present and use domain as directory name
            self.output_dir = domain.replace("*.", "").replace(".", "_")
        else:
            self.output_dir = output_dir
            
        self.max_workers = max_workers
        self.acunetix_config = acunetix_config
        self.acunetix_api = None
        
        # Initialize Acunetix API if config is provided
        if self.acunetix_config:
            verify_ssl = self.acunetix_config.get('verify_ssl', False)
            self.acunetix_api = AcunetixAPI(
                self.acunetix_config.get('api_url', ''),
                self.acunetix_config.get('api_key', ''),
                verify_ssl
            )
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Define output files
        self.subfinder_httpx_file = os.path.join(self.output_dir, "output-subfinder-httpx.txt")
        self.urls_file = os.path.join(self.output_dir, "list-urls.txt")
        self.nuclei_output = os.path.join(self.output_dir, "output-nuclei.txt")
        self.js_files = os.path.join(self.output_dir, "js.txt")
        self.js_bugs = os.path.join(self.output_dir, "js_bugs.txt")

    def check_tools(self):
        """Check if required tools are installed."""
        required_tools = ["subfinder", "httpx", "nuclei", "katana"]
        missing_tools = []
        
        for tool in required_tools:
            try:
                subprocess.run([tool, "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
                logger.info(f"✅ {tool} is installed")
            except FileNotFoundError:
                logger.error(f"❌ {tool} is not installed")
                missing_tools.append(tool)
        
        if missing_tools:
            logger.error(f"Please install the following tools: {', '.join(missing_tools)}")
            return False
        return True

    def run_command(self, command, description, output_file=None):
        """Run a shell command and log its output."""
        try:
            logger.info(f"Running: {description}")
            logger.info(f"Command: {command}")
            
            start_time = time.time()
            
            if output_file:
                with open(output_file, 'w') as f:
                    process = subprocess.run(
                        command, 
                        shell=True,
                        stdout=f,
                        stderr=subprocess.PIPE,
                        text=True,
                        check=True
                    )
            else:
                process = subprocess.run(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    check=True
                )
            
            elapsed_time = time.time() - start_time
            logger.info(f"✅ Completed in {elapsed_time:.2f} seconds")
            
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Command failed: {e}")
            logger.error(f"Error output: {e.stderr}")
            return False

    def enumerate_subdomains(self, domain):
        """Run subfinder and httpx to enumerate and probe subdomains."""
        command = f"subfinder -d {domain} -silent | httpx -title -tech-detect -ip --no-color -status-code -mc 200 -o {self.subfinder_httpx_file}"
        return self.run_command(command, "Subdomain enumeration and probing", self.subfinder_httpx_file)

    def extract_urls(self):
        """Extract URLs from the subfinder+httpx output file."""
        if not os.path.exists(self.subfinder_httpx_file):
            logger.error(f"File not found: {self.subfinder_httpx_file}")
            return False

        try:
            # Extract URLs with regex pattern
            with open(self.subfinder_httpx_file, 'r') as infile, open(self.urls_file, 'w') as outfile:
                content = infile.read()
                # Match URLs (http/https) from the output
                urls = re.findall(r'(https?://[^\s]+)', content)
                
                # Remove any potential trailing fields that httpx might have added
                clean_urls = [url.split('[')[0].strip() for url in urls]
                
                # Write clean URLs to output file
                for url in clean_urls:
                    outfile.write(f"{url}\n")
            
            # Count extracted URLs
            with open(self.urls_file, 'r') as f:
                url_count = sum(1 for _ in f)
            
            logger.info(f"✅ Extracted {url_count} URLs to {self.urls_file}")
            return True
        
        except Exception as e:
            logger.error(f"❌ Failed to extract URLs: {str(e)}")
            return False

    def run_nuclei_scan(self):
        """Run Nuclei scanner on the list of URLs."""
        command = f"nuclei -l {self.urls_file} -as -rl 3 -pc 20 -timeout 10 -retries 3 -max-host-error 50 -o {self.nuclei_output}"
        return self.run_command(command, "Nuclei vulnerability scanning", self.nuclei_output)

    def extract_js_files(self):
        """Extract JavaScript files using katana and httpx."""
        command = f"cat {self.urls_file} | katana | grep js | httpx -mc 200 | tee {self.js_files}"
        return self.run_command(command, "JavaScript file extraction", self.js_files)

    def scan_js_files(self, nuclei_templates_path="~/nuclei-templates"):
        """Scan JavaScript files for exposures using Nuclei."""
        command = f"nuclei -l {self.js_files} -t {nuclei_templates_path}/exposures/ -o {self.js_bugs}"
        return self.run_command(command, "JavaScript vulnerability scanning", self.js_bugs)

    def prepare_acunetix(self):
        """Prepare URL list for Acunetix scan."""
        if os.path.exists(self.urls_file):
            logger.info(f"✅ URL list ready for Acunetix scan at: {self.urls_file}")
            
            # If Acunetix API is configured, add targets and start scans
            if self.acunetix_api and self.acunetix_api.test_connection():
                logger.info("Starting Acunetix integration...")
                description_prefix = f"Recon for {self.domain}"
                
                # Add targets from URL file
                target_ids = self.acunetix_api.add_targets_from_file(self.urls_file, description_prefix)
                if not target_ids:
                    logger.warning("No targets were added to Acunetix")
                    return True
                
                # Start scans for each target
                scan_profile = self.acunetix_config.get('scan_profile', 'Full Scan')
                scan_ids = []
                
                for target_id in target_ids:
                    scan_id = self.acunetix_api.start_scan(target_id, scan_profile)
                    if scan_id:
                        scan_ids.append(scan_id)
                    time.sleep(1)  # Avoid API rate limiting
                
                logger.info(f"✅ Started {len(scan_ids)} Acunetix scans")
                
                # Save scan information to a file
                scan_info = {
                    'domain': self.domain,
                    'target_ids': target_ids,
                    'scan_ids': scan_ids,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                
                with open(os.path.join(self.output_dir, "acunetix_scans.json"), 'w') as f:
                    json.dump(scan_info, f, indent=2)
                
                logger.info(f"✅ Acunetix scan information saved to {os.path.join(self.output_dir, 'acunetix_scans.json')}")
            else:
                logger.info("To use with Acunetix, import this file into your Acunetix scanner or configure the API.")
            
            return True
        else:
            logger.error(f"❌ URL list file not found: {self.urls_file}")
            return False

    def summarize_results(self):
        """Summarize the reconnaissance results."""
        summary = "\n" + "="*50 + "\n"
        summary += "RECONNAISSANCE SUMMARY\n"
        summary += "="*50 + "\n\n"
        
        # Count unique subdomains
        if os.path.exists(self.urls_file):
            with open(self.urls_file, 'r') as f:
                urls = f.readlines()
                summary += f"Total unique URLs: {len(urls)}\n"
        
        # Count Nuclei findings
        if os.path.exists(self.nuclei_output):
            with open(self.nuclei_output, 'r') as f:
                findings = f.readlines()
                summary += f"Nuclei findings: {len(findings)}\n"
                
                # Count by severity if available
                severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
                for finding in findings:
                    for severity in severity_counts.keys():
                        if f"[{severity}]" in finding.lower():
                            severity_counts[severity] += 1
                
                for severity, count in severity_counts.items():
                    if count > 0:
                        summary += f"  - {severity.capitalize()}: {count}\n"
        
        # Count JS files
        if os.path.exists(self.js_files):
            with open(self.js_files, 'r') as f:
                js_files = f.readlines()
                summary += f"JavaScript files: {len(js_files)}\n"
        
        # Count JS vulnerabilities
        if os.path.exists(self.js_bugs):
            with open(self.js_bugs, 'r') as f:
                js_bugs = f.readlines()
                summary += f"JavaScript vulnerabilities: {len(js_bugs)}\n"
        
        summary += "\n" + "="*50 + "\n"
        logger.info(summary)
        
        # Write summary to file
        with open(os.path.join(self.output_dir, "summary.txt"), 'w') as f:
            f.write(summary)
        
        return True

    def full_recon(self, nuclei_templates_path="~/nuclei-templates"):
        """Run the complete reconnaissance workflow."""
        logger.info(f"Starting full reconnaissance for: {self.domain}")
        
        if not self.check_tools():
            return False
            
        steps = [
            (self.enumerate_subdomains, [self.domain], "Subdomain enumeration"),
            (self.extract_urls, [], "URL extraction"),
            (self.run_nuclei_scan, [], "Nuclei scanning"),
            (self.extract_js_files, [], "JavaScript extraction"),
            (self.scan_js_files, [nuclei_templates_path], "JavaScript scanning"),
            (self.prepare_acunetix, [], "Acunetix preparation"),
            (self.summarize_results, [], "Results summarization")
        ]
        
        for step_func, args, description in steps:
            logger.info(f"\n{'='*20} {description.upper()} {'='*20}")
            result = step_func(*args)
            if not result:
                logger.error(f"❌ {description} failed. Check the logs for details.")
                # Continue with next step instead of stopping
        
        logger.info(f"\n{'='*20} RECONNAISSANCE COMPLETED {'='*20}")
        logger.info(f"All results are saved in: {os.path.abspath(self.output_dir)}")
        return True


def main():
    parser = argparse.ArgumentParser(description="Automated Reconnaissance Tool")
    parser.add_argument("domain", help="Target domain (e.g., example.com or *.example.com)")
    parser.add_argument("--output-dir", "-o", default=None, 
                        help="Output directory (defaults to domain name)")
    parser.add_argument("--templates-path", "-t", default="~/nuclei-templates", 
                        help="Path to Nuclei templates")
    parser.add_argument("--workers", "-w", type=int, default=5, 
                        help="Maximum number of concurrent workers")
    
    # Acunetix API configuration
    parser.add_argument("--acunetix-url", default=None,
                        help="Acunetix API URL (e.g., https://localhost:3443/api/v1)")
    parser.add_argument("--acunetix-key", default=None,
                        help="Acunetix API Key")
    parser.add_argument("--acunetix-profile", default="Full Scan",
                        help="Acunetix scan profile (default: Full Scan)")
    parser.add_argument("--verify-ssl", action="store_true",
                        help="Verify SSL certificates when connecting to Acunetix (default: False)")
    
    args = parser.parse_args()
    
    # Set up Acunetix configuration if API URL and key are provided
    acunetix_config = None
    if args.acunetix_url and args.acunetix_key:
        acunetix_config = {
            'api_url': args.acunetix_url,
            'api_key': args.acunetix_key,
            'scan_profile': args.acunetix_profile,
            'verify_ssl': args.verify_ssl
        }
    
    recon = ReconTool(domain=args.domain, output_dir=args.output_dir, 
                     max_workers=args.workers, acunetix_config=acunetix_config)
    recon.full_recon(args.templates_path)


if __name__ == "__main__":
    main()