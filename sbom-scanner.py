import argparse
import os
import json
import requests
import logging
from packaging import version

# Configure logging
logging.basicConfig(
    filename='sbom_scanner.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# API configurations
CVE_API_BASE_URL = "https://cve.circl.lu/api"  # Example CVE API
CWE_API_BASE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml"  # Example CWE API

def fetch_cve_details(package_name, current_version):
    """
    Fetch CVE details for a given package and version.
    """
    url = f"{CVE_API_BASE_URL}/search/{package_name}"
    response = requests.get(url)
    
    if response.status_code == 200:
        vulnerabilities = response.json()
        matching_vulns = [
            vuln for vuln in vulnerabilities 
            if version.parse(current_version) in version.parse(vuln.get("version_range", ""))
        ]
        return matching_vulns
    else:
        logging.error(f"Failed to fetch CVE details for {package_name}. Status code: {response.status_code}")
        return []

def fetch_cwe_details(cwe_id):
    """
    Fetch CWE details for a given CWE ID.
    """
    response = requests.get(CWE_API_BASE_URL)
    if response.status_code == 200:
        cwe_data = response.text
        # Parsing logic would go here if CWE data format was JSON or XML parsing required
        return cwe_data  # Simplified; should process XML and return useful details
    else:
        logging.error(f"Failed to fetch CWE details. Status code: {response.status_code}")
        return None

def parse_sbom_file(file_path):
    """
    Parse a given SBOM file (JSON, XML, or TXT) to extract dependency details.
    """
    try:
        with open(file_path, 'r') as file:
            if file_path.endswith('.json'):
                return json.load(file)
            elif file_path.endswith('.xml'):
                # Use XML parsing library like xml.etree.ElementTree
                raise NotImplementedError("XML parsing not implemented in this example.")
            elif file_path.endswith('.txt'):
                return [line.strip() for line in file.readlines()]
            else:
                raise ValueError("Unsupported file format.")
    except Exception as e:
        logging.error(f"Error parsing SBOM file {file_path}: {e}")
        return None

def compare_versions(package_list):
    """
    Compare the current version of each package with the latest available.
    """
    results = []
    for package in package_list:
        package_name = package.get("name")
        current_version = package.get("version")
        # Logic to fetch the latest version from an online source
        latest_version = current_version  # Replace with actual latest version fetch logic
        results.append({
            "package": package_name,
            "current_version": current_version,
            "latest_version": latest_version
        })
    return results

def generate_vulnerability_report(dependencies):
    """
    Generate a detailed vulnerability report for a list of dependencies.
    """
    report = []
    for dependency in dependencies:
        name = dependency.get("name")
        current_version = dependency.get("version")
        cves = fetch_cve_details(name, current_version)
        for cve in cves:
            cwe_id = cve.get("cwe_id")
            cwe_details = fetch_cwe_details(cwe_id)
            report.append({
                "package": name,
                "version": current_version,
                "cve_id": cve.get("id"),
                "description": cve.get("summary"),
                "cwe_details": cwe_details
            })
    return report

def main():
    # CLI argument parsing
    parser = argparse.ArgumentParser(description="SBOM Scanner for vulnerabilities.")
    parser.add_argument("sbom_file", help="Path to the SBOM file (JSON, XML, or TXT).")
    args = parser.parse_args()

    sbom_file_path = args.sbom_file
    if not os.path.exists(sbom_file_path):
        logging.error(f"SBOM file not found: {sbom_file_path}")
        print(f"SBOM file not found: {sbom_file_path}")
        return

    print(f"Scanning SBOM file: {sbom_file_path}")
    dependencies = parse_sbom_file(sbom_file_path)
    if not dependencies:
        logging.error("Failed to parse SBOM file or no dependencies found.")
        print("Failed to parse SBOM file or no dependencies found.")
        return

    # Generate version comparison
    comparison_table = compare_versions(dependencies)
    print("Version Comparison Table:")
    for entry in comparison_table:
        print(f"{entry['package']}: Current Version: {entry['current_version']} | Latest Version: {entry['latest_version']}")

    # Generate vulnerability report
    vulnerability_report = generate_vulnerability_report(dependencies)
    print("\nVulnerability Report:")
    for entry in vulnerability_report:
        print(f"Package: {entry['package']}, Version: {entry['version']}, CVE ID: {entry['cve_id']}")
        print(f"Description: {entry['description']}")
        print(f"CWE Details: {entry['cwe_details']}\n")

    logging.info("SBOM scan completed successfully.")
    print("SBOM scan completed successfully.")

if __name__ == "__main__":
    main()
