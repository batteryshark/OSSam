#!/usr/bin/env python3
import nvdlib
import time
import random
import sys
import json

def sleep_with_jitter(base_seconds=1, jitter=0.5):
    """Sleep with a random jitter to avoid synchronized API calls"""
    jitter_time = random.uniform(-jitter, jitter)
    sleep_time = max(0.1, base_seconds + jitter_time)
    print(f"Sleeping for {sleep_time:.2f} seconds to avoid rate limits...")
    time.sleep(sleep_time)

def get_cpe(package_name, package_version=None):
    """
    Find CPE matches for a package, optionally filtering by version.
    This is the first step in finding vulnerabilities - identifying the correct CPE.
    """
    query = f"{package_name}"
    if package_version is not None:
        query += f" {package_version}"

    try:
        # First try exact package name
        results = nvdlib.searchCPE(keywordSearch=query, limit=5)
        
        if not results:
            # If no results, try just the package name
            results = nvdlib.searchCPE(keywordSearch=package_name, limit=5)
            
        if results:
            print(f"Found {len(results)} CPE matches for {query}")
            return results
        else:
            print(f"No CPE matches found for {query}")
            return []
    except Exception as e:
        print(f"Error searching for CPE: {str(e)}")
        return []

def search_cves_by_cpe(cpe):
    """
    Search for CVEs associated with a specific CPE.
    This is more accurate than keyword searching.
    """
    try:
        print(f"Searching for CVEs with CPE: {cpe.cpeName}")
        results = nvdlib.searchCVE(cpeName=cpe.cpeName, limit=20)
        return results
    except Exception as e:
        print(f"Error searching CVEs by CPE: {str(e)}")
        return []

def search_cve_by_id(cve_id):
    """
    Properly search for a specific CVE by ID without including the description in the URL
    """
    try:
        print(f"Searching for CVE details: {cve_id}")
        results = nvdlib.searchCVE(cveId=cve_id)
        if results:
            return results[0]
        return None
    except Exception as e:
        print(f"Error searching for CVE {cve_id}: {str(e)}")
        return None

def extract_cve_details(cve_item):
    """Extract details from a CVE item returned by nvdlib"""
    if not cve_item:
        return None
        
    # Extract severity information
    severity = "Unknown"
    cvss_score = None
    
    try:
        # Try to get CVSS v3.1 information
        metrics = cve_item.metrics
        if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
            cvss = metrics.cvssMetricV31[0]
            severity = cvss.cvssData.baseSeverity
            cvss_score = cvss.cvssData.baseScore
        # Fall back to CVSS v3.0
        elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
            cvss = metrics.cvssMetricV30[0]
            severity = cvss.cvssData.baseSeverity
            cvss_score = cvss.cvssData.baseScore
        # Fall back to CVSS v2
        elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
            cvss = metrics.cvssMetricV2[0]
            severity = cvss.baseSeverity
            cvss_score = cvss.baseScore
    except AttributeError:
        # If we encounter an attribute error, use the older attribute access pattern
        if hasattr(cve_item, 'v31severity'):
            severity = cve_item.v31severity
            cvss_score = cve_item.v31score
        elif hasattr(cve_item, 'v30severity'):
            severity = cve_item.v30severity
            cvss_score = cve_item.v30score
        elif hasattr(cve_item, 'v2severity'):
            severity = cve_item.v2severity
            cvss_score = cve_item.v2score
    
    # Extract description
    description = "No description available"
    if hasattr(cve_item, 'descriptions') and cve_item.descriptions:
        for desc in cve_item.descriptions:
            if hasattr(desc, 'value') and desc.value and desc.lang == 'en':
                description = desc.value
                break
    
    # Extract references
    references = []
    if hasattr(cve_item, 'references') and cve_item.references:
        for ref in cve_item.references:
            if hasattr(ref, 'url') and ref.url:
                references.append(ref.url)
    
    # Extract the vulnerability status
    status = "Unknown"
    if hasattr(cve_item, 'vulnStatus'):
        status = cve_item.vulnStatus
    
    return {
        "CVE_ID": cve_item.id,
        "Severity": severity,
        "CVSS_Score": cvss_score,
        "Details": description,
        "References": references[:5],  # Limit to 5 references
        "Status": status,
        "Source": "nvdlib direct API"
    }

def find_vulnerabilities(package_name, package_version=None):
    """
    Find vulnerabilities for a package using the correct approach:
    1. Find the CPE that matches the package
    2. Search for CVEs using that CPE
    """
    all_cves = []
    
    # Step 1: Find CPE matches
    cpe_matches = get_cpe(package_name, package_version)
    sleep_with_jitter()
    
    # Step 2: Search for CVEs using each CPE
    for cpe in cpe_matches:
        cve_results = search_cves_by_cpe(cpe)
        sleep_with_jitter()
        
        # Extract details from each CVE
        for cve_item in cve_results:
            cve_details = extract_cve_details(cve_item)
            if cve_details:
                all_cves.append(cve_details)
    
    return all_cves

def test_cve_lookup(cve_id):
    """Test looking up a specific CVE ID"""
    cve_item = search_cve_by_id(cve_id)
    if cve_item:
        details = extract_cve_details(cve_item)
        print(f"\nCVE Details for {cve_id}:")
        print(json.dumps(details, indent=2))
    else:
        print(f"No details found for {cve_id}")

def main():
    if len(sys.argv) < 2:
        print("Usage: test_nvd_api.py <package_name> [version]")
        print("OR: test_nvd_api.py --cve <cve_id>")
        sys.exit(1)
    
    if sys.argv[1] == "--cve" and len(sys.argv) > 2:
        # Test CVE lookup
        test_cve_lookup(sys.argv[2])
    else:
        # Test package vulnerability search
        package_name = sys.argv[1]
        package_version = sys.argv[2] if len(sys.argv) > 2 else None
        
        print(f"Searching for vulnerabilities for {package_name} {package_version or ''}")
        vulnerabilities = find_vulnerabilities(package_name, package_version)
        
        print(f"\nFound {len(vulnerabilities)} vulnerabilities:")
        for vuln in vulnerabilities:
            print(f"\n{vuln['CVE_ID']} ({vuln['Severity']} - CVSS: {vuln['CVSS_Score']})")
            print(f"Details: {vuln['Details'][:150]}...")

if __name__ == "__main__":
    main() 