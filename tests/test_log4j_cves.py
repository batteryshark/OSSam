#!/usr/bin/env python3
import json
from security_researcher import search_vulnerabilities, get_cve_details

def test_log4j_cves():
    """
    Direct test of CVE identification for log4j 2.14.1, which should have the Log4Shell vulnerability.
    """
    print("Testing CVE identification for log4j 2.14.1...")
    
    # Search for vulnerabilities directly
    vuln_results = search_vulnerabilities(package_name="log4j", version="2.14.1")
    
    print(f"Found {len(vuln_results.get('CVEs', []))} CVEs for log4j 2.14.1")
    
    # Print details of each CVE found
    for cve_detail in vuln_results.get('CVE_Details', []):
        print(f"\n- {cve_detail.get('CVE_ID')} ({cve_detail.get('Severity')})")
        print(f"  Score: {cve_detail.get('CVSS_Score')}")
        print(f"  Status: {cve_detail.get('Status', 'Unknown')}")
        print(f"  {cve_detail.get('Details')[:200]}...")
    
    # Look for the specific Log4Shell vulnerability (CVE-2021-44228)
    log4shell_cve = "CVE-2021-44228"
    print(f"\nLooking specifically for {log4shell_cve}...")
    
    try:
        cve_details = get_cve_details(log4shell_cve)
        print(f"Found details for {log4shell_cve}:")
        print(f"- Severity: {cve_details.get('Severity', 'Unknown')}")
        print(f"- CVSS Score: {cve_details.get('CVSS_Score', 'Unknown')}")
        print(f"- Status: {cve_details.get('Status', 'Unknown')}")
        print(f"- Details: {cve_details.get('Details', 'No details')[:200]}...")
        print("\nReferences:")
        for ref in cve_details.get('References', [])[:3]:
            print(f"- {ref}")
    except Exception as e:
        print(f"Error retrieving CVE details: {str(e)}")

if __name__ == "__main__":
    test_log4j_cves() 