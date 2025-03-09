#!/usr/bin/env python3
import json
import sys
from security_researcher import security_researcher, search_vulnerabilities, get_cve_details

def test_security_researcher():
    """
    Test the security researcher with a package known to have vulnerabilities.
    We'll use lodash 4.17.0 which has several known CVEs.
    """
    print("Testing security researcher with lodash 4.17.0...")
    
    # Construct package info dictionary
    package_info = {
        "name": "lodash",
        "version": "4.17.0",
        "description": "Lodash modular utilities.",
        "repository_url": "https://github.com/lodash/lodash",
        "homepage": "https://lodash.com/",
        "license": "MIT",
        "latest_version": "4.17.21",
        "stars": 52000,
        "issues": {
            "open": 100,
            "closed": 3000
        },
        "last_commit": "2022-01-01",
        "contributors": 300,
        "maintainers": ["John-David Dalton"]
    }
    
    # Test direct vulnerability search first
    print("\n1. Testing search_vulnerabilities function:")
    print("-------------------------------------------")
    vuln_results = search_vulnerabilities(package_name="lodash", version="4.17.0")
    
    print(f"Found {len(vuln_results.get('CVEs', []))} CVEs for lodash 4.17.0")
    
    for cve_detail in vuln_results.get('CVE_Details', []):
        print(f"\n- {cve_detail.get('CVE_ID')} ({cve_detail.get('Severity')})")
        print(f"  {cve_detail.get('Details')[:200]}...")
    
    # Now test the full security researcher
    print("\n\n2. Testing full security_researcher function:")
    print("---------------------------------------------")
    security_results = security_researcher(package_info=package_info)
    
    print("\nSecurity Research Results:")
    print("-------------------------")
    print(f"- Risk Rating: {security_results.get('Implementation Risk Rating', 'Unknown')}")
    print(f"- Risk Explanation: {security_results.get('Risk Rating Explanation', 'Not provided')}")
    
    print("\nPotential Concerns:")
    for concern in security_results.get('Potential Concerns', []):
        print(f"- {concern}")
    
    print("\nCVEs:")
    for cve in security_results.get('CVEs', []):
        print(f"- {cve}")
    
    print("\nOther Security Issues:")
    for issue in security_results.get('Other Security Bugs', []):
        print(f"- {issue}")
    
    print("\nReferences:")
    for ref in security_results.get('References', [])[:5]:  # Just show first 5
        print(f"- {ref}")
    
    # Test direct CVE lookup
    print("\n\n3. Testing direct CVE lookup (get_cve_details):")
    print("-----------------------------------------------")
    # Look up a known CVE for lodash
    known_cve = "CVE-2020-8203"  # High severity prototype pollution in lodash
    
    try:
        cve_details = get_cve_details(known_cve)
        print(f"Details for {known_cve}:")
        print(f"- Severity: {cve_details.get('Severity', 'Unknown')}")
        print(f"- CVSS Score: {cve_details.get('CVSS_Score', 'Unknown')}")
        print(f"- Details: {cve_details.get('Details', 'No details')[:200]}...")
        print(f"- Status: {cve_details.get('Status', 'Unknown')}")
        print("\nReferences:")
        for ref in cve_details.get('References', [])[:3]:  # Just show first 3
            print(f"- {ref}")
    except Exception as e:
        print(f"Error retrieving CVE details: {str(e)}")
    
    return True

if __name__ == "__main__":
    test_security_researcher() 