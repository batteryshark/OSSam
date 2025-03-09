#!/usr/bin/env python3
import json
import sys
from security_researcher import security_researcher, get_cve_details
from package_evaluator import generate_markdown_report
import os

def test_cve_handling():
    """Test CVE detection and handling in the OSSam system"""
    # Test with lodash which has known vulnerabilities
    package_info = {
        "Name": "lodash",
        "Requested Package Version": "4.17.0",
        "Latest Package Version": "4.17.21",
        "Primary Language": "JavaScript",
        "License Type": "MIT",
        "Description": "A modern JavaScript utility library delivering modularity, performance, & extras.",
        "Link to Source Code": "https://github.com/lodash/lodash",
        "Package Owner": "lodash",
        "References": ["https://github.com/lodash/lodash", "https://www.npmjs.com/package/lodash"]
    }
    
    print(f"Testing CVE handling with {package_info['Name']} {package_info['Requested Package Version']}")
    
    # First test: Directly get CVE details for a known CVE
    print("\n1. Testing direct CVE details retrieval")
    known_cve = "CVE-2019-10744"  # Known lodash vulnerability
    cve_details = get_cve_details(known_cve)
    print(f"\nCVE Details for {known_cve}:")
    print(json.dumps(cve_details, indent=2))
    
    # Second test: Create simple security info with just CVE IDs
    print("\n2. Testing with simple CVE ID list")
    simple_security_info = {
        "CVEs": ["CVE-2019-10744", "CVE-2020-8203", "CVE-2021-23337"],
        "Implementation Risk Rating": "High",
        "Implementation Risk Rating Explanation": "Multiple high severity vulnerabilities found",
        "Other Security Bugs": ["Multiple prototype pollution issues reported"],
        "Potential Concerns": ["Repository has multiple CVEs"],
        "References": ["https://github.com/lodash/lodash"]
    }
    
    # Generate a report using the simple security info
    simple_report = generate_markdown_report(
        package_info=package_info,
        license_info={"Verdict": "Allowed", "Explanation": "MIT license is allowed"},
        security_info=simple_security_info,
        verdict={"Verdict": "Do Not Use", "Explanation": "Multiple high severity vulnerabilities"}
    )
    
    # Save the simple report
    with open("test_simple_cves.md", "w") as f:
        f.write(simple_report)
    print(f"Simple CVE list report saved to test_simple_cves.md")
    
    # Third test: Create structured security info with CVE dictionaries using CVE_ID format
    print("\n3. Testing with structured CVE dictionaries using CVE_ID key")
    structured_security_info = {
        "CVEs": [
            {
                "CVE_ID": "CVE-2019-10744",
                "Severity": "Critical",
                "Details": "Prototype pollution vulnerability in defaultsDeep function",
                "Status": "Patched in version 4.17.12"
            },
            {
                "CVE_ID": "CVE-2020-8203",
                "Severity": "Medium",
                "Details": "Prototype pollution in zipObjectDeep function",
                "Status": "Patched in version 4.17.19"
            },
            {
                "CVE_ID": "CVE-2021-23337",
                "Severity": "High",
                "Details": "Command injection vulnerability via template function",
                "Status": "Patched in version 4.17.21"
            }
        ],
        "Implementation Risk Rating": "High",
        "Implementation Risk Rating Explanation": "Multiple high severity vulnerabilities found",
        "Other Security Bugs": ["Multiple prototype pollution issues reported"],
        "Potential Concerns": ["Repository has multiple CVEs"],
        "References": ["https://github.com/lodash/lodash"]
    }
    
    # Generate a report using the structured security info
    structured_report = generate_markdown_report(
        package_info=package_info,
        license_info={"Verdict": "Allowed", "Explanation": "MIT license is allowed"},
        security_info=structured_security_info,
        verdict={"Verdict": "Do Not Use", "Explanation": "Multiple high severity vulnerabilities"}
    )
    
    # Save the structured report
    with open("test_structured_cves.md", "w") as f:
        f.write(structured_report)
    print(f"Structured CVE dictionary report saved to test_structured_cves.md")
    
    # Fourth test: Use the full security researcher to get CVEs
    print("\n4. Testing with full security researcher")
    security_info = security_researcher(package_info)
    
    # Save the raw security info for inspection
    with open("test_security_info.json", "w") as f:
        json.dump(security_info, f, indent=2)
    print(f"Raw security researcher output saved to test_security_info.json")
    
    # Generate a report using the security researcher output
    researcher_report = generate_markdown_report(
        package_info=package_info,
        license_info={"Verdict": "Allowed", "Explanation": "MIT license is allowed"},
        security_info=security_info,
        verdict={"Verdict": "Do Not Use", "Explanation": "Multiple high severity vulnerabilities"}
    )
    
    # Save the researcher report
    with open("test_researcher_cves.md", "w") as f:
        f.write(researcher_report)
    print(f"Security researcher report saved to test_researcher_cves.md")
    
    # Print summary of detected CVEs
    print("\nSummary of CVEs detected:")
    if "CVEs" in security_info and security_info["CVEs"]:
        for i, cve in enumerate(security_info["CVEs"], 1):
            cve_id = cve.get("CVE ID", cve.get("CVE_ID", "Unknown"))
            severity = cve.get("Severity", "Unknown")
            print(f"{i}. {cve_id} - {severity}")
    else:
        print("No CVEs found in security researcher output")
    
    print("\nCVE handling tests completed")
    
if __name__ == "__main__":
    test_cve_handling() 