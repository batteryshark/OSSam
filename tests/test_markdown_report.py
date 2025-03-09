#!/usr/bin/env python3
import json
import sys
from package_evaluator import generate_markdown_report, save_markdown_report

def test_markdown_report():
    """
    Test the markdown report generator with sample data including a variety of reference formats.
    """
    print("Testing markdown report generation with sample data...")
    
    # Sample package info
    package_info = {
        "Name": "test-package",
        "Requested Package Version": "1.0.0",
        "Latest Package Version": "2.0.0", 
        "Primary Language": "JavaScript",
        "License Type": "MIT",
        "Description": "A test package for markdown report generation",
        "Link to Source Code": "https://github.com/example/test-package",
        "Package Owner": "example",
        "References": [
            "https://github.com/example/test-package",
            "https://www.npmjs.com/package/test-package", 
            "Search results from analyze_repository_health tool",  # Generic reference that should be replaced
            "N/A",  # Should be filtered out
            "",  # Empty reference that should be filtered out
            "https://github.com/example/test-package"  # Duplicate that should be filtered out
        ]
    }
    
    # Sample license info
    license_info = {
        "License Type": "MIT",
        "Allowed": True,
        "Explanation": "MIT license is allowed as per company policy",
        "References": [
            "https://opensource.org/licenses/MIT",
            "N/A",  # Should be filtered out
            "Search results from license_checker tool"  # Generic reference
        ]
    }
    
    # Sample security info
    security_info = {
        "Implementation Risk Rating": "Low",
        "Potential Concerns": [
            "No major concerns identified"
        ],
        "CVEs": [
            {
                "CVE_ID": "CVE-2023-00000",
                "Severity": "Low",
                "Description": "Sample vulnerability for testing",
                "Status": "Patched in version 1.0.1"
            }
        ],
        "Other Security Bugs": [
            "No other security issues found"
        ],
        "References": [
            "Search results for: 'test-package 1.0.0 CVE vulnerability'",  # Specific search query
            "Web search for: 'CVE-2023-00000 details severity exploit'",  # Web search reference
            "NVD CPE search for: 'test-package 1.0.0'",  # NVD API reference
            "CPE: cpe:2.3:a:example:test-package:1.0.0:*:*:*:*:*:*:*",  # CPE identifier
            "https://nvd.nist.gov/vuln/detail/CVE-2023-00000",
            "N/A"  # Should be filtered out
        ]
    }
    
    # Sample verdict
    verdict = {
        "Decision": "Allowed",
        "Explanation": "This package is allowed for use as no major security or license issues were found"
    }
    
    # Generate the markdown report
    markdown_report = generate_markdown_report(
        package_info=package_info,
        license_info=license_info,
        security_info=security_info,
        verdict=verdict
    )
    
    # Save the markdown report to a file
    report_file = "test_markdown_report.md"
    with open(report_file, "w") as f:
        f.write(markdown_report)
    
    print(f"Markdown report generated and saved to {report_file}")
    print("\nReport Preview:")
    print("----------------")
    
    # Print the References section to verify the improvements
    references_section = markdown_report.split("## 📚 References\n")[1] if "## 📚 References\n" in markdown_report else "References section not found"
    print(f"References Section:\n{references_section}")
    
    return True

if __name__ == "__main__":
    test_markdown_report() 