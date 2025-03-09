#!/usr/bin/env python3
import argparse
import json
import sys
import os
from typing import Dict, Any, List
import traceback

# Import our components
from package_evaluator import package_evaluator, generate_markdown_report, save_markdown_report

def format_output(data: Dict[str, Any], indent: int = 0) -> str:
    """Format dictionary data for console output with proper indentation"""
    result = []
    indent_str = " " * indent
    
    for key, value in data.items():
        if isinstance(value, dict):
            result.append(f"{indent_str}{key}:")
            result.append(format_output(value, indent + 2))
        elif isinstance(value, list):
            result.append(f"{indent_str}{key}:")
            for item in value:
                if isinstance(item, dict):
                    result.append(format_output(item, indent + 2))
                else:
                    result.append(f"{indent_str}  - {item}")
        else:
            result.append(f"{indent_str}{key}: {value}")
    
    return "\n".join(result)

def print_section_header(title: str, char: str = "=") -> None:
    """Print a formatted section header"""
    width = 80
    padding = (width - len(title) - 2) // 2
    header = f"{char * padding} {title} {char * padding}"
    print("\n" + header + "\n")

def print_references(references: List[str]) -> None:
    """Print references with proper formatting"""
    print_section_header("References", "-")
    for i, ref in enumerate(references, 1):
        print(f"{i}. {ref}")

def analyze_package(package_info: str, output_format: str = "console", output_file: str = None) -> None:
    """
    Analyze a package and display results in specified format.
    
    Args:
        package_info: Package name and optional version to analyze
        output_format: Output format (console, json, or markdown)
        output_file: File to write results to (optional)
    """
    try:
        # Run the evaluator
        print(f"Analyzing package: {package_info}")
        evaluation_results = package_evaluator(package_info)
        
        # Extract package name and version for filename purposes
        package_name = package_info.split()[0] if " " in package_info else package_info
        package_version = None
        
        if " " in package_info:
            package_version = package_info.split(" ", 1)[1].strip()
        elif "PackageInfo" in evaluation_results:
            package_version = (
                evaluation_results["PackageInfo"].get("Requested Package Version") or 
                evaluation_results["PackageInfo"].get("Latest Package Version") or 
                "unknown"
            )
        else:
            package_version = "unknown"
            
        # Display results based on format
        if output_format == "json":
            if output_file:
                with open(output_file, "w") as f:
                    json.dump(evaluation_results, f, indent=2)
                print(f"Results written to {output_file}")
            else:
                print(json.dumps(evaluation_results, indent=2))
                
        elif output_format == "markdown":
            # Generate the markdown report
            markdown_report = generate_markdown_report(
                package_info=evaluation_results.get("PackageInfo", {}),
                license_info=evaluation_results.get("LicenseInfo", {}),
                security_info=evaluation_results.get("SecurityInfo", {}),
                verdict={"Verdict": evaluation_results.get("Verdict", "Unknown"), 
                         "Explanation": evaluation_results.get("Explanation", "")}
            )
            
            # Always save to the markdown_reports directory
            report_path = save_markdown_report(
                report=markdown_report,
                package_name=package_name,
                package_version=package_version
            )
            
            # If an output file was specified, also write to that location
            if output_file:
                with open(output_file, "w") as f:
                    f.write(markdown_report)
                print(f"Markdown report written to {output_file}")
                
        else:  # console format
            # Print verdict and explanation
            print_section_header("Evaluation Results")
            print(f"\nVerdict: {evaluation_results.get('Verdict', 'Unknown')}\n")
            print(f"Explanation: {evaluation_results.get('Explanation', 'No explanation provided.')}\n")
            
            # Print package information
            if "PackageInfo" in evaluation_results and evaluation_results["PackageInfo"]:
                package_results = evaluation_results["PackageInfo"]
                print_section_header("Package Information", "-")
                print()
                print(f"Name: {package_results.get('Name', 'Unknown')}")
                print(f"Latest Version: {package_results.get('Latest Package Version', 'Unknown')}")
                print(f"Requested Version: {package_results.get('Requested Package Version', 'Unknown')}")
                print(f"Primary Language: {package_results.get('Primary Language', 'Unknown')}")
                print(f"License Type: {package_results.get('License Type', 'Unknown')}")
                print(f"Package Owner: {package_results.get('Package Owner', 'Unknown')}")
                print(f"Description: {package_results.get('Description', 'No description available')}")
                print(f"Source Code: {package_results.get('Link to Source Code', 'Unknown')}")
                
                if "References" in package_results and package_results["References"]:
                    print_references(package_results["References"])
            
            # Print license information
            if "LicenseInfo" in evaluation_results and evaluation_results["LicenseInfo"]:
                license_results = evaluation_results["LicenseInfo"]
                print_section_header("License Evaluation", "-")
                print()
                print(f"License Type: {license_results.get('Name', license_results.get('License_Type', 'Unknown'))}")
                print(f"Status: {license_results.get('Status', license_results.get('Decision', 'Unknown'))}")
                print(f"Notes: {license_results.get('Notes', license_results.get('Legal_Notes', 'No notes available'))}")
                
            # Print security information
            if "SecurityInfo" in evaluation_results and evaluation_results["SecurityInfo"]:
                security_results = evaluation_results["SecurityInfo"]
                print_section_header("Security Analysis", "-")
                print()
                
                print("Potential Concerns:")
                concerns = security_results.get("Potential Concerns", [])
                if concerns:
                    for concern in concerns:
                        print(f"- {concern}")
                else:
                    print("- None found")
                
                print("\nCVEs:")
                cves = security_results.get("CVEs", [])
                if cves:
                    for cve in cves:
                        if isinstance(cve, dict):
                            cve_id = cve.get("CVE ID", "Unknown")
                            severity = cve.get("Severity", "Unknown")
                            description = cve.get("Description", "No description")
                            status = cve.get("Status", "Unknown")
                            print(f"- {cve_id} ({severity}): {description} - {status}")
                        else:
                            print(f"- {cve}")
                else:
                    print("- None found")
                
                print("\nOther Security Bugs:")
                bugs = security_results.get("Other Security Bugs", [])
                if bugs:
                    for bug in bugs:
                        print(f"- {bug}")
                else:
                    print("- None found")
                
                print(f"\nImplementation Risk Rating: {security_results.get('Implementation Risk Rating', 'Unknown')}")
                print(f"\nImplementation Risk Rating Explanation: {security_results.get('Implementation Risk Rating Explanation', 'No explanation available')}")
                
                if "References" in security_results and security_results["References"]:
                    print_references(security_results["References"])
            
            # Also generate a markdown report for console output
            # This ensures we always create the markdown report file in the markdown_reports directory
            markdown_report = generate_markdown_report(
                package_info=evaluation_results.get("PackageInfo", {}),
                license_info=evaluation_results.get("LicenseInfo", {}),
                security_info=evaluation_results.get("SecurityInfo", {}),
                verdict={"Verdict": evaluation_results.get("Verdict", "Unknown"), 
                         "Explanation": evaluation_results.get("Explanation", "")}
            )
            
            # Save to the markdown_reports directory
            report_path = save_markdown_report(
                report=markdown_report,
                package_name=package_name,
                package_version=package_version
            )
        
        # Save combined results if output file is provided for console format
        if output_file and output_format not in ["json", "markdown"]:
            with open(output_file, "w") as f:
                if output_format == "json":
                    json.dump(evaluation_results, f, indent=2)
                else:
                    f.write("# Package Analysis Report\n\n")
                    f.write(f"## Verdict: {evaluation_results['Verdict']}\n\n")
                    f.write(f"## Explanation\n\n{evaluation_results['Explanation']}\n\n")
                    
                    if "PackageInfo" in evaluation_results:
                        f.write("## Package Information\n\n")
                        f.write(format_output(evaluation_results["PackageInfo"], 0))
                        f.write("\n\n")
                    
                    if "LicenseInfo" in evaluation_results:
                        f.write("## License Evaluation\n\n")
                        f.write(format_output(evaluation_results["LicenseInfo"], 0))
                        f.write("\n\n")
                    
                    if "SecurityInfo" in evaluation_results:
                        f.write("## Security Analysis\n\n")
                        f.write(format_output(evaluation_results["SecurityInfo"], 0))
                        f.write("\n\n")
    except Exception as e:
        print(f"Error analyzing package: {e}")
        traceback.print_exc()

def main():
    """
    Main function to parse command line arguments and run the package analysis.
    """
    parser = argparse.ArgumentParser(description="Analyze an open-source package for general information and security concerns.")
    parser.add_argument("package_info", help="Package name and optional version to analyze (e.g., 'lodash' or 'lodash 4.17.21')")
    parser.add_argument("-o", "--output", help="File to write results to")
    parser.add_argument("-f", "--format", choices=["console", "json", "markdown"], default="console", help="Output format")
    
    args = parser.parse_args()
    
    analyze_package(args.package_info, args.format, args.output)

if __name__ == "__main__":
    main() 