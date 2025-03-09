#!/usr/bin/env python3
import os
import json
import glob
from typing import Dict, Any, List, Optional
import time

from smolagents import CodeAgent, tool, FinalAnswerTool
import agent_models
from agent_tools import search_web

# Import our component agents
from package_researcher import package_researcher
from license_researcher import license_researcher
from security_researcher import security_researcher, get_cve_details

# Use the pre-defined model
model = agent_models.gemini_model

@tool
def evaluate_package_info(package_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate package information to determine if it's safe to use.
    
    Args:
        package_info: Information about the package from package_researcher
        
    Returns:
        Dictionary with verdict and explanation
    """
    return package_info

@tool
def evaluate_license_info(license_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluate license information to determine if it's legally safe to use.
    
    Args:
        license_info: License information from license_researcher
        
    Returns:
        Dictionary with license assessment
    """
    return license_info

@tool
def evaluate_security_info(security_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates the security information of a package to determine if it's safe to use.
    
    Args:
        security_info: The security information of the package
    
    Returns:
        A verdict on whether the package is safe to use from a security perspective
    """
    if not security_info:
        return {
            "Verdict": "Insufficient Information", 
            "Explanation": "No security information provided"
        }
    
    # Process CVEs to ensure proper formatting and details
    if "CVEs" in security_info:
        processed_cves = []
        for cve in security_info["CVEs"]:
            # Skip entries that don't have proper CVE IDs
            if "CVE ID" not in cve or not cve["CVE ID"] or cve["CVE ID"] == "Multiple" or cve["CVE ID"] == "Unknown":
                continue
                
            # Ensure the CVE ID is properly formatted (CVE-YYYY-NNNNN)
            cve_id = cve["CVE ID"]
            if not cve_id.startswith("CVE-"):
                continue
                
            processed_cves.append(cve)
        
        # If we have no properly formatted CVEs but had raw entries, we need to search for them
        if not processed_cves and security_info["CVEs"]:
            # This will be implemented in the security_researcher function
            pass
        else:
            security_info["CVEs"] = processed_cves
    
    # Rest of the function remains the same
    risk_rating = security_info.get("Implementation Risk Rating", "Unknown")
    
    if risk_rating == "High":
        return {
            "Verdict": "High Risk", 
            "Explanation": security_info.get("Implementation Risk Rating Explanation", "High security risk identified")
        }
    elif risk_rating == "Medium":
        return {
            "Verdict": "Medium Risk", 
            "Explanation": security_info.get("Implementation Risk Rating Explanation", "Medium security risk identified")
        }
    elif risk_rating == "Low":
        return {
            "Verdict": "Low Risk", 
            "Explanation": security_info.get("Implementation Risk Rating Explanation", "Low security risk identified")
        }
    else:
        return {
            "Verdict": "Unknown Risk", 
            "Explanation": "Could not determine security risk level"
        }

@tool
def generate_markdown_report(
    package_info: Dict[str, Any],
    license_info: Dict[str, Any],
    security_info: Dict[str, Any],
    verdict: Dict[str, Any]
) -> str:
    """
    Generates a markdown report for a package evaluation.
    
    Args:
        package_info: Information about the package
        license_info: License evaluation information
        security_info: Security evaluation information
        verdict: Verdict on whether the package is safe to use
    
    Returns:
        A markdown report as a string
    """
    report = []
    
    # Helper function to add a section header with an emoji
    def add_section(title, emoji):
        report.append(f"\n## {emoji} {title}\n")
    
    # Title
    package_name = package_info.get("Name", "Unknown Package")
    
    # Get version information, avoiding "Latest" as a display value
    version = package_info.get("Requested Package Version", "")
    if not version or version == "Latest":
        version = package_info.get("Latest Package Version", "")
        if version == "Latest":
            version = "Unknown Version"
    
    report.append(f"# OSS Assessment Report: {package_name} {version}\n")
    
    # Generate a timestamp
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report.append(f"*Generated on: {timestamp}*\n")
    
    # Package Information section first
    add_section("Package Information", "📦")
    if package_info:
        # Package details
        if "Name" in package_info:
            report.append(f"- **Name:** {package_info['Name']}")
        
        # Format requested version, avoiding "Latest" as a display value
        requested_version = package_info.get("Requested Package Version", "")
        if requested_version and requested_version != "Latest":
            report.append(f"- **Requested Version:** {requested_version}")
        else:
            report.append("- **Requested Version:** Latest")
        
        # Format latest version, avoiding "Latest" as a display value
        latest_version = package_info.get("Latest Package Version", "")
        if latest_version and latest_version != "Latest":
            report.append(f"- **Latest Version:** {latest_version}")
        else:
            report.append("- **Latest Version:** Unknown")
        
        if "Primary Language" in package_info:
            report.append(f"- **Primary Language:** {package_info['Primary Language']}")
        if "Description" in package_info:
            report.append(f"- **Description:** {package_info['Description']}")
        if "Link to Source Code" in package_info:
            report.append(f"- **Repository:** [{package_info['Link to Source Code']}]({package_info['Link to Source Code']})")
        if "Package Owner" in package_info:
            report.append(f"- **Maintained By:** {package_info['Package Owner']}")
    else:
        report.append("No package information available.")
    
    # Add verdict section after package info
    verdict_text = verdict.get("Verdict", "Unknown")
    
    # Map specific verdicts to their designated emojis
    verdict_emoji = "❓"  # Default unknown emoji
    if verdict_text == "Do not Use":
        verdict_emoji = "❌"
    elif verdict_text == "Generally Safe":
        verdict_emoji = "✅"
    elif verdict_text == "Seek Clarification":
        verdict_emoji = "❔"
    elif verdict_text == "Use with Caution":
        verdict_emoji = "❗"
    
    add_section("Package Evaluation", "🗒️")
    report.append(f"- **Advisory:** {verdict_emoji} {verdict_text}")
    report.append(f"- **Explanation:** {verdict.get('Explanation', 'No explanation provided.')}")
    
    # License Evaluation section
    add_section("License Evaluation", "📜")
    if license_info:
        license_name = license_info.get("Name", "Unknown")
        license_status = license_info.get("Status", "Unknown")
        
        status_emoji = "✅" if license_status == "Allowed" else "⚠️" if license_status == "Requires Legal Approval" else "❌"
        report.append(f"- **License:** {license_name}")
        report.append(f"- **Status:** {status_emoji} {license_status}")
        
        if "Notes" in license_info:
            report.append(f"- **Notes:** {license_info['Notes']}")
        
        if license_status == "Requires Legal Approval":
            report.append("\n> **Action Required:** This license requires legal approval before use.")
    else:
        report.append("No license information available.")
    
    # Security Evaluation section
    add_section("Security Evaluation", "🔒")
    if security_info:
        risk_rating = security_info.get("Implementation Risk Rating", "Unknown")
        risk_emoji = "✅" if risk_rating == "Low" else "⚠️" if risk_rating == "Medium" else "❌" if risk_rating == "High" else "❓"
        
        report.append(f"- **Security Risk:** {risk_emoji} {risk_rating}")
        
        if "Implementation Risk Rating Explanation" in security_info:
            report.append(f"- **Risk Assessment:** {security_info['Implementation Risk Rating Explanation']}")
        
        # CVEs subsection
        if "CVEs" in security_info and security_info["CVEs"]:
            report.append("\n### Known Vulnerabilities:\n")
            
            for cve in security_info["CVEs"]:
                # Check if the CVE is a string (just the ID) or a dictionary with details
                if isinstance(cve, str):
                    # It's just a CVE ID string
                    cve_id = cve
                    severity = "Unknown"  # We don't have severity info
                    description = "No details available"  # We don't have description
                    status = "Unknown"  # We don't have status info
                else:
                    # It's a dictionary with details
                    # Check both possible key formats (with and without underscore)
                    cve_id = cve.get("CVE ID", cve.get("CVE_ID", "Unknown"))
                    if cve_id == "Multiple" or cve_id == "Unknown":
                        continue  # Skip non-specific CVE entries
                    
                    severity = cve.get("Severity", "Unknown")
                    # Check both possible key formats for description
                    description = cve.get("Description", cve.get("Details", "No details available"))
                    # Limit description length if it's too long
                    if description and len(description) > 500:
                        description = description[:500] + "..."
                    
                    # Check both possible key formats for status
                    status = cve.get("Status", "Unknown")
                
                # Set appropriate severity emoji
                severity_emoji = "❌" if severity == "High" or severity == "Critical" else "⚠️" if severity == "Medium" else "⚙️" if severity == "Low" else "❓"
                
                # Add the CVE information to the report
                report.append(f"**{severity_emoji} {cve_id} ({severity})**")
                report.append(f"- {description}")
                status_emoji = "✅" if "Patched" in status else "❌"
                report.append(f"- Status: {status_emoji} {status}")
                report.append("")  # Add blank line between CVEs
        
        # Other security issues
        if "Other Security Bugs" in security_info and security_info["Other Security Bugs"]:
            report.append("\n### Other Security Concerns:\n")
            
            for issue in security_info["Other Security Bugs"]:
                report.append(f"- {issue}")
        
        # Potential concerns
        if "Potential Concerns" in security_info and security_info["Potential Concerns"]:
            report.append("\n### Repository Health:\n")
            
            for concern in security_info["Potential Concerns"]:
                report.append(f"- {concern}")
    else:
        report.append("No security information available.")
    
    # 5. Combined references section
    report.append("\n## 📚 References\n")
    references = []
    
    # Collect references from all sources
    if package_info and "References" in package_info:
        references.extend(package_info["References"])
    
    if license_info and "References" in license_info:
        references.extend(license_info["References"])
    
    if security_info and "References" in security_info:
        references.extend(security_info["References"])
    
    # Deduplicate references
    # Flatten any nested lists and ensure all items are strings
    flat_references = []
    for ref in references:
        if isinstance(ref, list):
            flat_references.extend([str(item) for item in ref])
        else:
            flat_references.append(str(ref))
    
    # Now deduplicate and filter out "N/A" and empty references
    clean_references = []
    for ref in flat_references:
        ref = ref.strip()
        # Skip empty references, "N/A" references, and duplicates
        if (ref and 
            ref != "N/A" and 
            "N/A" not in ref and 
            ref not in clean_references and
            not ref.isspace()):
            clean_references.append(ref)
    
    if clean_references:
        for i, ref in enumerate(clean_references, 1):
            report.append(f"{i}. {ref}")
    else:
        report.append("No references available.")
    
    return "\n".join(report)

def save_markdown_report(report: str, package_name: str, package_version: str) -> str:
    """
    Saves a markdown report to the markdown_reports directory.
    
    Args:
        report: The markdown report content
        package_name: The name of the package
        package_version: The version of the package
    
    Returns:
        The path to the saved report
    """
    import os
    
    # Create the markdown_reports directory if it doesn't exist
    reports_dir = "markdown_reports"
    os.makedirs(reports_dir, exist_ok=True)
    
    # Sanitize the package name and version for use in a filename
    safe_package_name = package_name.replace('/', '_').replace('\\', '_').replace(' ', '_')
    safe_version = package_version.replace('/', '_').replace('\\', '_').replace(' ', '_')
    
    # Create the filename
    filename = f"{safe_package_name}_{safe_version}.md"
    file_path = os.path.join(reports_dir, filename)
    
    # Write the report to the file
    with open(file_path, 'w') as f:
        f.write(report)
    
    print(f"Markdown report saved to {file_path}")
    return file_path

@tool
def determine_verdict(
    package_info: Dict[str, Any] = None, 
    license_info: Dict[str, Any] = None, 
    security_info: Dict[str, Any] = None,
    package_name: str = None
) -> Dict[str, Any]:
    """
    Determines if a package is safe to use based on package, license, and security information.
    
    Args:
        package_info: Package information
        license_info: License evaluation information
        security_info: Security evaluation information
        package_name: Name of the package
    
    Returns:
        Dictionary with verdict and explanation
    """
    if not package_info and not license_info and not security_info:
        return {"Verdict": "Unknown", "Explanation": "Insufficient information to make a determination."}
    
    # Initialize verdict components
    security_verdict = "Unknown"
    license_verdict = "Unknown"
    security_explanation = ""
    license_explanation = ""
    
    # Check security information
    if security_info:
        if "Verdict" in security_info:
            security_verdict = security_info["Verdict"]
            security_explanation = security_info.get("Explanation", "")
        else:
            # Infer from other fields
            risk_rating = security_info.get("Implementation Risk Rating", "Unknown")
            if risk_rating == "High":
                security_verdict = "Do not Use"
                security_explanation = security_info.get("Implementation Risk Rating Explanation", "High security risk identified.")
            elif risk_rating == "Medium":
                security_verdict = "Use with Caution"
                security_explanation = security_info.get("Implementation Risk Rating Explanation", "Medium security risk identified.")
            elif risk_rating == "Low":
                security_verdict = "Generally Safe"
                security_explanation = security_info.get("Implementation Risk Rating Explanation", "Low security risk identified.")
    
    # Check license information
    if license_info:
        if "Verdict" in license_info:
            license_verdict = license_info["Verdict"]
            license_explanation = license_info.get("Explanation", "")
        else:
            status = license_info.get("Status", "Unknown")
            if status == "Allowed":
                license_verdict = "Generally Safe"
                license_explanation = f"License ({license_info.get('Name', 'Unknown')}) is permitted for use."
            elif status == "Requires Legal Approval":
                license_verdict = "Seek Clarification"
                license_explanation = f"License ({license_info.get('Name', 'Unknown')}) requires legal approval."
            elif status == "Not Allowed":
                license_verdict = "Do not Use"
                license_explanation = f"License ({license_info.get('Name', 'Unknown')}) is not permitted for use."
    
    # Combine verdicts, giving priority to the most restrictive one
    if security_verdict == "Do not Use" or license_verdict == "Do not Use":
        final_verdict = "Do not Use"
    elif security_verdict == "Use with Caution" or license_verdict == "Use with Caution":
        final_verdict = "Use with Caution"
    elif security_verdict == "Seek Clarification" or license_verdict == "Seek Clarification":
        final_verdict = "Seek Clarification"
    elif security_verdict == "Generally Safe" and license_verdict == "Generally Safe":
        final_verdict = "Generally Safe"
    else:
        final_verdict = "Seek Clarification"  # Default to this if anything is unclear
    
    # Craft a detailed explanation based on the verdict
    combined_explanation = ""
    
    if final_verdict == "Do not Use":
        combined_explanation = f"{security_explanation} {license_explanation}".strip()
        if not combined_explanation:
            combined_explanation = f"The package {package_name if package_name else ''} is not safe to use due to security or license issues."
    
    elif final_verdict == "Use with Caution":
        # Create a more detailed explanation for "Use with Caution" that outlines specific risks
        risks = []
        
        # Add security risks
        if security_verdict == "Use with Caution" and security_info:
            if "CVEs" in security_info and security_info["CVEs"]:
                risks.append("Contains known vulnerabilities that may need mitigation")
            
            if "Implementation Risk Rating" in security_info and security_info["Implementation Risk Rating"] == "Medium":
                risks.append("Has medium security risk that requires attention")
            
            if "Other Security Bugs" in security_info and security_info["Other Security Bugs"]:
                risks.append("Has reported security issues that need to be addressed")
                
            if "Potential Concerns" in security_info and security_info["Potential Concerns"]:
                for concern in security_info["Potential Concerns"]:
                    if "deprecated" in concern.lower() or "maintenance" in concern.lower():
                        risks.append("May have maintenance or deprecation issues")
                        break
        
        # Add license risks
        if license_verdict == "Seek Clarification" and license_info:
            risks.append(f"License ({license_info.get('Name', 'Unknown')}) may require additional review or legal approval")
        
        # Add package-specific risks
        if package_info:
            if "Latest Package Version" in package_info and "Requested Package Version" in package_info:
                if package_info["Latest Package Version"] != package_info["Requested Package Version"]:
                    risks.append(f"Using an older version ({package_info['Requested Package Version']}) instead of the latest ({package_info['Latest Package Version']})")
        
        # Create a detailed explanation
        if risks:
            risk_list = ", ".join(risks[:-1]) + (" and " + risks[-1] if len(risks) > 1 else risks[0])
            combined_explanation = f"This package can be used with caution, but be aware of the following risks: {risk_list}. {security_explanation} {license_explanation}".strip()
        else:
            combined_explanation = f"{security_explanation} {license_explanation}".strip()
            if not combined_explanation:
                combined_explanation = f"The package {package_name if package_name else ''} can be used with caution, but requires careful implementation and monitoring."
    
    elif final_verdict == "Seek Clarification":
        combined_explanation = f"{security_explanation} {license_explanation}".strip()
        if not combined_explanation:
            combined_explanation = f"Additional information or clarification is needed before using the package {package_name if package_name else ''}."
    
    elif final_verdict == "Generally Safe":
        combined_explanation = f"{security_explanation} {license_explanation}".strip()
        if not combined_explanation:
            combined_explanation = f"The package {package_name if package_name else ''} appears to be safe to use based on security and license evaluation."
    
    else:  # Unknown or any other case
        combined_explanation = f"{security_explanation} {license_explanation}".strip()
        if not combined_explanation:
            combined_explanation = f"Insufficient information to determine if the package {package_name if package_name else ''} is safe to use."
    
    return {
        "Verdict": final_verdict,
        "Explanation": combined_explanation
    }

def save_evaluation_results(package_name: str, package_version: str, results: Dict[str, Any]) -> None:
    """
    Save evaluation results to a JSON file in the past_research directory.
    
    Args:
        package_name: Name of the package
        package_version: Version of the package
        results: Evaluation results to save
    """
    # Create past_research directory if it doesn't exist
    os.makedirs("past_research", exist_ok=True)
    
    # Create a safe filename
    safe_name = package_name.replace('/', '_').replace('@', '_').replace('\\', '_')
    if package_version:
        safe_version = package_version.replace('.', '_').replace('/', '_').replace('@', '_').replace('\\', '_')
        filename = f"{safe_name}_{safe_version}.json"
    else:
        filename = f"{safe_name}.json"
    
    filepath = os.path.join("past_research", filename)
    
    # Save results to file
    with open(filepath, 'w') as f:
        json.dump(results, f, indent=2)
    
    print(f"Evaluation results saved to {filepath}")

def load_previous_evaluation(package_name: str, package_version: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Check if a package has been evaluated before and load the results if found.
    
    Args:
        package_name: Name of the package
        package_version: Version of the package (optional)
        
    Returns:
        Previous evaluation results or None if not found
    """
    # Create a safe package name for filename matching
    safe_name = package_name.replace('/', '_').replace('@', '_').replace('\\', '_')
    
    # Check if past_research directory exists
    if not os.path.exists("past_research"):
        return None
    
    # If specific version is provided, try to find exact match
    if package_version:
        safe_version = package_version.replace('.', '_').replace('/', '_').replace('@', '_').replace('\\', '_')
        specific_filename = f"{safe_name}_{safe_version}.json"
        specific_filepath = os.path.join("past_research", specific_filename)
        
        if os.path.exists(specific_filepath):
            try:
                with open(specific_filepath, 'r') as f:
                    data = json.load(f)
                print(f"Found previous evaluation for {package_name} version {package_version}")
                return data
            except Exception as e:
                print(f"Error loading previous evaluation: {e}")
                return None
    
    # If no specific version, or specific version not found, look for any version
    pattern = os.path.join("past_research", f"{safe_name}_*.json")
    matching_files = glob.glob(pattern)
    
    # Also look for package without version
    generic_filepath = os.path.join("past_research", f"{safe_name}.json")
    if os.path.exists(generic_filepath):
        matching_files.append(generic_filepath)
    
    if matching_files:
        # Sort by modification time to get the most recent
        matching_files.sort(key=os.path.getmtime, reverse=True)
        try:
            with open(matching_files[0], 'r') as f:
                data = json.load(f)
            print(f"Found previous evaluation for {package_name} (most recent)")
            return data
        except Exception as e:
            print(f"Error loading previous evaluation: {e}")
    
    # No previous evaluation found
    return None

def package_evaluator(package_name: str) -> Dict[str, Any]:
    """
    Evaluates a package to determine if it's safe to use.
    
    Args:
        package_name: The name of the package to evaluate
    
    Returns:
        A verdict on whether the package is safe to use
    """
    # Extract version if included in package name
    package_version = None
    package_name_only = package_name
    
    if " " in package_name:
        parts = package_name.split(" ", 1)
        package_name_only = parts[0].strip()
        package_version = parts[1].strip()
        
        # Check if the version is a request for the latest version
        latest_version_keywords = ["latest", "current", "newest", "recent"]
        if package_version.lower() in latest_version_keywords:
            # Flag to indicate we should look up the latest version
            package_version = "latest"
    
    # Check for previous evaluation
    previous_evaluation = load_previous_evaluation(package_name_only, package_version)
    if previous_evaluation:
        print(f"Found previous evaluation for {package_name_only} version {package_version}")
        print(f"Using cached evaluation results for {package_name_only} {package_version}")
        return previous_evaluation
    
    print(f"Analyzing package: {package_name}")
    
    try:
        # Try the direct approach first (more reliable than using managed agents)
        from package_researcher import package_researcher
        package_info = package_researcher(package_name)
        
        # Add a sleep delay to avoid hitting Google API rate limits
        time.sleep(2)
        
        from license_researcher import license_researcher
        # Format package info for license researcher
        package_text = f"""
        Package: {package_info.get('Name', package_name_only)}
        Version: {package_info.get('Latest Package Version', 'Unknown')}
        License: {package_info.get('License Type', 'Unknown')}
        Repository: {package_info.get('Link to Source Code', 'Unknown')}
        Description: {package_info.get('Description', 'Unknown')}
        """
        license_info = license_researcher(package_text)
        
        # Add another sleep delay before security research
        time.sleep(2)
        
        from security_researcher import security_researcher
        security_info = security_researcher(package_name)
        
        # Specifically check and enhance CVE information if needed
        if "CVEs" in security_info and security_info["CVEs"]:
            needs_enhancement = False
            
            # Check if detailed CVE information is already available from nvdlib
            if "CVE_Details" in security_info and security_info["CVE_Details"]:
                print(f"Using CVE details from nvdlib (count: {len(security_info['CVE_Details'])})")
                # Convert the CVE_Details format to the one expected by the rest of the system
                enhanced_cves = []
                for cve_detail in security_info["CVE_Details"]:
                    enhanced_cves.append({
                        "CVE ID": cve_detail.get("CVE_ID", "Unknown"),
                        "Severity": cve_detail.get("Severity", "Unknown"),
                        "Description": cve_detail.get("Details", "No details available"),
                        "Status": cve_detail.get("Status", "Check if patched in latest version")
                    })
                security_info["CVEs"] = enhanced_cves
            else:
                # Otherwise, try to enhance the CVE details with the security researcher's API
                needs_enhancement = True
        
        # Add version information from package info to security info for verdict determination
        if package_version == "latest" and "Latest Package Version" in package_info:
            # If the user requested the latest version, use the actual latest version
            actual_version = package_info["Latest Package Version"]
            if actual_version != "Unknown":
                # Update the package_version to the actual latest version for verdict determination
                package_version = actual_version
        
        # Format package information for the verdict
        package_verdict_info = {
            "Name": package_info.get("Name", package_name_only),
            "Version": package_version or package_info.get("Latest Package Version", "Unknown"),
            "Latest Version": package_info.get("Latest Package Version", "Unknown")
        }
        
        # Determine verdict
        verdict = determine_verdict(
            package_info=package_info,
            license_info=license_info,
            security_info=security_info,
            package_name=package_name_only
        )
        
        # Combine all information
        evaluation_results = {
            "Verdict": verdict.get("Verdict", "Unknown"),
            "Explanation": verdict.get("Explanation", "No explanation provided"),
            "PackageInfo": package_info,
            "LicenseInfo": license_info,
            "SecurityInfo": security_info
        }
        
        # Determine the version to save - avoid using "latest" as a version identifier
        save_version = package_version
        if save_version == "latest" or not save_version:
            # Use the actual latest version for saving
            save_version = package_info.get("Latest Package Version", "unknown")
            if save_version == "Latest":
                save_version = "unknown"  # If we still have "Latest" as a string, replace with "unknown"
        
        # Save results for future use
        save_evaluation_results(package_name_only, save_version, evaluation_results)
        
        return evaluation_results
    except Exception as e:
        print(f"Error evaluating package: {e}")
        return {
            "Verdict": "Unknown",
            "Explanation": "An error occurred while evaluating the package"
        }

# Create a more sophisticated version using managed agents
def create_package_evaluation_agent():
    """
    Create a more sophisticated package evaluation agent that uses managed agents.
    
    Returns:
        A CodeAgent that can evaluate packages by orchestrating other agents
    """
    # First, create a dedicated agent for each specialized task
    # These agents will be managed by the manager agent
    package_research_agent = CodeAgent(
        tools=[search_web],  # Give it the search tool
        model=model,
        name="package_research_agent",
        description="Gathers information about a package using package_researcher."
    )
    
    license_research_agent = CodeAgent(
        tools=[search_web],  # Give it the search tool
        model=model,
        name="license_research_agent",
        description="Evaluates license compliance of a package using license_researcher."
    )
    
    security_research_agent = CodeAgent(
        tools=[search_web],  # Give it the search tool
        model=model,
        name="security_research_agent",
        description="Analyzes security vulnerabilities of a package using security_researcher."
    )
    
    # Create a manager agent that will orchestrate these specialized agents
    manager_agent = CodeAgent(
        tools=[determine_verdict, search_web],
        model=model,
        managed_agents=[
            package_research_agent,
            license_research_agent,
            security_research_agent
        ],
    )
    
    return manager_agent

# Direct function to evaluate a package using the multi-agent system
def evaluate_package(package_name: str) -> Dict[str, Any]:
    """
    Evaluate a package using the multi-agent system.
    
    Args:
        package_name: Name of the package to evaluate
        
    Returns:
        Dictionary with verdict and explanation
    """
    # First try the direct approach as a fallback
    try:
        return package_evaluator(package_name)
    except Exception as e:
        print(f"Warning: Direct approach failed: {str(e)}. Trying managed agents...")
        
        # Only create the manager agent if direct approach fails
        manager_agent = create_package_evaluation_agent()
        
        # Run the manager agent
        prompt = f"""
        You are a package evaluator agent responsible for determining if an open-source package is safe to use.
        You have access to three specialized agents:
        1. package_research_agent: Gathers information about a package
        2. license_research_agent: Evaluates license compliance
        3. security_research_agent: Analyzes security vulnerabilities
        
        Coordinate with these agents to gather all necessary information, then determine:
        - Verdict: One of ["Generally Safe", "Use with Caution", "Do not Use", "Seek Clarification"]
        - Explanation: Is it advisable from a security/licensing perspective to use this package? Why or why not?
        
        I need you to evaluate the package "{package_name}" to determine if it's safe to use.
        
        Coordinate with your specialized agents to:
        1. Gather information about the package
        2. Evaluate license compliance
        3. Assess security vulnerabilities
        
        Then determine:
        - Verdict: One of ["Generally Safe", "Use with Caution", "Do not Use", "Seek Clarification"]
        - Explanation: A clear explanation of why the package is or isn't advisable to use
        
        Return a structured JSON output with these two fields.
        """
        
        result = manager_agent.run(prompt)
        
        return result

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python package_evaluator.py <package_name>")
        sys.exit(1)
    
    package_name = sys.argv[1]
    result = evaluate_package(package_name)
    
    print(f"Verdict: {result['Verdict']}")
    print(f"Explanation: {result['Explanation']}") 