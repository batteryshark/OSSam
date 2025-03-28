"""
Package Evaluation Team using Pydantic AI

This module provides functionality to evaluate software packages using multiple specialized agents
and generate comprehensive reports.
"""

import asyncio
import os
import json
import time
from typing import Dict, Any, List, Optional
from datetime import datetime
from typing_extensions import TypedDict, NotRequired
from pydantic import BaseModel
from pydantic_ai import Agent, RunContext
from dotenv import load_dotenv

# Import our specialized agents
from agent__package_info import package_researcher, PackageResearchResult
from agent__license_researcher import license_researcher, LicenseResearchResult
from agent__vulnerability_researcher import vulnerability_researcher, VulnerabilityResearchResult
from agent__software_health_assessor import software_health_assessor, SoftwareHealthReport

load_dotenv()

# Define structured output type for package evaluation
class PackageEvaluationResult(TypedDict):
    """Final package evaluation result with comprehensive guidance."""
    guidance: str  # One of ["Generally Safe", "Use with Caution", "Do not Use", "Seek Clarification"]
    explanation: str
    package_info: PackageResearchResult
    license_info: LicenseResearchResult
    vulnerability_info: VulnerabilityResearchResult
    health_info: SoftwareHealthReport
    evaluation_timestamp: str
    agent_notes: NotRequired[str]  # AI-generated guidance and analysis

# Define dependencies for the agent
class PackageEvaluationDeps(BaseModel):
    """Dependencies for package evaluation."""
    current_date: str
    package_info: PackageResearchResult
    license_info: LicenseResearchResult
    vulnerability_info: VulnerabilityResearchResult
    health_info: SoftwareHealthReport

# Create the Pydantic AI agent for final evaluation
evaluation_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=PackageEvaluationDeps,
    result_type=PackageEvaluationResult,
    retries=3,
    system_prompt="""
    You are a package evaluation specialist who provides final guidance on whether a software package
    is safe to use based on comprehensive research from multiple specialized agents.
    
    Your task is to:
    1. Review all the information gathered about the package
    2. Provide a clear guidance recommendation
    3. Explain the reasoning behind your recommendation, including:
       - Key factors that influenced your decision
       - Specific concerns or positive aspects
       - Any mitigating factors or risks
       - Recommendations for safe usage if applicable
    
    IMPORTANT GUIDELINES:
    
    - Consider all aspects of the package: license, vulnerabilities, health status
    - Be conservative in your recommendations - prioritize security and stability
    - Provide clear, actionable explanations
    - Consider both technical and legal implications
    - If there are significant concerns, recommend seeking clarification
    
    Your guidance should be one of:
    - "Generally Safe": Package appears safe to use with standard precautions
    - "Use with Caution": Package has some concerns but can be used with specific mitigations
    - "Do not Use": Package has significant issues that make it unsuitable
    - "Seek Clarification": More information needed to make a determination
    
    Always verify your findings from multiple sources before making a determination.
    """
)

def save_to_cache(evaluation_result: Dict[str, Any]) -> str:
    """
    Save evaluation results to cache.
    
    Args:
        evaluation_result: The evaluation results to save
        
    Returns:
        The filename where the results were saved
    """
    # Create cache directory if it doesn't exist
    os.makedirs("cache", exist_ok=True)
    
    # Generate filename using epoch timestamp
    timestamp = int(time.time())
    filename = f"{timestamp}.json"
    filepath = os.path.join("cache", filename)
    
    # Save the results
    with open(filepath, 'w') as f:
        json.dump(evaluation_result, f, indent=2)
    
    return filename

def generate_markdown_report(evaluation_result: Dict[str, Any]) -> str:
    """
    Generate a markdown report from the evaluation results.
    
    Args:
        evaluation_result: The evaluation results to format
        
    Returns:
        The markdown report as a string
    """
    try:
        # Create markdown directory if it doesn't exist
        os.makedirs("markdown", exist_ok=True)
        
        # Generate filename using epoch timestamp
        timestamp = int(time.time())
        filename = f"{timestamp}.md"
        filepath = os.path.join("markdown", filename)
        
        # Extract data for easier reference
        package_info = evaluation_result.get("package_info", {})
        license_info = evaluation_result.get("license_info", {})
        vulnerability_info = evaluation_result.get("vulnerability_info", {})
        health_info = evaluation_result.get("health_info", {})
        
        # Generate the markdown content
        markdown = f"""# Software Package Evaluation Report

## 📦 Package Information
- **Name**: {package_info.get('Name', 'Unknown')}
- **Version**: {package_info.get('Latest_Package_Version', 'Unknown')}
- **Primary Language**: {package_info.get('Primary_Language', 'Unknown')}
- **Description**: {package_info.get('Description', 'No description available')}
- **Source Code**: {package_info.get('Link_to_Source_Code', 'Not available')}
- **Documentation**: {package_info.get('Documentation_URL', 'Not available')}

## 📊 Overall Assessment
- **Guidance**: {evaluation_result.get('guidance', 'Unknown')}
- **Explanation**: {evaluation_result.get('explanation', 'No explanation provided')}
- **Health Score**: {health_info.get('overall_assessment', {}).get('health_score', 'Unknown')}/100

## 📜 License Information
- **License**: {license_info.get('Name', 'Unknown')}
- **Status**: {license_info.get('Status', 'Unknown')}
- **Notes**: {license_info.get('Notes', 'No notes available')}"""

        # Add Agent Notes if present
        if license_info.get("Agent_Notes"):
            markdown += f"\n- **AI Analysis**: {license_info['Agent_Notes']}"

        markdown += "\n\n## 🔒 Security Assessment\n### Vulnerabilities\n"
        
        vulnerabilities = vulnerability_info.get("vulnerabilities", [])
        if vulnerabilities:
            for vuln in vulnerabilities:
                markdown += f"""
#### {vuln.get('cve_id', 'No CVE')} - {vuln.get('severity', 'Unknown')}
- **Description**: {vuln.get('description', 'No description available')}
- **Status**: {vuln.get('status', 'Unknown')}
- **Fixed in**: {vuln.get('fixed_in_version', 'Unknown')}
- **Attack Vector**: {vuln.get('attack_vector', 'Unknown')}
"""
        else:
            markdown += "No known vulnerabilities found.\n"
        
        markdown += "\n### Security Advisories\n"
        advisories = vulnerability_info.get("advisories", [])
        if advisories:
            for advisory in advisories:
                markdown += f"""
#### {advisory.get('title', 'Untitled')} - {advisory.get('severity', 'Unknown')}
- **Description**: {advisory.get('description', 'No description available')}
- **Affected Versions**: {advisory.get('affected_versions', 'Unknown')}
- **Remediation**: {advisory.get('remediation', 'No remediation information available')}
"""
        else:
            markdown += "No security advisories found.\n"
        
        markdown += "\n## 🏥 Health Assessment\n"
        
        # Get nested dictionaries with default empty dicts
        health_info = evaluation_result.get('health_info', {})
        maintenance = health_info.get('maintenance_info', {})
        community = health_info.get('community_info', {})
        documentation = health_info.get('documentation_info', {})
        future = health_info.get('future_info', {})
        overall = health_info.get('overall_assessment', {})
        
        markdown += f"""
### Maintenance Status
- **Status**: {maintenance.get('status', 'Unknown')}
- **Last Activity**: {maintenance.get('last_activity', 'Unknown')}
- **Activity Frequency**: {maintenance.get('activity_frequency', 'Unknown')}
- **Open Issues**: {maintenance.get('open_issues', 'Unknown')}

### Community Health
- **Contributors**: {community.get('contributor_count', 'Unknown')}
- **Contribution Diversity**: {community.get('contribution_diversity', 'Unknown')}
- **Bus Factor**: {community.get('bus_factor', 'Unknown')}
- **Activity Level**: {community.get('activity_level', 'Unknown')}

### Documentation
- **Quality**: {documentation.get('quality', 'Unknown')}
- **Completeness**: {documentation.get('completeness', 'Unknown')}
- **Examples Available**: {'Yes' if documentation.get('examples') else 'No'}

## 📈 Overall Assessment
- **Health Score**: {overall.get('health_score', 'Unknown')}/100
- **Key Strengths**: {', '.join(overall.get('key_strengths', []))}
- **Key Risks**: {', '.join(overall.get('key_risks', []))}
- **Summary**: {overall.get('summary', 'No summary available')}

## 🔮 Future Outlook
- **Outlook**: {future.get('outlook', 'Unknown')}
- **Roadmap Available**: {'Yes' if future.get('roadmap') else 'No'}
- **Key Opportunities**: {', '.join(future.get('opportunities', []))}
- **Key Risks**: {', '.join(future.get('risks', []))}

## 📚 References
"""
        
        # Add references from all sources
        for ref in package_info.get('References', []):
            markdown += f"- {ref}\n"
        for ref in license_info.get('References', []):
            markdown += f"- {ref}\n"
        for advisory in vulnerability_info.get('advisories', []):
            for ref_url in advisory.get('references', []):
                markdown += f"- {ref_url}\n"
        
        # Save the markdown file
        with open(filepath, 'w') as f:
            f.write(markdown)
        
        return filename,markdown
        
    except Exception as e:
        print(f"Warning: Error generating markdown report: {str(e)}")
        return "error_report.md",""

async def evaluate_from_cache() -> PackageEvaluationResult:
    """
    Evaluate a package using cached data from JSON files.
    
    Returns:
        Dictionary with evaluation results
    """
    try:
        # Load cached data from JSON files
        with open("package_info.json", "r") as f:
            package_info = json.load(f)
        with open("license_info.json", "r") as f:
            license_info = json.load(f)
        with open("vulnerability_info.json", "r") as f:
            vulnerability_info = json.load(f)
        with open("software_health.json", "r") as f:
            health_info = json.load(f)
        
        # Ensure health_info has the correct structure
        if not isinstance(health_info, dict):
            health_info = {}
        if 'details' not in health_info:
            health_info['details'] = {}
        if 'overall_assessment' not in health_info:
            health_info['overall_assessment'] = {'health_score': 0}
        
        # Ensure all required nested structures exist
        for section in ['maintenance', 'community', 'documentation', 'adoption', 'maturity', 'future']:
            if section not in health_info['details']:
                health_info['details'][section] = {}
        
        # Prepare dependencies for final evaluation
        current_date = datetime.now().strftime("%B %d, %Y")
        deps = PackageEvaluationDeps(
            current_date=current_date,
            package_info=package_info,
            license_info=license_info,
            vulnerability_info=vulnerability_info,
            health_info=health_info
        )
        
        # Run only the final evaluation agent with cached data
        result = await evaluation_agent.run(
            """Evaluate the package based on the cached information from JSON files.
            Consider the following aspects:
            1. Package health and maintenance status
            2. Security vulnerabilities and advisories
            3. License compliance and legal implications
            4. Community health and documentation quality
            
            Provide a detailed explanation of your assessment, including:
            - Key factors that influenced your decision
            - Specific concerns or positive aspects
            - Any mitigating factors or risks
            - Recommendations for safe usage if applicable""",
            deps=deps
        )
        
        # Create result dictionary
        result_dict = {
            "guidance": result.data["guidance"],
            "explanation": result.data["explanation"],
            "package_info": package_info,
            "license_info": license_info,
            "vulnerability_info": vulnerability_info,
            "health_info": health_info,
            "evaluation_timestamp": result.data["evaluation_timestamp"]
        }
        if "agent_notes" in result.data:
            result_dict["agent_notes"] = result.data["agent_notes"]
        
        # Save results and generate report
        cache_file = save_to_cache(result_dict)
        print(f"Saved evaluation to cache: {cache_file}")
        
        markdown_file, markdown_report = generate_markdown_report(result_dict)
        print(f"Generated markdown report: {markdown_file}")
        
        return result_dict
        
    except FileNotFoundError as e:
        missing_file = str(e).split("'")[1]
        return {
            "guidance": "Seek Clarification",
            "explanation": f"Required cache file {missing_file} not found. Please ensure all cache files are present.",
            "package_info": {},
            "license_info": {},
            "vulnerability_info": {},
            "health_info": {
                "overall_assessment": {"health_score": 0},
                "details": {
                    "maintenance": {},
                    "community": {},
                    "documentation": {},
                    "adoption": {},
                    "maturity": {},
                    "future": {}
                }
            },
            "evaluation_timestamp": datetime.now().strftime("%B %d, %Y")
        }
    except json.JSONDecodeError as e:
        return {
            "guidance": "Seek Clarification",
            "explanation": f"Error parsing JSON from cache files: {str(e)}",
            "package_info": {},
            "license_info": {},
            "vulnerability_info": {},
            "health_info": {
                "overall_assessment": {"health_score": 0},
                "details": {
                    "maintenance": {},
                    "community": {},
                    "documentation": {},
                    "adoption": {},
                    "maturity": {},
                    "future": {}
                }
            },
            "evaluation_timestamp": datetime.now().strftime("%B %d, %Y")
        }
    except Exception as e:
        return {
            "guidance": "Seek Clarification",
            "explanation": f"Unexpected error during evaluation: {str(e)}",
            "package_info": {},
            "license_info": {},
            "vulnerability_info": {},
            "health_info": {
                "overall_assessment": {"health_score": 0},
                "details": {
                    "maintenance": {},
                    "community": {},
                    "documentation": {},
                    "adoption": {},
                    "maturity": {},
                    "future": {}
                }
            },
            "evaluation_timestamp": datetime.now().strftime("%B %d, %Y")
        }

async def evaluate_package_team(text_information: str) -> PackageEvaluationResult:
    """
    Evaluate a software package using a two-stage workflow:
    1. Get basic package info and check cache for exact match
    2. If no match, run full analysis workflow
    
    Args:
        text_information: Textual information about the software package
        
    Returns:
        Dictionary with comprehensive evaluation results
        Markdown file with the evaluation results
    """
    start_time = time.time()
    try:
        # Stage 1: Get basic package info first to understand what we're looking for
        package_info = await package_researcher(text_information)
        requested_version = package_info.get("Requested_Package_Version", "")
        package_name = package_info.get("Name", "")
        print(f"Package name: {package_name}, Version: {requested_version}")

        # Check cache directory for matching results using the standardized package info
        cache_dir = "cache"
        if os.path.exists(cache_dir):
            for filename in os.listdir(cache_dir):
                if filename.endswith(".json"):
                    with open(os.path.join(cache_dir, filename), "r") as f:
                        cached_data = json.load(f)
                        cached_package = cached_data.get("package_info", {})
                        if (cached_package.get("Name").lower() == package_name.lower() and 
                            cached_package.get("Requested_Package_Version").lower() == requested_version.lower()):
                            # Found exact match in cache, use it
                            result_dict = cached_data
                            markdown_file, markdown_report = generate_markdown_report(result_dict)
                            print(f"Found exact match in cache: {filename}")
                            return result_dict, markdown_report

        print("No exact match found in cache, running full analysis workflow")
        # Stage 2: Run full analysis workflow
        # Get license information from package info 
        if package_info.get("License_Type","") != "Unknown":
            license_info = await license_researcher(package_info.get("License_Type",""))
        else:
            license_info = await license_researcher(text_information + "\n" + json.dumps(package_info))
        
        # Get vulnerability information
        vulnerability_info = await vulnerability_researcher(text_information)
        
        # Get health information
        health_info = await software_health_assessor(text_information)
        
        # Prepare dependencies for final evaluation
        current_date = datetime.now().strftime("%B %d, %Y")
        deps = PackageEvaluationDeps(
            current_date=current_date,
            package_info=package_info,
            license_info=license_info,
            vulnerability_info=vulnerability_info,
            health_info=health_info
        )
        
        # Run final evaluation
        result = await evaluation_agent.run(
            "Evaluate the package based on all gathered information",
            deps=deps
        )
        
        # Create result dictionary
        result_dict = {
            "guidance": result.data["guidance"],
            "explanation": result.data["explanation"],
            "package_info": package_info.model_dump() if hasattr(package_info, 'model_dump') else package_info,
            "license_info": license_info.model_dump() if hasattr(license_info, 'model_dump') else license_info,
            "vulnerability_info": vulnerability_info.model_dump() if hasattr(vulnerability_info, 'model_dump') else vulnerability_info,
            "health_info": health_info.model_dump() if hasattr(health_info, 'model_dump') else health_info,
            "evaluation_timestamp": result.data["evaluation_timestamp"]
        }
        if "agent_notes" in result.data:
            result_dict["agent_notes"] = result.data["agent_notes"]
        
        end_time = time.time()
        print(f"Time taken for full analysis: {end_time - start_time} seconds")
        # Save results and generate report
        cache_file = save_to_cache(result_dict)
        print(f"Saved evaluation to cache: {cache_file}")
        
        markdown_file, markdown_report = generate_markdown_report(result_dict)
        print(f"Generated markdown report: {markdown_file}")
        
        return result_dict, markdown_report
        
    except Exception as e:
        return {
            "guidance": "Seek Clarification",
            "explanation": f"Error during evaluation: {str(e)}",
            "package_info": {},
            "license_info": {},
            "vulnerability_info": {},
            "health_info": {},
            "evaluation_timestamp": datetime.now().strftime("%B %d, %Y")
        }, None

def print_results(result: PackageEvaluationResult):
    """Print evaluation results in a clean format."""
    try:
        print("\n🔍 PACKAGE EVALUATION RESULTS:")
        print("=" * 50)
        
        # Get nested data with defaults
        package_info = result.get('package_info', {})
        license_info = result.get('license_info', {})
        vulnerability_info = result.get('vulnerability_info', {})
        health_info = result.get('health_info', {})
        
        # Print basic information
        print(f"📦 Package: {package_info.get('Name', 'Unknown')}")
        print(f"📊 Version: {package_info.get('Latest_Package_Version', 'Unknown')}")
        print(f"🎯 Guidance: {result.get('guidance', 'Unknown')}")
        print(f"📝 Explanation: {result.get('explanation', 'No explanation provided')}")
        print(f"📜 License: {license_info.get('Name', 'Unknown')} ({license_info.get('Status', 'Unknown')})")
        print(f"🔒 Vulnerabilities: {len(vulnerability_info.get('vulnerabilities', []))}")
        
        # Get health score from nested structure
        health_score = (
            health_info.get('overall_assessment', {}).get('health_score')
            or health_info.get('overallAssessment', {}).get('healthScore')
            or 'Unknown'
        )
        print(f"🏥 Health Score: {health_score}/100")
        print("=" * 50)
        
    except Exception as e:
        print("\n⚠️ Error displaying results:")
        print("=" * 50)
        print(f"Error: {str(e)}")
        print("=" * 50)

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        # If no arguments provided, evaluate from cache
        print("No package specified, evaluating from cache...")
        result = asyncio.run(evaluate_from_cache())
    else:
        # Evaluate the specified package
        package_input = sys.argv[1]
        print(f"Evaluating package: {package_input}")
        result,mdf = asyncio.run(evaluate_package_team(package_input))
    
    print_results(result) 