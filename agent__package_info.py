"""
Package Researcher using Pydantic AI

This module provides functionality to research software packages, libraries, or tools
based on provided text information using Pydantic AI.
"""

import asyncio
from typing import List
from datetime import datetime
from typing_extensions import TypedDict, NotRequired
from pydantic import BaseModel
from pydantic_ai import Agent, RunContext
from dotenv import load_dotenv
import external_tools

load_dotenv()


# Define structured output type for package research
class PackageResearchResult(TypedDict):
    """Package research result with comprehensive package information."""
    Name: str
    Latest_Package_Version: str
    Requested_Package_Version: str
    Primary_Language: str
    License_Type: str
    Description: str
    Link_to_Source_Code: str
    Package_Owner: str
    References: List[str]
    Documentation_URL: NotRequired[str]
    Normalization: NotRequired[str]

class PackageResearchRequest(BaseModel):
    """Request for package research."""
    text_information: str
# Define dependencies for the agent
class PackageResearchDeps(BaseModel):
    """Dependencies for package research."""
    current_date: str


# Create the Pydantic AI agent
package_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=PackageResearchDeps,
    result_type=PackageResearchResult,
    retries=3,
    system_prompt="""
    You are a package researcher for a software company. Your task is to:
    
    1. Identify the package from the user's input (which may be a URL, package name, or direct package reference)
    2. Research comprehensive information about the package
    3. Provide a structured response with all required information
    
    IMPORTANT GUIDELINES:
    
    - If URLs are provided, visit them to find package information (especially GitHub repositories)
    - For GitHub repos, check package metadata files, README.md, and documentation
    - Version handling is CRITICAL:
      * If a specific version is mentioned (e.g., "Python 3.6"), find information for that version
      * For "Latest_Package_Version", ALWAYS return the absolute latest version available, regardless of major version
      * For "Requested_Package_Version":
        - If a specific version is requested, return that version
        - If no version is specified, return the same version as Latest_Package_Version
      * If a version series is mentioned (e.g., "Python 3.x"), find the latest version in that series
    - Cross-reference information from multiple sources to ensure accuracy
    - For non-standard or proprietary packages, flag them appropriately
    - Always verify version information against official package repositories (PyPI, npm, etc.)
    
    Always verify your findings from multiple sources before making a determination.
    """
)

@package_agent.tool
def find_basic_package_information(ctx: RunContext[PackageResearchDeps], request: PackageResearchRequest) -> str:
    """
    Find basic information about a package by searching package repositories 
    and relevant websites.

    Args:
        ctx: Run context with dependencies
        text_information: Textual information about the software package that may
                         include URLs, package name, and version
    
    Returns:
        Comprehensive information about the package
    """
    print(f"find_basic_package_information called with text_information: {request.text_information}")
    prompt = f"""
    Today's date is {ctx.deps.current_date}.
    
    Your task is to search the web to identify basic information about a software package based on the provided information.
    If URLs are present in the text, prioritize extracting information from those URLs first.
    
    Information to extract:
    1. Package name - Return "Unknown" if not found
    2. Package owner/maintainer/organization - Return "Unknown" if not found
    3. Package age - How long has this package existed?
    4. Latest version number - Return "Unknown" if not found
      * CRITICAL: This MUST be the absolute latest version available, regardless of major version
      * For example, for Python, this should be the latest version (e.g., 3.13.x), not just the latest in an older series
      * For packages with multiple major versions, return the highest version number
      * If a package has multiple release channels (stable, beta, etc.), prefer the stable channel
      * IMPORTANT: This should be the true latest version, not the latest version in the requested series
    5. The specific version mentioned in the input text (if any)
      * If a specific version is requested, return that version
      * If no version is specified, return the same version as Latest_Package_Version
      * If a version series is mentioned (e.g., "Python 3.x"), find the latest version in that series
      * IMPORTANT: This is separate from Latest_Package_Version - Latest_Package_Version should always be the absolute latest
    6. Package description - Return "Unknown" if not found
    7. Source code repository URL - Return "Unknown" if not found
    8. Primary programming language - Return "Unknown" if not found
    9. Documentation URLs - Return "Unknown" if not found
    10. License type - Return "Unknown" if not found. Ensure the license is valid for the specified version
    11. Documentation URL - Look for official documentation URL (e.g., docs.python.org, reactjs.org/docs, etc.)
       - This should be the main documentation URL, not just a GitHub README
       - Return "Unknown" if not found
    
    Validation steps:
    1. If a specific version is mentioned, verify that it exists. Include a WARNING if verification fails.
    2. For latest version, verify against official package repositories (PyPI, npm, etc.)
    3. Cross-reference information from multiple sources when possible to ensure accuracy.
    4. If URLs are provided, check if they are valid and contain the required information.
    5. CRITICAL: Latest_Package_Version must ALWAYS be the absolute latest version, regardless of what version was requested
    6. Verify documentation URLs are accessible and point to official documentation
    7. For latest version, ensure you're getting the absolute latest, not just the latest in a specific series
    8. Double-check that Latest_Package_Version is truly the latest version available, not just the latest in the requested series
    
    Text Information:
    {request.text_information}
    
    Your final answer MUST be a detailed report of all information found organized by category.
    Include all source URLs that provided the information.
    If no information can be found, return "No information found".
    """
    
    result = external_tools.search_web(prompt)
    return result.data if result.status == "success" else f"Error: {result.error}"

@package_agent.tool
def extract_package_from_url(ctx: RunContext[PackageResearchDeps], url: str) -> str:
    """
    Extract package information from a specific URL.
    
    Args:
        ctx: Run context with dependencies
        url: URL that may contain package information
    
    Returns:
        Extracted package information from the URL
    """
    print(f"extract_package_from_url called with URL: {url}")
    render_js = any(domain in url for domain in ["github.com", "gitlab.com", "npmjs.com", "pypi.org"])
    
    try:
        result = external_tools.scrape_url(url, render_js=render_js)
        if result.status != "success":
            return f"Error visiting URL {url}: {result.error}"
            
        content = result.content
        
        # Special handling for GitHub repositories
        if "github.com" in url:
            # Extract owner and repo from URL
            parts = url.rstrip("/").split("/")
            if len(parts) >= 5:
                owner = parts[-2]
                repo = parts[-1]
                
                # Check releases page
                releases_url = f"https://github.com/{owner}/{repo}/releases"
                releases_result = external_tools.scrape_url(releases_url, render_js=True)
                releases_content = releases_result.content if releases_result.status == "success" else ""
                
                # Check repository metadata
                api_url = f"https://api.github.com/repos/{owner}/{repo}"
                api_result = external_tools.scrape_url(api_url, render_js=False)
                api_content = api_result.content if api_result.status == "success" else ""
                
                prompt = f"""
                Analyze the following content from GitHub repository: {url}
                
                Main Repository Content:
                {content}
                
                Releases Page Content:
                {releases_content}
                
                Repository API Data:
                {api_content}
                
                Extract the following information if available:
                1. Package name
                2. Latest version (from releases page)
                3. Owner/maintainer
                4. Description
                5. License information (from repository metadata)
                6. Primary programming language (from repository metadata)
                7. Links to documentation
                8. Links to source code
                9. Release date or package age
                
                If the content references other important pages with additional information, note those URLs.
                
                Return the extracted information in a structured format.
                """
            else:
                prompt = f"""
                Analyze the following content from URL: {url}
                
                Content:
                {content}
                
                Extract the following information if available:
                1. Package name
                2. Latest version
                3. Owner/maintainer
                4. Description
                5. License information
                6. Primary programming language
                7. Links to documentation
                8. Links to source code
                9. Release date or package age
                
                If the content references other important pages with additional information, note those URLs.
                
                Return the extracted information in a structured format.
                """
        else:
            prompt = f"""
            Analyze the following content from URL: {url}
            
            Content:
            {content}
            
            Extract the following information if available:
            1. Package name
            2. Latest version
            3. Owner/maintainer
            4. Description
            5. License information
            6. Primary programming language
            7. Links to documentation
            8. Links to source code
            9. Release date or package age
            
            If the content references other important pages with additional information, note those URLs.
            
            Return the extracted information in a structured format.
            """
        
        result = external_tools.search_web(prompt)
        return result.data if result.status == "success" else f"Error: {result.error}"
    except Exception as e:
        return f"Error processing URL {url}: {str(e)}"

@package_agent.system_prompt
def add_current_date(ctx: RunContext[PackageResearchDeps]) -> str:
    """Add current date to the system prompt."""
    return f"Today's date is {ctx.deps.current_date}."

async def package_researcher(text_information: str) -> PackageResearchResult:
    """
    Research a software package based on the provided information.
    
    Args:
        text_information: Textual information about the software package
        
    Returns:
        Dictionary with package research results
    """
    # Load dependencies
    current_date = datetime.now().strftime("%B %d, %Y")
    deps = PackageResearchDeps(current_date=current_date)
    
    try:
        result = await package_agent.run(text_information, deps=deps)
        return result.data
    except Exception as e:
        return {
            "Name": "Unknown",
            "Latest_Package_Version": "Unknown",
            "Requested_Package_Version": "Unknown",
            "Primary_Language": "Unknown",
            "License_Type": "Unknown",
            "Description": f"Error while researching package: {str(e)}. Please review the package information manually.",
            "Link_to_Source_Code": "Unknown",
            "Package_Owner": "Unknown",
            "Documentation_URL": "Unknown",
            "References": [f"Error during processing: {str(e)}"]
        }
    
def print_results(result: PackageResearchResult):
    # Print results in a clean format
    print("\n🔍 PACKAGE RESEARCH RESULTS:")
    print("=" * 50)
    print(f"📦 Package: {result['Name']}")
    print(f"📊 Latest Version: {result['Latest_Package_Version']}")
    print(f"🎯 Requested Version: {result['Requested_Package_Version']}")
    print(f"💻 Primary Language: {result['Primary_Language']}")
    print(f"📜 License: {result['License_Type']}")
    print(f"📝 Description: {result['Description']}")
    print(f"🔗 Source Code: {result['Link_to_Source_Code']}")
    print(f"📚 Documentation: {result.get('Documentation_URL', 'Unknown')}")
    print(f"👤 Package Owner: {result['Package_Owner']}")
    
    if "Normalization" in result:
        print(f"🔄 Normalization: {result['Normalization']}")
    
    if result['References']:
        print("\n📚 References:")
        for i, ref in enumerate(result['References'], 1):
            print(f"  {i}. {ref}")
    print("=" * 50) 

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python agent__package_info.py <package_name_or_url>")
        sys.exit(1)
        
    package_input = sys.argv[1]
    
    # Run the async function using asyncio
    result = asyncio.run(package_researcher(package_input))
    print_results(result)

    import json
    with open("package_info.json", "w") as f:
        json.dump(result, f)