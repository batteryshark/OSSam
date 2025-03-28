"""
Software Health Assessor using Pydantic AI

This module provides functionality to assess the overall health, sustainability,
maintenance status, and reputational standing of software packages using Pydantic AI.
"""

import asyncio
import json
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field
from pydantic_ai import Agent, RunContext
from dotenv import load_dotenv
import external_tools

load_dotenv()

# Basic Info Models
class BasicInfo(BaseModel):
    """Basic information about the software."""
    name: str = Field(..., description="Name of the software")
    description: str = Field(..., description="Description of the software")
    repository_url: str = Field(..., description="Repository URL")
    website_url: Optional[str] = Field(None, description="Website URL")
    type: str = Field(..., description="Type of software")
    stars_forks: Optional[str] = Field(None, description="GitHub stars and forks")
    downloads: Optional[str] = Field(None, description="Download statistics")

# Community Models
class CommunityInfo(BaseModel):
    """Community-related information."""
    activity_level: str = Field(..., description="Level of community activity")
    contributor_count: Optional[int] = Field(None, description="Number of contributors")
    contribution_diversity: str = Field(..., description="Diversity of contributions")
    bus_factor: str = Field(..., description="Bus factor assessment")
    notes: str = Field(..., description="Additional community notes")

# Documentation Models
class DocumentationInfo(BaseModel):
    """Documentation-related information."""
    quality: str = Field(..., description="Documentation quality assessment")
    completeness: str = Field(..., description="Documentation completeness")
    examples: str = Field(..., description="Availability of examples")
    notes: str = Field(..., description="Additional documentation notes")

# Maintenance Models
class MaintenanceInfo(BaseModel):
    """Maintenance-related information."""
    status: str = Field(..., description="Maintenance status")
    last_activity: str = Field(..., description="Last activity date")
    activity_frequency: str = Field(..., description="Frequency of updates")
    open_issues: Optional[int] = Field(None, description="Number of open issues")
    notes: str = Field(..., description="Additional maintenance notes")

# Future Models
class FutureInfo(BaseModel):
    """Future outlook information."""
    outlook: str = Field(..., description="Overall future outlook")
    roadmap: str = Field(..., description="Roadmap assessment")
    risks: List[str] = Field(default_factory=list, description="Future risks")
    opportunities: List[str] = Field(default_factory=list, description="Future opportunities")
    notes: str = Field(..., description="Additional future notes")

# Overall Assessment Model
class OverallAssessment(BaseModel):
    """Overall health assessment."""
    health_score: str = Field(..., description="Overall health score (0-100)")
    key_risks: List[str] = Field(default_factory=list, description="Key risks")
    key_strengths: List[str] = Field(default_factory=list, description="Key strengths")
    summary: str = Field(..., description="Overall summary")

# Dependencies
class HealthAssessmentDeps(BaseModel):
    """Dependencies for health assessment."""
    current_date: str

# Owner Models
class OwnerInfo(BaseModel):
    """Information about the software owner/company."""
    name: str = Field(..., description="Name of the owner/company")
    type: str = Field(..., description="Type of owner (company, individual, organization)")
    description: str = Field(..., description="Description of the owner/company")
    funding_status: Optional[str] = Field(None, description="Funding status and history")
    reputation: str = Field(..., description="Overall reputation assessment")
    controversies: List[str] = Field(default_factory=list, description="Known controversies or issues")
    track_record: str = Field(..., description="Track record of other projects/products")
    stability: str = Field(..., description="Assessment of owner/company stability")
    notes: str = Field(..., description="Additional notes about the owner/company")

# Main Software Health Report Model
class SoftwareHealthReport(BaseModel):
    """Complete software health assessment report."""
    assessment_timestamp: str = Field(..., description="Timestamp of the assessment")
    basic_info: BasicInfo = Field(..., description="Basic information about the software")
    owner_info: OwnerInfo = Field(..., description="Information about the software owner/company")
    community_info: CommunityInfo = Field(..., description="Community health information")
    documentation_info: DocumentationInfo = Field(..., description="Documentation quality information")
    maintenance_info: MaintenanceInfo = Field(..., description="Maintenance status information")
    future_info: FutureInfo = Field(..., description="Future outlook information")
    overall_assessment: OverallAssessment = Field(..., description="Overall health assessment")
    error: Optional[str] = Field(None, description="Error message if assessment failed")

# Create specialized agents
basic_info_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=BasicInfo,
    retries=3,
    system_prompt="""
    You are a Basic Information Assessment Agent. Your task is to gather comprehensive basic information
    about a software package. Analyze the provided information to extract:
    1. Name and description
    2. Repository URL and website URL
    3. Type of software
    4. GitHub statistics (stars, forks)
    5. Download statistics
    6. Any additional relevant metrics
    
    Focus on finding official sources and verifying the information. Consider both technical and business aspects.
    """
)

community_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=CommunityInfo,
    retries=3,
    system_prompt="""
    You are a Community Assessment Agent. Your task is to evaluate the software's community health by analyzing:
    1. Activity level based on issues, PRs, and discussions
    2. Contributor diversity and engagement
    3. Bus factor assessment
    4. Community feedback and sentiment
    5. Response times to issues and PRs
    
    Consider both quantitative metrics (number of contributors, issues) and qualitative aspects
    (community engagement, responsiveness). Look for patterns in community behavior and potential risks.
    """
)

documentation_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=DocumentationInfo,
    retries=3,
    system_prompt="""
    You are a Documentation Assessment Agent. Your task is to evaluate the software's documentation by analyzing:
    1. Quality of official documentation
    2. Completeness of coverage
    3. Availability of examples and tutorials
    4. API documentation quality
    5. Community documentation and guides
    
    Consider both technical accuracy and accessibility. Look for gaps in documentation and areas for improvement.
    Assess the documentation's ability to help users get started and solve problems.
    """
)

maintenance_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=MaintenanceInfo,
    retries=3,
    system_prompt="""
    You are a Maintenance Assessment Agent. Your task is to evaluate the software's maintenance status by analyzing:
    1. Activity frequency and patterns
    2. Last activity date
    3. Issue resolution patterns
    4. Release frequency and quality
    5. Maintenance discussions and status updates
    
    Consider both recent activity and historical patterns. Look for signs of active maintenance,
    potential slowdowns, or maintenance issues. Assess the project's ability to handle issues and
    maintain quality over time.
    """
)

future_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=FutureInfo,
    retries=3,
    system_prompt="""
    You are a Future Outlook Assessment Agent. Your task is to evaluate the software's future prospects by analyzing:
    1. Roadmap and development plans
    2. Funding and company information
    3. Community sentiment about future direction
    4. Known issues and controversies
    5. Market position and competition
    
    Consider both technical roadmap and business sustainability. Look for signs of continued investment,
    potential risks, and opportunities. Assess the project's ability to adapt and grow in the future.
    """
)

owner_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=OwnerInfo,
    retries=3,
    system_prompt="""
    You are an Owner/Company Assessment Agent. Your task is to evaluate the software owner/company by analyzing:
    1. Basic information about the owner/company
    2. Funding status and financial stability
    3. Reputation in the industry
    4. Known controversies or issues
    5. Track record with other projects
    6. Overall stability and longevity
    
    Consider both historical context and current status. Look for:
    - Funding rounds and valuations
    - Previous projects and their success/failure
    - Any legal or ethical controversies
    - Company size and growth trajectory
    - Industry reputation and partnerships
    
    This information is crucial for assessing the long-term viability of the software.
    """
)

overall_agent = Agent(
    "google-gla:gemini-2.0-flash",
    deps_type=HealthAssessmentDeps,
    result_type=OverallAssessment,
    retries=3,
    system_prompt="""
    You are an Overall Health Assessment Agent. Your task is to provide a comprehensive health assessment
    based on all available information. Consider:
    1. Overall health score (0-100)
    2. Key risks and their severity
    3. Key strengths and their impact
    4. Comprehensive summary of findings
    
    Provide a balanced evaluation that considers all aspects of the software's health. Focus on actionable
    insights and clear recommendations. Consider both immediate status and long-term sustainability.
    """
)

@basic_info_agent.tool
def get_basic_info(ctx: RunContext[HealthAssessmentDeps], text_information: str) -> str:
    """Get basic information about the software."""
    # Search for general information
    general_result = external_tools.search_web(f"Find comprehensive information about {text_information}")
    
    # Search for GitHub stats if it's a GitHub project
    github_result = external_tools.search_web(f"Find GitHub statistics for {text_information}")
    
    # Search for download statistics
    download_result = external_tools.search_web(f"Find download statistics for {text_information}")
    
    combined_info = f"""
    General Information:
    {general_result.data if general_result.status == "success" else "No general information found"}
    
    GitHub Statistics:
    {github_result.data if github_result.status == "success" else "No GitHub statistics found"}
    
    Download Statistics:
    {download_result.data if download_result.status == "success" else "No download statistics found"}
    """
    
    return combined_info

@community_agent.tool
def get_community_info(ctx: RunContext[HealthAssessmentDeps], repo_url: str) -> str:
    """Get community information from the repository."""
    # Get repository information
    repo_result = external_tools.scrape_url(repo_url, render_js=False)
    
    # Get issues information
    issues_result = external_tools.scrape_url(f"{repo_url}/issues", render_js=False)
    
    # Get pull requests information
    pr_result = external_tools.scrape_url(f"{repo_url}/pulls", render_js=False)
    
    # Search for community discussions
    community_result = external_tools.search_web(f"Find community discussions and feedback about {repo_url}")
    
    combined_info = f"""
    Repository Information:
    {repo_result.content if repo_result.status == "success" else "No repository information found"}
    
    Issues:
    {issues_result.content if issues_result.status == "success" else "No issues information found"}
    
    Pull Requests:
    {pr_result.content if pr_result.status == "success" else "No pull requests information found"}
    
    Community Discussions:
    {community_result.data if community_result.status == "success" else "No community discussions found"}
    """
    
    return combined_info

@documentation_agent.tool
def get_documentation_info(ctx: RunContext[HealthAssessmentDeps], text_information: str) -> str:
    """Get documentation information."""
    # Search for official documentation
    doc_result = external_tools.search_web(f"Find official documentation for {text_information}")
    
    # Search for user guides and tutorials
    tutorial_result = external_tools.search_web(f"Find user guides and tutorials for {text_information}")
    
    # Search for API documentation
    api_result = external_tools.search_web(f"Find API documentation for {text_information}")
    
    # Search for community documentation
    community_doc_result = external_tools.search_web(f"Find community documentation and guides for {text_information}")
    
    combined_info = f"""
    Official Documentation:
    {doc_result.data if doc_result.status == "success" else "No official documentation found"}
    
    User Guides and Tutorials:
    {tutorial_result.data if tutorial_result.status == "success" else "No tutorials found"}
    
    API Documentation:
    {api_result.data if api_result.status == "success" else "No API documentation found"}
    
    Community Documentation:
    {community_doc_result.data if community_doc_result.status == "success" else "No community documentation found"}
    """
    
    return combined_info

@maintenance_agent.tool
def get_maintenance_info(ctx: RunContext[HealthAssessmentDeps], repo_url: str) -> str:
    """Get maintenance information from the repository."""
    # Get repository activity
    activity_result = external_tools.scrape_url(f"{repo_url}/commits", render_js=False)
    
    # Get issues information
    issues_result = external_tools.scrape_url(f"{repo_url}/issues", render_js=False)
    
    # Get release information
    release_result = external_tools.scrape_url(f"{repo_url}/releases", render_js=False)
    
    # Search for maintenance-related discussions
    maintenance_result = external_tools.search_web(f"Find maintenance and development status for {repo_url}")
    
    combined_info = f"""
    Repository Activity:
    {activity_result.content if activity_result.status == "success" else "No activity information found"}
    
    Issues:
    {issues_result.content if issues_result.status == "success" else "No issues information found"}
    
    Releases:
    {release_result.content if release_result.status == "success" else "No release information found"}
    
    Maintenance Discussions:
    {maintenance_result.data if maintenance_result.status == "success" else "No maintenance discussions found"}
    """
    
    return combined_info

@future_agent.tool
def get_future_info(ctx: RunContext[HealthAssessmentDeps], text_information: str) -> str:
    """Get future outlook information."""
    # Search for roadmap information
    roadmap_result = external_tools.search_web(f"Find roadmap and future plans for {text_information}")
    
    # Search for funding and company information
    funding_result = external_tools.search_web(f"Find funding and company information for {text_information}")
    
    # Search for community sentiment and future discussions
    sentiment_result = external_tools.search_web(f"Find community sentiment and future discussions about {text_information}")
    
    # Search for known issues and controversies
    issues_result = external_tools.search_web(f"Find known issues and controversies for {text_information}")
    
    combined_info = f"""
    Roadmap and Future Plans:
    {roadmap_result.data if roadmap_result.status == "success" else "No roadmap information found"}
    
    Funding and Company Information:
    {funding_result.data if funding_result.status == "success" else "No funding information found"}
    
    Community Sentiment:
    {sentiment_result.data if sentiment_result.status == "success" else "No sentiment information found"}
    
    Known Issues and Controversies:
    {issues_result.data if issues_result.status == "success" else "No issues information found"}
    """
    
    return combined_info

@owner_agent.tool
def get_owner_info(ctx: RunContext[HealthAssessmentDeps], text_information: str) -> str:
    """Get information about the software owner/company."""
    # Search for company/owner information
    company_result = external_tools.search_web(f"Find company and owner information for {text_information}")
    
    # Search for funding information
    funding_result = external_tools.search_web(f"Find funding and financial information for {text_information}")
    
    # Search for controversies and issues
    controversy_result = external_tools.search_web(f"Find controversies and issues related to {text_information}")
    
    # Search for track record and history
    history_result = external_tools.search_web(f"Find history and track record for {text_information}")
    
    combined_info = f"""
    Company/Owner Information:
    {company_result.data if company_result.status == "success" else "No company information found"}
    
    Funding Information:
    {funding_result.data if funding_result.status == "success" else "No funding information found"}
    
    Controversies and Issues:
    {controversy_result.data if controversy_result.status == "success" else "No controversy information found"}
    
    Track Record and History:
    {history_result.data if history_result.status == "success" else "No history information found"}
    """
    
    return combined_info

async def software_health_assessor(text_information: str) -> SoftwareHealthReport:
    """Assess software health using multiple specialized agents."""
    current_date = datetime.now().strftime("%B %d, %Y")
    deps = HealthAssessmentDeps(current_date=current_date)
    
    try:
        print("\n🔄 Starting software health assessment...")
        print("=" * 50)
        
        print("\n📦 Gathering basic information...")
        basic_info = await basic_info_agent.run(text_information, deps=deps)
        print("✓ Basic information gathered")
        
        print("\n👤 Analyzing owner/company information...")
        owner_info = await owner_agent.run(text_information, deps=deps)
        print("✓ Owner information analyzed")
        
        print("\n👥 Evaluating community health...")
        community_info = await community_agent.run(basic_info.data.repository_url, deps=deps)
        print("✓ Community health evaluated")
        
        print("\n📚 Assessing documentation quality...")
        documentation_info = await documentation_agent.run(text_information, deps=deps)
        print("✓ Documentation quality assessed")
        
        print("\n🔧 Checking maintenance status...")
        maintenance_info = await maintenance_agent.run(basic_info.data.repository_url, deps=deps)
        print("✓ Maintenance status checked")
        
        print("\n🔮 Analyzing future outlook...")
        future_info = await future_agent.run(text_information, deps=deps)
        print("✓ Future outlook analyzed")
        
        print("\n📊 Generating overall assessment...")
        overall_info = await overall_agent.run(
            f"Basic: {basic_info.data.model_dump_json()}\n"
            f"Owner: {owner_info.data.model_dump_json()}\n"
            f"Community: {community_info.data.model_dump_json()}\n"
            f"Documentation: {documentation_info.data.model_dump_json()}\n"
            f"Maintenance: {maintenance_info.data.model_dump_json()}\n"
            f"Future: {future_info.data.model_dump_json()}",
            deps=deps
        )
        print("✓ Overall assessment generated")
        
        print("\n💾 Preparing final report...")
        result = SoftwareHealthReport(
            assessment_timestamp=current_date,
            basic_info=basic_info.data,
            owner_info=owner_info.data,
            community_info=community_info.data,
            documentation_info=documentation_info.data,
            maintenance_info=maintenance_info.data,
            future_info=future_info.data,
            overall_assessment=overall_info.data
        )
        print("✓ Report prepared")
        print("=" * 50)
        
        return result
        
    except Exception as e:
        print(f"\n❌ Error during assessment: {str(e)}")
        return SoftwareHealthReport(
            assessment_timestamp=current_date,
            basic_info=BasicInfo(
                name="Error",
                description="Error during assessment",
                repository_url="Unknown",
                type="Unknown"
            ),
            owner_info=OwnerInfo(
                name="Error",
                type="Unknown",
                description="Error during assessment",
                reputation="Unknown",
                track_record="Unknown",
                stability="Unknown",
                notes="Error during assessment"
            ),
            community_info=CommunityInfo(
                activity_level="Unknown",
                contribution_diversity="Unknown",
                bus_factor="Unknown",
                notes="Error during assessment"
            ),
            documentation_info=DocumentationInfo(
                quality="Unknown",
                completeness="Unknown",
                examples="Unknown",
                notes="Error during assessment"
            ),
            maintenance_info=MaintenanceInfo(
                status="Unknown",
                last_activity="Unknown",
                activity_frequency="Unknown",
                notes="Error during assessment"
            ),
            future_info=FutureInfo(
                outlook="Unknown",
                roadmap="Unknown",
                notes="Error during assessment"
            ),
            overall_assessment=OverallAssessment(
                health_score="0",
                summary="Error during assessment"
            ),
            error=str(e)
        )

def print_results(result: dict):
    """Print health assessment results in a clean format."""
    print("\n🔍 SOFTWARE HEALTH ASSESSMENT:")
    print("=" * 50)
    
    if "error" in result:
        print(f"❌ Error: {result['error']}")
        return
        
    basic = result["basic_info"]
    print(f"📦 Package: {basic['name']}")
    print(f"📝 Description: {basic['description']}")
    print(f"🔗 Repository: {basic['repository_url']}")
    if basic.get("website_url"):
        print(f"🌐 Website: {basic['website_url']}")
    
    owner = result["owner_info"]
    print(f"\n👤 Owner/Company: {owner['name']}")
    print(f"📋 Type: {owner['type']}")
    print(f"💰 Funding: {owner['funding_status'] or 'Unknown'}")
    print(f"⭐ Reputation: {owner['reputation']}")
    print(f"📊 Stability: {owner['stability']}")
    
    overall = result["overall_assessment"]
    print(f"\n💯 Health Score: {overall['health_score']}")
    
    maintenance = result["maintenance_info"]
    print(f"🔧 Maintenance: {maintenance['status']}")
    print(f"⏰ Last Activity: {maintenance['last_activity']}")
    
    community = result["community_info"]
    print(f"👥 Community Health: {community['activity_level']}")
    
    documentation = result["documentation_info"]
    print(f"📚 Documentation: {documentation['quality']}")
    
    future = result["future_info"]
    print(f"🔮 Future Outlook: {future['outlook']}")
    
    if owner["controversies"]:
        print("\n⚠️ Owner Controversies:")
        for controversy in owner["controversies"]:
            print(f"  • {controversy}")
    
    if overall["key_risks"]:
        print("\n⚠️ Key Risks:")
        for risk in overall["key_risks"]:
            print(f"  • {risk}")
    
    if overall["key_strengths"]:
        print("\n💪 Key Strengths:")
        for strength in overall["key_strengths"]:
            print(f"  • {strength}")
    
    print("=" * 50)

def save_results_json(result: dict, filename: str = "software_health.json"):
    """Save health assessment results to a JSON file."""
    with open(filename, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nResults saved to {filename}")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python agent__software_health_assessor.py <package_name_or_url>")
        sys.exit(1)
        
    package_input = sys.argv[1]
    
    # Run the async function using asyncio
    result = asyncio.run(software_health_assessor(package_input))
    print_results(result)
    save_results_json(result) 