import os
import yaml
import re
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List
import time
import random

from smolagents import CodeAgent, tool, FinalAnswerTool, LiteLLMModel

import agent_models
import agent_tools

from dotenv import load_dotenv
load_dotenv()

final_answer_tool = FinalAnswerTool()

# Helper function to handle rate limiting with exponential backoff
def sleep_with_backoff(attempt=1, base_time=2, max_time=60):
    """Sleep with exponential backoff and randomized duration to handle rate limiting
    
    Args:
        attempt: The current retry attempt number (starts at 1)
        base_time: The base sleep time in seconds
        max_time: Maximum sleep time in seconds
    """
    # Calculate exponential backoff with attempt
    backoff_time = min(base_time * (2 ** (attempt - 1)), max_time)
    
    # Add jitter (random variation) to avoid synchronized retries
    jitter = random.uniform(0.8, 1.2)
    sleep_time = backoff_time * jitter
    
    print(f"Sleeping for {sleep_time:.2f} seconds to avoid rate limits...")
    time.sleep(sleep_time)

@tool
def extract_package_info(text: str) -> Dict[str, Any]:
    """
    Extract package information from the given text.
    
    Args:
        text: Text containing information about a software package
        
    Returns:
        Dictionary with extracted package information
    """
    # Use pattern matching to extract version information
    version_pattern = r'(?:version|v)[:\s]+([0-9]+(?:\.[0-9]+)*(?:-[a-zA-Z0-9]+)?)'
    version_match = re.search(version_pattern, text, re.IGNORECASE)
    version = version_match.group(1) if version_match else None
    
    # Extract URLs
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    urls = re.findall(url_pattern, text)
    
    # Categorize URLs
    repo_urls = []
    doc_urls = []
    package_manager_urls = []
    other_urls = []
    
    for url in urls:
        parsed = urlparse(url)
        
        # Repository URLs
        if any(domain in parsed.netloc for domain in ['github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net', 'huggingface.co']):
            repo_urls.append(url)
        # Package manager URLs
        elif any(domain in parsed.netloc for domain in ['npmjs.com', 'pypi.org', 'maven.org', 'nuget.org']):
            package_manager_urls.append(url)
        # Documentation URLs
        elif any(domain in parsed.netloc for domain in ['docs.', 'documentation.', 'readthedocs.io']):
            doc_urls.append(url)
        # Other URLs
        else:
            other_urls.append(url)
    
    # Try to extract owner information from repository URL
    owner = None
    if repo_urls:
        for repo_url in repo_urls:
            parsed = urlparse(repo_url)
            if 'github.com' in parsed.netloc or 'gitlab.com' in parsed.netloc:
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) >= 2:
                    owner = path_parts[0]  # First part of path is owner/org
                    break
            elif 'huggingface.co' in parsed.netloc:
                path_parts = parsed.path.strip('/').split('/')
                if len(path_parts) >= 1:
                    owner = path_parts[0]  # First part of path is owner/org
                    break
    
    return {
        "Extracted Version": version,
        "URLs": urls,
        "Repository URLs": repo_urls,
        "Package Manager URLs": package_manager_urls,
        "Documentation URLs": doc_urls,
        "Other URLs": other_urls,
        "Owner": owner,
        "Raw Text": text
    }

@tool
def find_package_version(name: str, max_retries: int = 5) -> Dict[str, Any]:
    """
    Find the latest version of a package by searching package repositories.
    
    Args:
        name: Name of the package to look up
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        Dictionary with version information
    """
    # Create search terms for different package managers
    search_terms = [
        f"{name} latest version npm",
        f"{name} latest version pypi",
        f"{name} latest version maven",
        f"{name} latest version nuget",
        f"{name} latest release github",
        f"{name} latest version"
    ]
    
    # Extract URLs from the search result
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    
    # Try each search term until we find version information
    for search_term in search_terms:
        # Apply retry mechanism for each search term
        for attempt in range(1, max_retries + 1):
            try:
                # Add sleep before search to avoid rate limits
                if attempt > 1:  # Only sleep if this is a retry
                    sleep_with_backoff(attempt=attempt)
                else:
                    sleep_with_backoff(attempt=1, base_time=1)  # Smaller sleep for first attempt
                
                search_result = agent_tools.search_web(search_term)
                
                # Extract version information from the search result
                # More comprehensive version pattern to catch various formats like 1.2.3, v1.2.3, version 1.2.3, etc.
                version_patterns = [
                    r'(?:version|v)[:\s]+([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)',  # version: 1.2.3 or v: 1.2.3
                    r'latest (?:version|release)[:\s]+([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)',  # latest version: 1.2.3
                    r'(?:released|current)[:\s]+([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)',  # released: 1.2.3
                    r'[\'"]?version[\'"]?[:\s]*[\'"]([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)[\'"]',  # "version": "1.2.3"
                    r'v([0-9]+(?:\.[0-9]+)+(?:-[a-zA-Z0-9.]+)?)',  # v1.2.3
                    r'([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)'  # simple 1.2.3 format (last resort)
                ]
                
                version_match = None
                for pattern in version_patterns:
                    match = re.search(pattern, search_result, re.IGNORECASE)
                    if match:
                        version_match = match
                        break
                
                # Extract URLs from search results
                urls = re.findall(url_pattern, search_result)
                
                if version_match:
                    return {
                        "Package": name,
                        "Latest Version": version_match.group(1),
                        "Search Term": search_term,
                        "Found In": search_result[:200] + "..." if len(search_result) > 200 else search_result,
                        "Source URLs": urls[:5]  # Include up to 5 URLs from the search result
                    }
            except Exception as e:
                error_message = str(e).lower()
                # Check if error message suggests rate limiting
                rate_limit_keywords = ["rate limit", "too many requests", "429", "quota exceeded", "throttl"]
                is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                
                if is_rate_limit and attempt < max_retries:
                    print(f"Search for package version '{search_term}' failed due to rate limiting. Retrying ({attempt}/{max_retries})...")
                    continue  # Sleep will happen at the start of the next iteration
                elif attempt < max_retries:
                    # If it's not a rate limit error but we still have retries
                    print(f"Search for package version '{search_term}' failed for other reasons. Retrying ({attempt}/{max_retries})...")
                    continue
                else:
                    # If we've reached the maximum number of retries, move to the next search term
                    print(f"Search for package version '{search_term}' failed after {max_retries} attempts. Trying next search term...")
                    break
    
    # If we've tried all search terms and still haven't found a version
    return {
        "Package": name,
        "Latest Version": "Unknown",
        "Error": "Could not determine latest version after trying multiple search terms"
    }

@tool
def find_package_owner(name: str, max_retries: int = 5) -> Dict[str, Any]:
    """
    Find the owner/maintainer of a package by searching online sources.
    
    Args:
        name: Name of the package to look up
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        Dictionary with owner information
    """
    # Create search terms for finding package owner
    search_terms = [
        f"{name} package owner",
        f"{name} maintainer",
        f"{name} who maintains",
        f"{name} github owner",
        f"{name} company behind"
    ]
    
    # Extract URLs from the search result
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    
    # Try each search term until we find owner information
    for search_term in search_terms:
        # Apply retry mechanism for each search term
        for attempt in range(1, max_retries + 1):
            try:
                # Add sleep before search to avoid rate limits
                if attempt > 1:  # Only sleep if this is a retry
                    sleep_with_backoff(attempt=attempt)
                else:
                    sleep_with_backoff(attempt=1, base_time=1)  # Smaller sleep for first attempt
                
                search_result = agent_tools.search_web(search_term)
                
                # Check if search result contains owner information
                owner_candidates = []
                
                # Look for GitHub/GitLab patterns
                github_pattern = r'github\.com/([^/]+)/[^/]+'
                github_matches = re.findall(github_pattern, search_result)
                owner_candidates.extend(github_matches)
                
                # Look for company/org names mentioned with ownership terms
                company_pattern = r'(developed|maintained|created|owned|built) by ([A-Z][a-zA-Z0-9\s]+)'
                company_matches = re.findall(company_pattern, search_result)
                for match in company_matches:
                    owner_candidates.append(match[1].strip())
                
                # Extract URLs from search results
                urls = re.findall(url_pattern, search_result)
                
                if owner_candidates:
                    # Count occurrences of each candidate
                    from collections import Counter
                    candidate_counts = Counter(owner_candidates)
                    most_common = candidate_counts.most_common(1)[0][0]
                    
                    return {
                        "Package": name,
                        "Owner": most_common,
                        "All Candidates": dict(candidate_counts),
                        "Search Term": search_term,
                        "Source URLs": urls[:5]  # Include up to 5 URLs from the search result
                    }
            except Exception as e:
                error_message = str(e).lower()
                # Check if error message suggests rate limiting
                rate_limit_keywords = ["rate limit", "too many requests", "429", "quota exceeded", "throttl"]
                is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                
                if is_rate_limit and attempt < max_retries:
                    print(f"Search for package owner '{search_term}' failed due to rate limiting. Retrying ({attempt}/{max_retries})...")
                    continue  # Sleep will happen at the start of the next iteration
                elif attempt < max_retries:
                    # If it's not a rate limit error but we still have retries
                    print(f"Search for package owner '{search_term}' failed for other reasons. Retrying ({attempt}/{max_retries})...")
                    continue
                else:
                    # If we've reached the maximum number of retries, move to the next search term
                    print(f"Search for package owner '{search_term}' failed after {max_retries} attempts. Trying next search term...")
                    break
    
    # If we've tried all search terms and still haven't found an owner
    return {
        "Package": name,
        "Owner": "Unknown",
        "Error": "Could not determine package owner after trying multiple search terms"
    }

def validate_output(final_answer, memory):  
    """
    Validate the format of the final answer provided by the agent.
    
    Args:
        final_answer: The final answer from the agent
        memory: The agent's memory
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    required_keys = ["Name", "Latest Package Version", "Requested Package Version", 
                     "Primary Language", "License Type", "Description", "Link to Source Code",
                     "Package Owner", "References"]
    
    # If final_answer is a string, try to evaluate it as a dictionary
    if isinstance(final_answer, str):
        try:
            # Clean up the string to make it a valid Python dict
            final_answer = final_answer.replace("'", '"')
            
            # If the string doesn't start with a {, add it
            if not final_answer.strip().startswith('{'):
                final_answer = '{' + final_answer + '}'
                
            # Try to evaluate the string as a dictionary
            import ast
            final_answer = ast.literal_eval(final_answer)
        except:
            return False, f"Final answer is not a valid dictionary: {final_answer}"

    # Check if final_answer is a dictionary
    if not isinstance(final_answer, dict):
        return False, f"Final answer is not a dictionary: {final_answer}"
    
    # Check if all required keys are present
    missing_keys = [key for key in required_keys if key not in final_answer]
    if missing_keys:
        return False, f"Missing required keys: {', '.join(missing_keys)}"
    
    return True, ""

def package_researcher(text_information: str) -> Dict[str, Any]:
    """
    Research a software package based on the provided information.
    
    Args:
        text_information: Textual information about the software package
        
    Returns:
        Dictionary with package research results, containing:
        - Name: The Name of the Identified Package
        - Latest Package Version: Latest version available online or "Latest" if not found
        - Requested Package Version: Requested version or latest if not specified
        - Primary Language: Primary programming language or N/A
        - License Type: Software license type or "Not Found"
        - Description: High-level summary of the package
        - Link to Source Code: URL to the package's source code repository
        - Package Owner: Individual, organization, or company that owns/maintains the package
        - References: List of URLs used as sources for the information
    """
    # Import datetime to get the current date
    from datetime import datetime

    # Get the current date for the agent's context
    current_date = datetime.now().strftime("%B %d, %Y")

    # Create an agent with the research tools
    agent = CodeAgent(
        tools=[
            extract_package_info,
            find_package_version,
            find_package_owner,
            agent_tools.search_web,
            final_answer_tool
        ],
        model=agent_models.gemini_model,
        max_steps=20,
        final_answer_checks=[validate_output],
        additional_authorized_imports=["urllib.parse", "re", "json", "datetime"]
    )
    
    # Construct a prompt for the agent based on the detailed flow
    prompt = f"""
    I need you to research the software package described in the information below. Your task is to extract or find 
    all relevant information about this package and provide a comprehensive report.
    
    IMPORTANT: Today's date is {current_date}. When evaluating version release dates, package age, or any time-related information, 
    use this date as the reference point.
    
    Package Information:
    {text_information}
    
    Follow these precise steps:
    
    1. Analyze the given text to identify the package name and any immediately available information.
    
    2. If URLs are provided in the text, prioritize extracting information from them first:
       a. If the URL points to a repository (GitHub, GitLab, etc.), extract the package name, description, language, license, and owner.
       b. If the URL is to a package manager (npm, PyPI, etc.), extract version information as well.
    
    3. Use the search_web tool to fill in any missing information:
       a. If the package name is unclear, search for keywords from the text to identify it
       b. Search for the latest version of the package - ALWAYS try to find the specific version number (like "1.2.3")
       c. Search for the primary programming language
       d. Search for the license type
       e. Search for a comprehensive description
       f. Search for the repository URL if not already found
       g. Search for the package owner (individual, organization, or company that maintains the package)
    
    4. For each piece of information you find, keep track of the source URL where you found it.
    
    5. If there's any conflicting information, use the most authoritative source (official repository, package manager, documentation).
    
    6. IMPORTANT - For version handling:
       a. If the text contains terms like "current", "latest", "newest", or similar words that suggest the latest version, then the "Requested Package Version" should be set to the actual latest version number you find.
       b. NEVER use the string "Latest" as a version number. Always try to find the specific numeric version (e.g., "4.2.1").
       c. Only if you absolutely cannot find a specific version number after searching, then use "Unknown" instead of "Latest".
       d. Remember that today's date is {current_date} when evaluating if a version release date is valid - versions with dates up to this day are valid, not "from the future".
    
    Your final answer MUST be a dictionary containing these exact keys:
    - Name: The Name of the Identified Package
    - Latest Package Version: The specific version number of the latest version available (e.g., "2.1.3"), or "Unknown" if no version found.
    - Requested Package Version: The specific version requested by the user, or the same as Latest Package Version if the user asked for "latest", "current", etc., or if no version was specified.
    - Primary Language: Identified programming primary language if available or "N/A".
    - License Type: Identified software license type of the package or "Not Found".
    - Description: A high level summary of what this software package is, what it does, and common use cases.
    - Link to Source Code: If identified, a URL to the package's source code page on github, gitlab, sourceforge, huggingface, or similar.
    - Package Owner: The individual, organization, or company that owns or maintains the package (e.g., Google, Meta, Hashicorp, individual GitHub username).
    - References: A list of URLs that were used as sources for the information gathered about this package.
    """
    
    return agent.run(prompt)


if __name__ == "__main__":
    # Example usage
    # test_info = "I need information about React.js for a project"
    
    # test_info = "https://github.com/tensorflow/tensorflow"
    
    # test_info = "lodash version 4.17"
    
    # test_info = "Django python framework"
    
    # test_info = "https://huggingface.co/Qwen/QwQ-32B"
    # test_info = "e2b"
    test_info = "Hashicorp Vault"
    result = package_researcher(test_info)
    print("\nPackage Research Results:")
    print(f"Name: {result['Name']}")
    print(f"Latest Version: {result['Latest Package Version']}")
    print(f"Requested Version: {result['Requested Package Version']}")
    print(f"Primary Language: {result['Primary Language']}")
    print(f"License Type: {result['License Type']}")
    print(f"Package Owner: {result['Package Owner']}")
    print(f"Description: {result['Description']}")
    print(f"Source Code: {result['Link to Source Code']}")
    
    # Print references if they exist
    if "References" in result and result["References"]:
        print("\nReferences:")
        for i, ref in enumerate(result["References"], 1):
            print(f"{i}. {ref}")
    
"""
General Flow:
1. Extract any information available from the initial text
2. Search for any remaining information needed
3. Format the results into a structured output
""" 