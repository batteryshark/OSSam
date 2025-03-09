import os
import yaml
import re
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List, Tuple
import time
import random

from smolagents import CodeAgent, tool, FinalAnswerTool, LiteLLMModel
import agent_models
import agent_tools

# Import nvdlib for direct NVD API access
import nvdlib

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

def is_version_affected(cve_description: str, package_version: str) -> bool:
    """
    Determine if a specific package version is affected by a vulnerability based on its description.
    
    Args:
        cve_description: The description of the CVE
        package_version: The specific version to check
        
    Returns:
        Boolean indicating if the version is potentially affected
    """
    # If no specific version is provided, assume it's affected
    if not package_version:
        return True
        
    # Quick check for when the description explicitly mentions the version
    if package_version.lower() in cve_description.lower():
        return True

    # Common patterns indicating version ranges in CVE descriptions
    affected_patterns = [
        f"versions up to {package_version}",
        f"versions before {package_version}",
        f"prior to {package_version}",
        f"versions {package_version} and earlier",
        f"including {package_version}",
        f"{package_version} is affected"
    ]
    
    # Check if any of the patterns match
    for pattern in affected_patterns:
        if pattern.lower() in cve_description.lower():
            return True
    
    # If the description mentions version ranges, we would need more complex parsing
    # For a robust solution, this is where an LLM call would be ideal
    # For now, we'll be conservative and include the CVE if we're not sure
    if any(x in cve_description.lower() for x in ["version", "affected", "vulnerable", "impact"]):
        return True
        
    return False

def check_version_with_llm(cve_description: str, package_name: str, package_version: str, max_retries: int = 5) -> Tuple[bool, str]:
    """
    Use LLM to determine if a specific package version is affected by a vulnerability.
    Uses exponential backoff to handle rate limiting.
    
    Args:
        cve_description: The description of the CVE
        package_name: Name of the package
        package_version: The specific version to check
        max_retries: Maximum number of retries (default: 5)
        
    Returns:
        Tuple of (is_affected, explanation)
    """
    # Skip LLM check if no version specified
    if not package_version:
        return True, "No specific version provided to check"
        
    # Create a more detailed prompt for Gemini
    prompt = f"""
    Analyze if version '{package_version}' of '{package_name}' is affected by the following CVE:
    
    CVE description:
    {cve_description}
    
    Follow these steps:
    1. Identify any version information mentioned in the description (ranges, specific versions, etc.)
    2. Compare '{package_version}' with the affected versions
    3. Determine if '{package_version}' falls within the affected range or matches the criteria
    
    Rules:
    - Consider version comparisons semantically (e.g., 1.1.0 is different from 1.1.0q)
    - If the description mentions "prior to X" and '{package_version}' is before X, it's affected
    - If the description mentions "up to X" and '{package_version}' is before or equal to X, it's affected
    - If the description mentions "between X and Y" and '{package_version}' falls in that range, it's affected
    - If no clear version information is given, but it seems to affect all versions, assume it's affected
    
    Begin your response with YES, NO, or UNCERTAIN, then explain your reasoning.
    """
    
    # Try multiple times with exponential backoff for rate limiting
    for attempt in range(1, max_retries + 1):
        try:
            # Get a Gemini model instance
            model = LiteLLMModel(
                model_id="gemini/gemini-2.0-flash-lite",
                api_key=os.getenv("GEMINI_API_KEY")
            )
            
            # Format message in chat format
            messages = [
                {"role": "user", "content": [{"type": "text", "text": prompt}]}
            ]
            
            # Get response from the model with temperature 0 for deterministic output
            response = model(messages, temperature=0.0).content.strip()
            
            # Parse the response
            clean_response = response.upper()
            
            # Determine if the version is affected based on the response
            if "YES" in clean_response[:10]:
                return True, response
            elif "NO" in clean_response[:10]:
                return False, response
            else:
                # If uncertain, be conservative and assume it could be affected
                return True, response
                
        except Exception as e:
            error_message = str(e).lower()
            
            # Check if error message suggests rate limiting
            rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
            is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
            
            if is_rate_limit and attempt < max_retries:
                print(f"Gemini API rate limited. Retrying attempt {attempt}/{max_retries}...")
                sleep_with_backoff(attempt=attempt, base_time=5, max_time=120)  # Longer backoff for Gemini API
                continue
            elif attempt < max_retries:
                print(f"Gemini API error: {str(e)}. Retrying attempt {attempt}/{max_retries}...")
                sleep_with_backoff(attempt=attempt)
                continue
            else:
                print(f"Failed to use Gemini after {max_retries} attempts: {str(e)}")
                # If there's an error after all retries, fall back to the simple pattern-based check
                return is_version_affected(cve_description, package_version), f"Error with Gemini check after {max_retries} attempts: {str(e)}"
    
    # Fallback in case we somehow exit the loop
    return is_version_affected(cve_description, package_version), "Failed to get a response from Gemini"

def analyze_version_affected(cve_description: str, package_name: str, package_version: str, max_retries: int = 5) -> Tuple[bool, str, str]:
    """
    Determine if a package version is affected by a CVE using both pattern matching and LLM.
    
    Args:
        cve_description: The description of the CVE
        package_name: Name of the package
        package_version: The specific version to check
        max_retries: Maximum number of retries for LLM calls (default: 5)
        
    Returns:
        Tuple of (is_affected, explanation, confidence)
    """
    # If no version is provided, it's always considered affected
    if not package_version:
        return True, "No specific version provided to check", "HIGH"
    
    # Quick checks for obvious cases to avoid unnecessary LLM calls
    
    # Case 1: The exact version is mentioned in the description
    if package_version.lower() in cve_description.lower():
        # Only when the version appears in context that suggests it's affected
        version_indicators = [
            f"affects {package_version}",
            f"including {package_version}",
            f"version {package_version} is",
            f"{package_version} and",
            f"{package_version} is affected",
            f"{package_version} contains"
        ]
        for indicator in version_indicators:
            if indicator.lower() in cve_description.lower():
                return True, f"Version {package_version} is explicitly mentioned as affected", "HIGH"
    
    # Case 2: The description clearly indicates all versions are affected
    all_versions_patterns = [
        "all versions",
        "any version",
        "every version",
        "affects all"
    ]
    if any(p.lower() in cve_description.lower() for p in all_versions_patterns):
        return True, "All versions are indicated as affected", "HIGH"
    
    # Case 3: Check for version ranges using common patterns
    # For complex version comparisons where we need nuanced analysis, use the LLM
    if any(x in cve_description.lower() for x in [
        "prior to", "before", "versions up to", "earlier than", 
        "later than", "newer than", "between", "from version", 
        "versions from", "through", "and later", "and earlier"
    ]):
        # This description contains version ranges that require analysis
        is_affected, explanation = check_version_with_llm(
            cve_description, 
            package_name, 
            package_version,
            max_retries=max_retries
        )
        
        # Determine confidence based on the explanation
        if "YES" in explanation[:10].upper() or "NO" in explanation[:10].upper():
            confidence = "MEDIUM"  # LLM was decisive
            
            # Look for additional confidence indicators in the explanation
            if any(x in explanation.lower() for x in ["certain", "definitely", "clearly", "absolutely"]):
                confidence = "HIGH"
            elif any(x in explanation.lower() for x in ["might", "may", "possible", "could", "uncertain"]):
                confidence = "LOW"
                
        else:
            confidence = "LOW"  # LLM was uncertain
        
        return is_affected, explanation, confidence
    
    # For descriptions with minimal version information but mentions vulnerability
    # details, use simpler pattern matching
    if any(x in cve_description.lower() for x in ["vulnerability", "exploit", "attack", "security"]):
        # Use pattern matching since this might be a general vulnerability without specific version info
        pattern_result = is_version_affected(cve_description, package_version)
        return pattern_result, "Based on pattern matching for general vulnerability indicators", "LOW"
    
    # If we're not sure, be conservative and assume it could be affected
    return True, "Unable to determine version specificity, conservatively assuming affected", "LOW"

@tool
def analyze_repository_health(repo_url: str) -> Dict[str, Any]:
    """
    Analyze the health and activity of a repository based on its URL.
    
    Args:
        repo_url: URL of the repository (GitHub, GitLab, etc.)
        
    Returns:
        Dictionary with repository health analysis
    """
    if not repo_url or not isinstance(repo_url, str):
        return {
            "Error": "Invalid repository URL",
            "Details": "Repository URL is empty or not a string",
            "References": []
        }
    
    # Extract repository owner and name from URL
    repo_info = {}
    parsed_url = urlparse(repo_url)
    
    # Extract information based on platform
    if "github.com" in parsed_url.netloc:
        path_parts = parsed_url.path.strip('/').split('/')
        if len(path_parts) >= 2:
            repo_info["Platform"] = "GitHub"
            repo_info["Owner"] = path_parts[0]
            repo_info["Name"] = path_parts[1]
    elif "gitlab.com" in parsed_url.netloc:
        path_parts = parsed_url.path.strip('/').split('/')
        if len(path_parts) >= 2:
            repo_info["Platform"] = "GitLab"
            repo_info["Owner"] = path_parts[0]
            repo_info["Name"] = path_parts[1]
    else:
        repo_info["Platform"] = "Unknown"
        repo_info["URL"] = repo_url
    
    # Search for repository information
    search_queries = []
    
    if repo_info.get("Platform") == "GitHub" and repo_info.get("Owner") and repo_info.get("Name"):
        search_queries = [
            f"{repo_info['Owner']}/{repo_info['Name']} github age creation date",
            f"{repo_info['Owner']}/{repo_info['Name']} github contributors count",
            f"{repo_info['Owner']}/{repo_info['Name']} github last commit",
            f"{repo_info['Owner']}/{repo_info['Name']} github activity issues pull requests"
        ]
    else:
        search_queries = [
            f"{repo_url} creation date",
            f"{repo_url} contributors count",
            f"{repo_url} last commit",
            f"{repo_url} repository activity issues pull requests"
        ]
    
    results = {}
    references = []
    
    # Extract URLs from search results
    url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
    
    for query in search_queries:
        try:
            search_result = agent_tools.search_web(query)
            urls = re.findall(url_pattern, search_result)
            references.extend(urls[:3])  # Add up to 3 URLs per query
            # Add the specific search query to references
            references.append(f"Search results for '{query}'")
            results[query] = search_result
        except Exception as e:
            results[query] = f"Error: {str(e)}"
            # Add the failed search query to references
            references.append(f"Failed search for '{query}'")
    
    # Filter out any duplicates and empty references
    clean_references = []
    for ref in references:
        if ref and ref not in clean_references:
            clean_references.append(ref)
    
    return {
        "Repository": repo_info,
        "Search Results": results,
        "References": clean_references
    }

@tool
def search_cves_with_nvdlib(package_name: str, version: Optional[str] = None, max_retries: int = 5) -> Dict[str, Any]:
    """
    Search for CVEs directly from the National Vulnerability Database using nvdlib.
    Uses a CPE-based approach for better accuracy.
    
    Args:
        package_name: Name of the package to search for vulnerabilities
        version: Optional specific version to search for
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        Dictionary with vulnerability information from NVD
    """
    cve_list = []
    references = []
    search_results = {}
    full_cve_details = []
    
    print(f"Searching NVD for vulnerabilities in {package_name} {version if version else ''}")
    
    # Step 1: Find CPE matches for the package
    query = f"{package_name}"
    if version:
        query += f" {version}"
    
    cpe_matches = []
    references = []  # Track references specific to this function
    for attempt in range(1, max_retries + 1):
        try:
            # First try with package name and version
            cpe_results = nvdlib.searchCPE(keywordSearch=query, limit=5)
            
            if cpe_results:
                cpe_matches.extend(cpe_results)
                # Add reference with the specific query used
                references.append(f"NVD CPE search for: '{query}'")
                print(f"Found {len(cpe_results)} CPE matches for '{query}'")
            else:
                # If no results with version, try just the package name
                cpe_results = nvdlib.searchCPE(keywordSearch=package_name, limit=5)
                if cpe_results:
                    cpe_matches.extend(cpe_results)
                    # Add reference with the specific query used
                    references.append(f"NVD CPE search for: '{package_name}'")
                    print(f"Found {len(cpe_results)} CPE matches for '{package_name}'")
            
            # Break out of the retry loop if successful
            break
        except Exception as e:
            error_message = str(e).lower()
            
            # Check if error message suggests rate limiting
            rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
            is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
            
            if is_rate_limit and attempt < max_retries:
                print(f"NVD API rate limited when searching CPEs. Retrying ({attempt}/{max_retries})...")
                sleep_with_backoff(attempt=attempt)
                continue
            elif attempt < max_retries:
                print(f"NVD API error when searching CPEs: {str(e)}. Retrying ({attempt}/{max_retries})...")
                sleep_with_backoff(attempt=1)
                continue
            else:
                print(f"Failed to search CPEs after {max_retries} attempts: {str(e)}")
    
    # Step 2: If we found CPE matches, search for CVEs using each CPE
    if cpe_matches:
        for cpe in cpe_matches:
            cpe_name = cpe.cpeName
            print(f"Searching for CVEs with CPE: {cpe_name}")
            
            for attempt in range(1, max_retries + 1):
                try:
                    cve_results = nvdlib.searchCVE(cpeName=cpe_name, limit=20)
                    search_results[f"cpe_{cpe_name}"] = cve_results
                    
                    # Extract CVE information
                    for cve_item in cve_results:
                        cve_id = cve_item.id
                        
                        # Skip if we've already seen this CVE
                        if cve_id in [cve["CVE_ID"] for cve in full_cve_details]:
                            continue
                            
                        cve_list.append(cve_id)
                        
                        # Extract severity information
                        severity = "Unknown"
                        cvss_score = None
                        
                        try:
                            # Try to get CVSS v3.1 information
                            metrics = cve_item.metrics
                            if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                                cvss = metrics.cvssMetricV31[0]
                                severity = cvss.cvssData.baseSeverity
                                cvss_score = cvss.cvssData.baseScore
                            # Fall back to CVSS v3.0
                            elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
                                cvss = metrics.cvssMetricV30[0]
                                severity = cvss.cvssData.baseSeverity
                                cvss_score = cvss.cvssData.baseScore
                            # Fall back to CVSS v2
                            elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                                cvss = metrics.cvssMetricV2[0]
                                severity = cvss.baseSeverity
                                cvss_score = cvss.baseScore
                        except AttributeError:
                            # If we encounter an attribute error, use the older attribute access pattern
                            if hasattr(cve_item, 'v31severity'):
                                severity = cve_item.v31severity
                                cvss_score = cve_item.v31score
                            elif hasattr(cve_item, 'v30severity'):
                                severity = cve_item.v30severity
                                cvss_score = cve_item.v30score
                            elif hasattr(cve_item, 'v2severity'):
                                severity = cve_item.v2severity
                                cvss_score = cve_item.v2score
                        
                        # Extract references
                        cve_references = []
                        if hasattr(cve_item, 'references') and cve_item.references:
                            for ref in cve_item.references:
                                if hasattr(ref, 'url') and ref.url:
                                    cve_references.append(ref.url)
                                    references.append(ref.url)
                        
                        # Extract description
                        description = "No description available"
                        if hasattr(cve_item, 'descriptions') and cve_item.descriptions:
                            for desc in cve_item.descriptions:
                                if hasattr(desc, 'value') and desc.value and (not hasattr(desc, 'lang') or desc.lang == 'en'):
                                    description = desc.value
                                    break
                        
                        # Extract the vulnerability status
                        status = "Unknown"
                        if hasattr(cve_item, 'vulnStatus'):
                            status = cve_item.vulnStatus
                        
                        # Check if this version is affected by the vulnerability using our enhanced approach
                        version_affected, explanation, confidence = analyze_version_affected(
                            description, 
                            package_name, 
                            version,
                            max_retries=max_retries
                        )
                        
                        # Create detailed CVE entry
                        if not version or version_affected:
                            full_cve_details.append({
                                "CVE_ID": cve_id,
                                "Severity": severity,
                                "CVSS_Score": cvss_score,
                                "Details": description,
                                "References": cve_references[:5],  # Limit to 5 references
                                "Status": status,
                                "Source": "nvdlib CPE search",
                                "Version_Affected": version_affected,
                                "Version_Analysis": explanation if version else "No specific version provided",
                                "Confidence": confidence if version else "HIGH"
                            })
                    
                    # Break out of the retry loop if successful
                    break
                    
                except Exception as e:
                    # Handle API errors
                    error_message = str(e).lower()
                    
                    # Check if error message suggests rate limiting
                    rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
                    is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                    
                    if is_rate_limit and attempt < max_retries:
                        print(f"NVD API rate limited when searching CVEs by CPE. Retrying ({attempt}/{max_retries})...")
                        sleep_with_backoff(attempt=attempt)
                        continue
                    elif attempt < max_retries:
                        print(f"NVD API error when searching CVEs by CPE: {str(e)}. Retrying ({attempt}/{max_retries})...")
                        sleep_with_backoff(attempt=1)
                        continue
                    else:
                        print(f"Failed to search CVEs by CPE after {max_retries} attempts: {str(e)}")
            
            # Add a sleep between CPE searches to avoid hitting rate limits
            sleep_with_backoff(attempt=1)
    
    # Step 3: If we still don't have any CVEs, try direct keyword search as a fallback
    if not cve_list:
        print("No CVEs found using CPE search, trying direct keyword search")
        
        # Different search strategies as fallbacks
        fallback_strategies = [
            # Strategy 1: Direct product search using keyword
            {"keywordSearch": package_name},
            
            # Strategy 2: If version is provided, try keyword with version
            {"keywordSearch": f"{package_name} {version}" if version else None},
        ]
        
        # Filter out None strategies
        fallback_strategies = [s for s in fallback_strategies if not any(v is None for v in s.values())]
        
        for strategy_idx, strategy in enumerate(fallback_strategies):
            if "keywordSearch" in strategy:
                keyword = strategy["keywordSearch"]
                
                for attempt in range(1, max_retries + 1):
                    try:
                        # Use nvdlib to search for CVEs by keyword
                        print(f"Fallback Strategy {strategy_idx+1}: Searching for CVEs with keyword '{keyword}'")
                        search_results[f"keyword_{keyword}"] = nvdlib.searchCVE(
                            keywordSearch=keyword,
                            limit=20,  # Limit the number of results
                        )
                        
                        # If successful, extract CVE information
                        for cve_item in search_results[f"keyword_{keyword}"]:
                            cve_id = cve_item.id
                            
                            # Skip if we've already seen this CVE
                            if cve_id in [cve["CVE_ID"] for cve in full_cve_details]:
                                continue
                                
                            cve_list.append(cve_id)
                            
                            # Extract severity information
                            severity = "Unknown"
                            cvss_score = None
                            
                            try:
                                # Try to get CVSS v3.1 information
                                metrics = cve_item.metrics
                                if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                                    cvss = metrics.cvssMetricV31[0]
                                    severity = cvss.cvssData.baseSeverity
                                    cvss_score = cvss.cvssData.baseScore
                                # Fall back to CVSS v3.0
                                elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
                                    cvss = metrics.cvssMetricV30[0]
                                    severity = cvss.cvssData.baseSeverity
                                    cvss_score = cvss.cvssData.baseScore
                                # Fall back to CVSS v2
                                elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                                    cvss = metrics.cvssMetricV2[0]
                                    severity = cvss.baseSeverity
                                    cvss_score = cvss.baseScore
                            except AttributeError:
                                # If we encounter an attribute error, use the older attribute access pattern
                                if hasattr(cve_item, 'v31severity'):
                                    severity = cve_item.v31severity
                                    cvss_score = cve_item.v31score
                                elif hasattr(cve_item, 'v30severity'):
                                    severity = cve_item.v30severity
                                    cvss_score = cve_item.v30score
                                elif hasattr(cve_item, 'v2severity'):
                                    severity = cve_item.v2severity
                                    cvss_score = cve_item.v2score
                            
                            # Extract references
                            cve_references = []
                            if hasattr(cve_item, 'references') and cve_item.references:
                                for ref in cve_item.references:
                                    if hasattr(ref, 'url') and ref.url:
                                        cve_references.append(ref.url)
                                        references.append(ref.url)
                            
                            # Extract description
                            description = "No description available"
                            if hasattr(cve_item, 'descriptions') and cve_item.descriptions:
                                for desc in cve_item.descriptions:
                                    if hasattr(desc, 'value') and desc.value and (not hasattr(desc, 'lang') or desc.lang == 'en'):
                                        description = desc.value
                                        break
                            
                            # Extract the vulnerability status
                            status = "Unknown"
                            if hasattr(cve_item, 'vulnStatus'):
                                status = cve_item.vulnStatus
                            
                            # Check if this version is affected by the vulnerability using our enhanced approach
                            version_affected, explanation, confidence = analyze_version_affected(
                                description, 
                                package_name, 
                                version,
                                max_retries=max_retries
                            )
                            
                            # Create detailed CVE entry
                            if not version or version_affected:
                                full_cve_details.append({
                                    "CVE_ID": cve_id,
                                    "Severity": severity,
                                    "CVSS_Score": cvss_score,
                                    "Details": description,
                                    "References": cve_references[:5],  # Limit to 5 references
                                    "Status": status,
                                    "Source": "nvdlib keyword search",
                                    "Version_Affected": version_affected,
                                    "Version_Analysis": explanation if version else "No specific version provided",
                                    "Confidence": confidence if version else "HIGH"
                                })
                        
                        # Break out of the attempt loop if successful
                        break
                        
                    except Exception as e:
                        # Handle API errors
                        error_message = str(e).lower()
                        
                        # Check if error message suggests rate limiting
                        rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
                        is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                        
                        if is_rate_limit and attempt < max_retries:
                            print(f"NVD API rate limited when using keyword search. Retrying ({attempt}/{max_retries})...")
                            sleep_with_backoff(attempt=attempt, base_time=5)  # Longer base time for NVD API
                            continue
                        elif attempt < max_retries:
                            print(f"NVD API error when using keyword search: {str(e)}. Retrying ({attempt}/{max_retries})...")
                            sleep_with_backoff(attempt=1)
                            continue
                        else:
                            print(f"Failed to search NVD API by keyword after {max_retries} attempts: {str(e)}")
                            break
    
    # Add specific CPE identifiers to references
    if cpe_matches:
        for cpe in cpe_matches:
            references.append(f"CPE: {cpe.cpeName}")
    
    # Collect all unique references from both CPE searches and CVE data
    all_refs = list(set(references))
    
    return {
        "Package": package_name,
        "Version": version,
        "CVEs": cve_list,
        "CVE_Details": full_cve_details,
        "References": all_refs
    }

@tool
def search_vulnerabilities(package_name: str, version: Optional[str] = None, max_retries: int = 5) -> Dict[str, Any]:
    """
    Search for known vulnerabilities for a specific package and version.
    
    Args:
        package_name: Name of the package to search for vulnerabilities
        version: Optional specific version to search for
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        Dictionary with vulnerability information
    """
    # First, try to search for CVEs using nvdlib (direct NVD API)
    try:
        nvdlib_results = search_cves_with_nvdlib(package_name=package_name, version=version, max_retries=max_retries)
        
        # Update the CVE list to only include those that affect the specified version
        if version:
            # Filter the CVE list to only include those that were determined to affect the version
            filtered_cve_ids = [cve["CVE_ID"] for cve in nvdlib_results["CVE_Details"] if cve.get("Version_Affected", True)]
            nvdlib_results["CVEs"] = filtered_cve_ids
            
            # Add information about the filtering
            nvdlib_results["Version_Specific"] = True
            nvdlib_results["Version_Filtered_Count"] = len(filtered_cve_ids)
            nvdlib_results["Total_Found_Count"] = len([cve["CVE_ID"] for cve in nvdlib_results["CVE_Details"]])
            
            # Group CVEs by confidence level
            high_confidence_cves = []
            medium_confidence_cves = []
            low_confidence_cves = []
            
            # Add a summary of the version analysis
            version_analysis_summary = []
            for cve in nvdlib_results["CVE_Details"]:
                if cve.get("Version_Affected", True):
                    confidence = cve.get("Confidence", "LOW")
                    summary_entry = {
                        "CVE_ID": cve["CVE_ID"],
                        "Affected": True,
                        "Analysis": cve.get("Version_Analysis", "No analysis available"),
                        "Confidence": confidence,
                        "Severity": cve.get("Severity", "Unknown"),
                        "CVSS_Score": cve.get("CVSS_Score")
                    }
                    version_analysis_summary.append(summary_entry)
                    
                    # Add to the appropriate confidence group
                    if confidence == "HIGH":
                        high_confidence_cves.append(cve["CVE_ID"])
                    elif confidence == "MEDIUM":
                        medium_confidence_cves.append(cve["CVE_ID"])
                    else:  # LOW or undefined
                        low_confidence_cves.append(cve["CVE_ID"])
            
            # Add the confidence groupings to the results
            nvdlib_results["Version_Analysis_Summary"] = version_analysis_summary
            nvdlib_results["High_Confidence_CVEs"] = high_confidence_cves
            nvdlib_results["Medium_Confidence_CVEs"] = medium_confidence_cves
            nvdlib_results["Low_Confidence_CVEs"] = low_confidence_cves
            
            print(f"Found {nvdlib_results['Version_Filtered_Count']} CVEs that likely affect version {version} out of {nvdlib_results['Total_Found_Count']} total CVEs")
            print(f"  - {len(high_confidence_cves)} with HIGH confidence")
            print(f"  - {len(medium_confidence_cves)} with MEDIUM confidence")
            print(f"  - {len(low_confidence_cves)} with LOW confidence")
        
        # If we found CVEs using nvdlib, return those results
        if nvdlib_results["CVEs"]:
            if not version:
                print(f"Found {len(nvdlib_results['CVEs'])} CVEs using nvdlib")
            return nvdlib_results
        else:
            print("No CVEs found using nvdlib, falling back to web search")
    except Exception as e:
        print(f"Error searching for CVEs using nvdlib: {str(e)}")
        print("Falling back to web search for CVEs")
    
    # If nvdlib search failed or found no results, fall back to web search
    search_results = {}
    references = []
    cve_list = []
    
    # Search queries to execute
    search_queries = [
        f"{package_name} {version} CVE vulnerability",
        f"{package_name} {version} security vulnerabilities",
        f"{package_name} {version} security advisories",
        f"{package_name} security bugs issues"
    ]
    
    # Execute each search query with retry logic and progressive backoff
    for query in search_queries:
        for attempt in range(1, max_retries + 1):
            try:
                # Always add a small delay before each web search to avoid rapid-fire requests
                # This prevents hitting rate limits in the first place
                if attempt > 1:
                    sleep_with_backoff(attempt=attempt-1, base_time=3, max_time=90)
                else:
                    # Even on first attempt, add a small delay between searches
                    time.sleep(random.uniform(1.0, 2.0))
                    
                results = agent_tools.search_web(search_query=query)
                search_results[query] = results
                # Add the actual search query to references instead of generic label
                references.append(f"Search results for: '{query}'")
                
                # Always add a delay after successful search to avoid hitting rate limits on subsequent searches
                # Use progressively longer delays if we've already hit rate limits before
                sleep_with_backoff(attempt=max(1, attempt-1), base_time=3, max_time=60)
                break  # Break the retry loop on success
                
            except Exception as e:
                error_message = str(e).lower()
                rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
                
                if any(keyword in error_message for keyword in rate_limit_keywords) and attempt < max_retries:
                    print(f"Web search API rate limited. Retrying ({attempt}/{max_retries})...")
                    # Use longer backoff time for rate limits
                    sleep_with_backoff(attempt=attempt, base_time=5, max_time=120)
                    continue
                elif attempt < max_retries:
                    print(f"Web search API error: {str(e)}. Retrying ({attempt}/{max_retries})...")
                    sleep_with_backoff(attempt=attempt, base_time=3)
                    continue
                else:
                    print(f"Web search failed after {max_retries} attempts: {str(e)}")
                    search_results[query] = f"Search failed: {str(e)}"
    
    # Extract references from search results
    for query, result in search_results.items():
        if isinstance(result, str) and result.startswith("Search failed"):
            # Include the actual search query that failed instead of generic label
            references.append(f"Failed search for: '{query}'")
    
    # Extract CVEs using regex
    for _, result in search_results.items():
        if isinstance(result, str) and not result.startswith("Search failed"):
            # Find CVEs using regex
            cve_pattern = r'CVE-\d{4}-\d{4,7}'
            found_cves = re.findall(cve_pattern, result)
            cve_list.extend(found_cves)
    
    # Deduplicate CVEs
    cve_list = list(set(cve_list))
    
    return {
        "Package": package_name,
        "Version": version,
        "CVEs": cve_list,
        "Search Results": search_results,
        "References": references
    }

@tool
def get_cve_details(cve_id: str, max_retries: int = 5) -> Dict[str, Any]:
    """
    Get detailed information about a specific CVE.
    
    Args:
        cve_id: The CVE ID to look up (e.g., CVE-2021-44228)
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        Dictionary with CVE details
    """
    # First try to get CVE details directly from nvdlib (NVD API)
    try:
        print(f"Getting details for {cve_id} from NVD API...")
        for attempt in range(1, max_retries + 1):
            try:
                # Use nvdlib to get CVE details - IMPORTANT: Only pass the CVE ID, not any additional text
                # This was causing 403 errors before because the URL was malformed
                cve_results = nvdlib.searchCVE(cveId=cve_id)
                
                if cve_results and len(cve_results) > 0:
                    cve_result = cve_results[0]  # Get the first result
                    
                    # Extract severity information
                    severity = "Unknown"
                    cvss_score = None
                    
                    try:
                        # Try to get CVSS v3.1 information
                        metrics = cve_result.metrics
                        if hasattr(metrics, 'cvssMetricV31') and metrics.cvssMetricV31:
                            cvss = metrics.cvssMetricV31[0]
                            severity = cvss.cvssData.baseSeverity
                            cvss_score = cvss.cvssData.baseScore
                        # Fall back to CVSS v3.0
                        elif hasattr(metrics, 'cvssMetricV30') and metrics.cvssMetricV30:
                            cvss = metrics.cvssMetricV30[0]
                            severity = cvss.cvssData.baseSeverity
                            cvss_score = cvss.cvssData.baseScore
                        # Fall back to CVSS v2
                        elif hasattr(metrics, 'cvssMetricV2') and metrics.cvssMetricV2:
                            cvss = metrics.cvssMetricV2[0]
                            severity = cvss.baseSeverity
                            cvss_score = cvss.baseScore
                    except AttributeError:
                        # If we encounter an attribute error, use the older attribute access pattern
                        if hasattr(cve_result, 'v31severity'):
                            severity = cve_result.v31severity
                            cvss_score = cve_result.v31score
                        elif hasattr(cve_result, 'v30severity'):
                            severity = cve_result.v30severity
                            cvss_score = cve_result.v30score
                        elif hasattr(cve_result, 'v2severity'):
                            severity = cve_result.v2severity
                            cvss_score = cve_result.v2score
                    
                    # Extract references
                    references = []
                    if hasattr(cve_result, 'references') and cve_result.references:
                        for ref in cve_result.references:
                            if hasattr(ref, 'url') and ref.url:
                                references.append(ref.url)
                    
                    # Extract description
                    description = "No description available"
                    if hasattr(cve_result, 'descriptions') and cve_result.descriptions:
                        for desc in cve_result.descriptions:
                            if hasattr(desc, 'value') and desc.value and (not hasattr(desc, 'lang') or desc.lang == 'en'):
                                description = desc.value
                                break
                    
                    # Extract the vulnerability status
                    status = "Unknown"
                    if hasattr(cve_result, 'vulnStatus'):
                        status = cve_result.vulnStatus
                    
                    return {
                        "CVE_ID": cve_id,
                        "Severity": severity,
                        "CVSS_Score": cvss_score,
                        "Details": description,
                        "References": references[:5],  # Limit to 5 references
                        "Status": status,
                        "Source": "nvdlib direct API"
                    }
                break  # Break out of retry loop if successful
            except Exception as e:
                # Handle API errors
                error_message = str(e).lower()
                
                # Check if error message suggests rate limiting
                rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
                is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                
                if is_rate_limit and attempt < max_retries:
                    print(f"NVD API rate limited. Retrying ({attempt}/{max_retries})...")
                    sleep_with_backoff(attempt=attempt, base_time=5)  # Longer base time for NVD API
                    continue
                elif attempt < max_retries:
                    print(f"NVD API error when fetching {cve_id}: {str(e)}. Retrying ({attempt}/{max_retries})...")
                    sleep_with_backoff(attempt=1)
                    continue
                else:
                    print(f"Failed to get CVE details from NVD API after {max_retries} attempts: {str(e)}")
                    raise  # Re-raise to fall back to web search
    except Exception as e:
        print(f"Error getting CVE details from NVD API: {str(e)}")
        print("Falling back to web search for CVE details")
    
    # If nvdlib failed, fall back to web search
    search_query = f"{cve_id} details severity exploit"
    references = []  # Track references specific to web search
    
    for attempt in range(1, max_retries + 1):
        try:
            search_result = agent_tools.search_web(search_query)
            
            # Add the actual search query to references
            references.append(f"Web search for: '{search_query}'")
            
            # Extract URLs
            url_pattern = r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&//=]*)'
            urls = re.findall(url_pattern, search_result)
            
            # Add up to 5 URLs from the search results to references
            if urls:
                references.extend(urls[:5])
            
            # Try to extract severity information
            severity_patterns = [
                r'(Critical|High|Medium|Low)\s+[Ss]everity',
                r'[Ss]everity\s*:\s*(Critical|High|Medium|Low)',
                r'CVSS\s+[Ss]core\s*:\s*(\d+\.\d+)',
                r'(CVSS|EPSS)\s+[Ss]core\s*[v]?[234]?\s*:?\s*(\d+\.\d+)'
            ]
            
            severity = "Unknown"
            cvss_score = None
            
            for pattern in severity_patterns:
                match = re.search(pattern, search_result, re.IGNORECASE)
                if match:
                    if match.group(1).lower() in ["critical", "high", "medium", "low"]:
                        severity = match.group(1)
                        break
                    elif match.group(1) == "CVSS" or match.group(1) == "EPSS":
                        try:
                            score = float(match.group(2))
                            cvss_score = score
                            # CVSS Severity Rating Scale
                            if score >= 9.0:
                                severity = "Critical"
                            elif score >= 7.0:
                                severity = "High"
                            elif score >= 4.0:
                                severity = "Medium"
                            else:
                                severity = "Low"
                            break
                        except (IndexError, ValueError):
                            continue
            
            return {
                "CVE_ID": cve_id,
                "Severity": severity,
                "CVSS_Score": cvss_score,
                "Details": search_result,
                "References": references[:5],  # Include up to 5 references
                "Source": "web search"
            }
        except Exception as e:
            error_message = str(e).lower()
            rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
            
            if any(keyword in error_message for keyword in rate_limit_keywords) and attempt < max_retries:
                print(f"Search for CVE '{cve_id}' failed due to rate limiting. Retrying ({attempt}/{max_retries})...")
                sleep_with_backoff(attempt=attempt)
                continue
            elif attempt < max_retries:
                # If it's not a rate limit error but we still have retries
                print(f"Search for CVE '{cve_id}' failed for other reasons. Retrying ({attempt}/{max_retries})...")
                sleep_with_backoff(attempt=1)  # Use base backoff
                continue
            else:
                # If we've reached the maximum number of retries, return an error
                return {
                    "CVE_ID": cve_id,
                    "Error": f"Failed to retrieve details after {max_retries} attempts: {str(e)}",
                    "References": [],
                    "Source": "error"
                }

@tool
def calculate_risk_rating(concerns: List[str], cve_count: int, high_severity_cve_count: int, 
                         other_bugs_count: int, repo_age_months: Optional[int] = None, 
                         contributors_count: Optional[int] = None,
                         last_commit_months_ago: Optional[int] = None) -> Dict[str, Any]:
    """
    Calculate a risk rating based on security analysis.
    
    Args:
        concerns: List of concerns identified
        cve_count: Number of CVEs found
        high_severity_cve_count: Number of high severity CVEs found
        other_bugs_count: Number of other security bugs found
        repo_age_months: Age of the repository in months (optional)
        contributors_count: Number of contributors (optional)
        last_commit_months_ago: Months since last commit (optional)
        
    Returns:
        Dictionary with risk rating analysis
    """
    # Initialize risk factors
    risk_factors = {
        "Has Critical/High CVEs": high_severity_cve_count > 0,
        "Multiple CVEs": cve_count > 2,
        "Recent CVEs": False,  # Will be determined by analysis
        "Low Maintainer Activity": False,
        "Few Contributors": False,
        "Very New Repository": False,
        "Many Security Concerns": len(concerns) > 3,
        "Other Security Bugs": other_bugs_count > 0
    }
    
    # Determine maintenance factors if data is available
    if last_commit_months_ago is not None:
        risk_factors["Low Maintainer Activity"] = last_commit_months_ago > 6
    
    if contributors_count is not None:
        risk_factors["Few Contributors"] = contributors_count < 3
    
    if repo_age_months is not None:
        risk_factors["Very New Repository"] = repo_age_months < 6
    
    # Count high risk factors
    high_risk_factors = [
        "Has Critical/High CVEs",
        "Multiple CVEs",
        "Recent CVEs"
    ]
    
    medium_risk_factors = [
        "Low Maintainer Activity",
        "Few Contributors",
        "Other Security Bugs"
    ]
    
    low_risk_factors = [
        "Very New Repository",
        "Many Security Concerns"
    ]
    
    # Count active risk factors
    high_count = sum(1 for factor in high_risk_factors if risk_factors.get(factor, False))
    medium_count = sum(1 for factor in medium_risk_factors if risk_factors.get(factor, False))
    low_count = sum(1 for factor in low_risk_factors if risk_factors.get(factor, False))
    
    # Determine overall risk rating
    risk_rating = "Low"
    if high_count > 0:
        risk_rating = "High"
    elif medium_count >= 2 or (medium_count >= 1 and low_count >= 1):
        risk_rating = "Medium"
    
    # Generate explanation
    active_factors = [factor for factor, active in risk_factors.items() if active]
    
    explanation = f"The package has been rated as {risk_rating} risk based on the following factors: "
    if active_factors:
        explanation += ", ".join(active_factors) + "."
    else:
        explanation += "No significant risk factors were identified."
    
    if high_count > 0:
        explanation += " The presence of high severity vulnerabilities significantly increases risk."
    elif medium_count > 0:
        explanation += f" {medium_count} medium risk factors were identified."
    
    return {
        "Risk Rating": risk_rating,
        "Risk Factors": risk_factors,
        "Explanation": explanation
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
    required_keys = ["Potential Concerns", "CVEs", "Other Security Bugs", 
                     "Implementation Risk Rating", "Implementation Risk Rating Explanation",
                     "References"]
    
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

def security_researcher(package_info: Dict[str, Any]) -> Dict[str, Any]:
    """
    Perform security research on a package based on provided package information.
    
    Args:
        package_info: Dictionary containing package information (from package_researcher)
        
    Returns:
        Dictionary with security research results, containing:
        - Potential Concerns: List of concerns about the package 
        - CVEs: List of known vulnerabilities and their details
        - Other Security Bugs: List of other security issues
        - Implementation Risk Rating: High/Medium/Low risk assessment
        - Implementation Risk Rating Explanation: Explanation of the risk rating
        - References: List of sources used for the security research
    """
    # Check if package_info is a string (legacy compatibility)
    if isinstance(package_info, str):
        # Convert to a simple dictionary with just the name
        package_info = {"Name": package_info, "package_name": package_info, "name": package_info}
    
    # Normalize the package_info structure to ensure it has standard keys
    normalized_info = package_info.copy()
    
    # Handle variations in key names for package name
    if "Name" not in normalized_info and "name" in normalized_info:
        normalized_info["Name"] = normalized_info["name"]
    if "name" not in normalized_info and "Name" in normalized_info:
        normalized_info["name"] = normalized_info["Name"]
        
    # Handle variations in key names for package version
    version_keys = ["Latest Package Version", "Requested Package Version", "version", "Version"]
    for src_key in version_keys:
        if src_key in normalized_info and normalized_info[src_key]:
            # Ensure all version keys exist
            for dest_key in ["Latest Package Version", "Requested Package Version", "version"]:
                if dest_key not in normalized_info or not normalized_info[dest_key]:
                    normalized_info[dest_key] = normalized_info[src_key]
            break
            
    # Handle variations in key names for repository URL
    if "Link to Source Code" not in normalized_info and "repository_url" in normalized_info:
        normalized_info["Link to Source Code"] = normalized_info["repository_url"]
    if "repository_url" not in normalized_info and "Link to Source Code" in normalized_info:
        normalized_info["repository_url"] = normalized_info["Link to Source Code"]
        
    # Create an agent with the security research tools
    agent = CodeAgent(
        tools=[
            analyze_repository_health,
            search_vulnerabilities,
            get_cve_details,
            calculate_risk_rating,
            agent_tools.search_web,
            final_answer_tool
        ],
        model=agent_models.gemini_model,
        max_steps=25,
        final_answer_checks=[validate_output],
        additional_authorized_imports=["urllib.parse", "re", "json", "datetime"]
    )
    
    # Add convenience fields to help the agent
    if "Name" in normalized_info and "version" in normalized_info:
        normalized_info["package_with_version"] = f"{normalized_info['Name']} {normalized_info['version']}"
    
    # Get the current date for the agent's context
    current_date = datetime.now().strftime("%B %d, %Y")

    # Create a formatted version of the package info for the prompt
    package_info_str = json.dumps(normalized_info, indent=2)
    
    # Construct a prompt for the agent
    prompt = f"""
    I need you to perform a security analysis on the package described below. Your task is to identify potential 
    security concerns, vulnerabilities, and provide a risk assessment.
    
    IMPORTANT: Today's date is {current_date}. Use this as the reference point when evaluating repository activity, 
    vulnerability dates, patch timelines, and any other time-sensitive information.
    
    Package Information:
    {package_info_str}
    
    IMPORTANT: The package_info dictionary above contains valuable information you should use throughout your analysis.
    Specifically:
    - Extract the package name from package_info["Name"] or package_info["name"]
    - Extract the package version from package_info["Requested Package Version"], package_info["Latest Package Version"], or package_info["version"]
    - Use the repository URL from package_info["Link to Source Code"] or package_info["repository_url"] for repository health analysis
    - Consider the package maintainer/owner information from package_info["Package Owner"] or package_info["maintainers"]
    
    Follow these precise steps:
    
    1. Analyze the repository health and activity:
       a. Use the analyze_repository_health tool with the repository URL from package_info
       b. How old is the repository? (newer repositories might be less stable)
       c. How many contributors does it have? (fewer contributors might indicate less support)
       d. When was the last commit? (inactive repositories might indicate abandonment)
       e. How active is development? (low activity might indicate lack of maintenance)
    
    2. Search for known vulnerabilities:
       a. Use the search_vulnerabilities tool with the exact package name and version from package_info
       b. Look for CVEs (Common Vulnerabilities and Exposures) affecting this package/version
       c. For each CVE found, use get_cve_details to get severity, impact, and remediation if available
       d. Determine if the vulnerabilities affect the specific version mentioned
    
    3. Search for other security bugs or issues not listed as CVEs:
       a. Look for security-related issues in issue trackers
       b. Look for security-related pull requests or commits
       c. Look for mentions of security problems in documentation or discussions
    
    4. Based on your findings, determine an Implementation Risk Rating:
       a. High: Critical/high severity vulnerabilities exist, or multiple unresolved security issues
       b. Medium: Some security concerns, but limited impact or available mitigations
       c. Low: Few or no security concerns identified
    
    5. Provide an explanation for your risk rating that summarizes the key factors.
    
    6. Keep track of all sources and references you use in your research.
    
    Your final answer MUST be a dictionary containing these exact keys:
    - Potential Concerns: A list of concerns about the package (repository age, contributor count, activity, etc.)
    - CVEs: A list of known vulnerabilities with severity, description, and status (patched/unpatched)
    - Other Security Bugs: A list of other security issues not listed as CVEs
    - Implementation Risk Rating: Overall risk rating (High, Medium, or Low)
    - Implementation Risk Rating Explanation: Explanation of the risk rating based on findings
    - References: A list of URLs used as sources for the security research
    - Package_Info: The normalized package information used for this analysis
    """
    
    # Run the agent with retry logic for potential rate limit issues
    max_agent_retries = 3
    for attempt in range(1, max_agent_retries + 1):
        try:
            # Run the agent with a timeout
            result = agent.run(prompt)
            
            # Add the normalized package info to the result if it's not already there
            if isinstance(result, dict) and "Package_Info" not in result:
                result["Package_Info"] = normalized_info
                
            return result
            
        except Exception as e:
            error_message = str(e).lower()
            rate_limit_keywords = ["rate limit", "resource exhausted", "quota", "quota exceeded", "429", "too many requests", "throttl"]
            
            if any(keyword in error_message for keyword in rate_limit_keywords) and attempt < max_agent_retries:
                print(f"Rate limit encountered in agent execution. Waiting before retry {attempt}/{max_agent_retries}...")
                # Use a much longer backoff for agent retries
                sleep_with_backoff(attempt=attempt, base_time=10, max_time=300)
                continue
            elif attempt < max_agent_retries:
                print(f"Error in agent execution: {str(e)}. Retrying {attempt}/{max_agent_retries}...")
                sleep_with_backoff(attempt=attempt, base_time=5)
                continue
            else:
                print(f"Failed to complete security research after {max_agent_retries} attempts: {str(e)}")
                # Return a partial result with error information
                return {
                    "Potential Concerns": ["Analysis failed due to rate limits or other errors"],
                    "CVEs": [],
                    "Other Security Bugs": [],
                    "Implementation Risk Rating": "Unknown",
                    "Implementation Risk Rating Explanation": f"Security analysis failed due to technical errors: {str(e)}",
                    "References": [],
                    "Package_Info": normalized_info,
                    "Error": str(e)
                }


if __name__ == "__main__":
    # Example usage with output from package_researcher
    package_info = {
        "Name": "lodash",
        "Latest Package Version": "4.17.21",
        "Requested Package Version": "4.17",
        "Primary Language": "JavaScript",
        "License Type": "MIT",
        "Description": "Lodash is a JavaScript utility library that provides helpful functions for common programming tasks. It simplifies working with arrays, numbers, objects, strings, and more.",
        "Link to Source Code": "https://github.com/lodash/lodash",
        "Package Owner": "lodash",
        "References": [
            "https://www.npmjs.com/package/lodash",
            "https://github.com/lodash/lodash",
            "https://lodash.com/"
        ]
    }
    
    result = security_researcher(package_info)
    
    print("\nSecurity Research Results:")
    print("\nPotential Concerns:")
    for concern in result["Potential Concerns"]:
        print(f"- {concern}")
    
    print("\nCVEs:")
    if result["CVEs"]:
        for cve in result["CVEs"]:
            print(f"- {cve}")
    else:
        print("- None found")
    
    print("\nOther Security Bugs:")
    if result["Other Security Bugs"]:
        for bug in result["Other Security Bugs"]:
            print(f"- {bug}")
    else:
        print("- None found")
    
    print(f"\nImplementation Risk Rating: {result['Implementation Risk Rating']}")
    print(f"\nImplementation Risk Rating Explanation: {result['Implementation Risk Rating Explanation']}")
    
    if result["References"]:
        print("\nReferences:")
        for i, ref in enumerate(result["References"], 1):
            print(f"{i}. {ref}") 