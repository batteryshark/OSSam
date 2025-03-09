import os
import yaml

from typing import Dict, Any, Optional, List
from smolagents import CodeAgent, tool, FinalAnswerTool, LiteLLMModel

import agent_models
import agent_tools

from dotenv import load_dotenv
load_dotenv()





@tool
def lookup_license_information(name: str, references: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Look up license information from the license guidance database.
    
    Args:
        name: The type of license to evaluate
        references: Optional list of URLs or sources where license information was found
        
    Returns:
        Dictionary with license evaluation results
    """
    # Short circuit if the license type is "Unknown"
    if name == "Unknown":
        return {
            "Name": "Unknown",
            "Status": "Requires Legal Approval",
            "Notes": "The license type was unable to be determined, please review the license information manually and seek legal approval if necessary.",
            "References": references or []
        }
    
    # Load license data
    license_data = yaml.safe_load(open("license_data.yaml", 'r'))
    
    # Check if the license type is in the license data
    if name in license_data:
        result = license_data[name]
        # Include references if provided
        result["References"] = references or []
        return result
    
    # If not found directly, try normalizing the license name
    try:
        # Inline normalization logic
        known_licenses = list(license_data.keys())
        
        normalization_prompt = f"""
        I need to normalize a software license name by matching it to one in a list of known licenses.

        ### Instructions:
        - Compare the **Original license name** to the **Known licenses in database**.
        - Identify if the original license is a **variant, alternative spelling, or commonly used abbreviation** of a known license.
        - Examples of valid matches:
        - "Apache License 2.0" → "Apache 2.0"
        - "MIT License" → "MIT"
        - "GNU General Public License v3.0" → "GPL-3.0"
        - Consider **case insensitivity, extra words (like 'License'), and common variations**.
        - If a match is found, return **only** the normalized license name.
        - If there is no match, return **exactly**: `No Match`.

        ### Data:
        - **Original license name:** {name}
        - **Known licenses in database:** {', '.join(known_licenses)}

        Return only the matched normalized license name or "No Match".
        """
        
        model = LiteLLMModel(
        model_id="gemini/gemini-2.0-flash-lite",
        api_key=os.getenv("GEMINI_API_KEY")
        )
        messages = [
            {"role": "user", "content": [{"type": "text", "text": normalization_prompt}]}
        ]
        normalized_name = model(messages,temperature=0.0).content.strip()
        
        # Check if the normalized name is in the database
        if normalized_name != "No Match" and normalized_name in license_data:
            result = license_data[normalized_name].copy()
            # Include references if provided
            result["References"] = references or []
            # Keep the original name for clarity, but add a note about normalization
            result["Name"] = name
            result["Notes"] = f"{result['Notes']} (Normalized from '{name}' to '{normalized_name}')"
            return result
    except Exception as e:
        print(f"Error during license normalization: {e}")
    
    # If license is not in database, return appropriate message
    return {
        "Name": name,
        "Status": "Requires Legal Approval",
        "Notes": "This license type is not in the common license list and requires legal review.",
        "References": references or []
    }

def validate_output(final_answer, memory):  
    """Validator function for the agent."""
    expected_keys = {"Name", "Status", "Notes", "References"}
    if not isinstance(final_answer, dict) or not all(key in final_answer for key in expected_keys):
        return False, "Invalid output format. Must include Name, Status, Notes, and References."

    license_data = yaml.safe_load(open("license_data.yaml", 'r'))
    
    # For unknown license
    if final_answer["Name"] == "Unknown" and (
        final_answer["Status"] != "Requires Legal Approval" or
        final_answer["Notes"] != "The license type was unable to be determined, please review the license information manually and seek legal approval if necessary."
    ):
        return False, "Invalid format for Unknown license type."
    
    # For licenses not in the database
    if final_answer["Name"] not in license_data and final_answer["Status"] != "Requires Legal Approval":
        return False, "License type not found in common license data and status is not 'Requires Legal Approval'"
    
    # TODO: Additional verification step to ensure that the license defined here is correct at least according to a web search. It's possible that the data we got is wrong.

    return True, ""

def license_researcher(text_information: str) -> Dict[str, Any]:
    """
    Evaluate a software license based on the provided information.
    
    Args:
        text_information: Textual information about the software package
        
    Returns:
        Dictionary with license evaluation results, containing:
        - Name: Identified license name or "Unknown" if not determinable
        - Status: Approval status (Allowed, See Notes, Requires Legal Approval, Not Allowed)
        - Notes: Any specific guidance from legal about this license
        - References: List of URLs or sources where license information was found
    """

    # Create an agent with the evaluation tools
    final_answer_tool = FinalAnswerTool()
    agent = CodeAgent(
        tools=[
            lookup_license_information,
            agent_tools.search_web,
            final_answer_tool
        ],
        model=agent_models.gemini_model,
        max_steps=20,
        final_answer_checks=[validate_output],
        additional_authorized_imports=["google.genai", "yaml", "urllib.parse"]
    )
    
    # Construct a prompt for the agent based on the detailed flow
    prompt = f"""
    I need you to evaluate the software license information provided below. Your task is to identify the license type 
    and provide license guidance according to our database. Assume that the version of the software is the latest 
    version if not specified.
    
    Package Information:
    {text_information}
    
    Follow these precise steps:
    
    1. Try to find the license type in the given text first.
       a. If you can't find it, use the search_web tool to search for package license information based on the given text, any URLs in the text, package version, etc.
       b. If you STILL can't find it, return "Unknown" for the license name and use the lookup_license_information tool with "Unknown" as the license name.
    
    2. If the license type is found, use the lookup_license_information tool to check if it exists in our license guidance database, use the information returned as your final answer.
    
    Your final answer MUST be a dictionary containing these exact keys:
    - Name: The license name (found, normalized, or "Unknown")
    - Status: The approval status from the license database or "Requires Legal Approval" if not in database
    - Notes: Guidance notes from the license database or appropriate message if not in database
    - References: List of URLs or sources where license information was found
    """
    
    return agent.run(prompt)


if __name__ == "__main__":
    # Example usage
    test_info = """
    Package: TensorFlow
    Repository: https://github.com/tensorflow/tensorflow
    The TensorFlow library is licensed under the Apache License 2.0.
    It's an open-source machine learning framework developed by Google.
    """
    
    # test_info = "https://huggingface.co/deepseek-ai/DeepSeek-R1"
    
    test_info = "openssl 0.9.8"
    #test_info = "handlebars.js"
    #test_info = "Hashicorp Vault"
    #test_info = "GraalVM"
    #test_info = "https://github.com/oracle/graal GraalVM https://github.com/oracle/graal?tab=License-1-ov-file#readme"
    result = license_researcher(test_info)
    print("\nLicense Evaluation Results:")
    print(result)
    print(f"License Type: {result['Name']}")
    print(f"Decision: {result['Status']}")
    print(f"Legal Notes: {result['Notes']}")
    
    # Print references if they exist
    if "References" in result:
        print("\nReferences:")
        for ref in result["References"]:
            print(f"- {ref}") 


