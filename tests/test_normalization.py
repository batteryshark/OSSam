import yaml
from typing import Dict, Any, Optional, List
from smolagents.models import LiteLLMModel
import os
from dotenv import load_dotenv

load_dotenv()

# Load license data
license_data = yaml.safe_load(open("license_data.yaml", 'r'))

def normalize_license_name(name: str, references: Optional[List[str]] = None) -> Dict[str, Any]:

    # Check if the license type is in the license data
    if name in license_data:
        result = license_data[name]
        # Include references if provided
        result["References"] = references or []
        return result

    # If not found directly, try normalizing the license name

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

    Return ONLY the matched normalized license name or "No Match".
    """
    
    # Using ollama model for license normalization
    model = LiteLLMModel(
    model_id="gemini/gemini-2.0-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY")
)
    messages = [
        {"role": "user", "content": [{"type": "text", "text": normalization_prompt}]}
    ]
    normalized_name = model(messages,temperature=0.0).content.strip()
    return normalized_name

name = "MIT License"
references = ["https://opensource.org/licenses/MIT"]
normalized_name = normalize_license_name(name, references)
print(normalized_name)