# Agent Design for License Researcher

## Description
The License Researcher is an AI agent that evaluates third-party software packages to determine if their licenses comply with organizational policies. It analyzes provided information about a software package, identifies the license type, and compares it against an approved list of licenses established by the legal department. This agent helps developers and project managers make informed decisions about incorporating third-party software into their projects while maintaining license compliance.

## Input
The agent takes a block of textual information as input. This can include:
- Package name and version
- Repository URLs
- Any extracted license information from documentation
- Other relevant details about the software package

The input doesn't need to explicitly identify the license - the agent will attempt to extract or research this information.

## Output
The agent produces a structured output containing several sections pertaining to license information:

* **Name**: The identified type of license or "Unknown" if not able to be determined.
* **Status**: The decision based on given information from legal:
    - **Allowed**: The license is universally permissible by legal and does not require additional approval.
    - **See Notes**: The license in many cases is permissible, but legal has included additional notes and considerations for additional clarity.
    - **Requires Legal Approval**: The license is undetermined or otherwise questionable in certain cases. Engage legal with this information and request approval.
    - **Not Allowed**: In almost all cases, this license is not allowed for commercial use. While legal can still be engaged, it is highly unlikely that approval or an exception will be given.
* **Notes**: Any specific guidance legal wants to give about this license type, including special considerations or limitations.
* **References**: URLs or sources where license information was found during research.

## Tools

* **Web Search** - Utilizes the smolagents web search module to find license information when it's not present in the initial input. It creates search queries based on the package information to locate the appropriate license details.

* **License Information Lookup** - Evaluates a license against a set of information provided by the legal department. It queries a database of known licenses and their statuses, normalizing license names when needed to match common variants or alternative spellings. If the requested license is not listed, the function defaults to "Requires Legal Approval".

* **License Normalization** - When a license doesn't directly match known licenses in the database, the agent attempts to normalize the license name by identifying variants, alternative spellings, or common abbreviations that match approved licenses.

* **Output Validation** - Ensures that the final response meets the expected format and contains valid information based on the license database and organizational policies. 