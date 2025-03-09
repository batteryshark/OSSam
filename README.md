# OSSam - Open Source Software Assessment and Management Tool

<p align="center">
  <img src="artwork/OSSam.png" alt="OSSam Logo" width="300"/>
</p>

OSSam is a comprehensive toolkit for analyzing open-source software packages for both general information and security concerns. It helps developers, security researchers, and organizations make informed decisions about the open-source packages they want to incorporate into their projects.

## Features

OSSam provides the following components that work together to deliver a complete package analysis:

1. **Package Researcher** - Gathers and analyzes information about third-party software packages, including:
   - Name, version, and maintainer
   - License type
   - Primary programming language
   - Description and purpose
   - Repository information
   - Documentation links

2. **Security Researcher** - Evaluates the security posture of third-party software packages, including:
   - Repository health metrics (age, contributor count, activity)
   - Known vulnerabilities (CVEs) with severity ratings
   - Other security issues not formally recorded as CVEs
   - Risk rating (Low, Medium, High, Critical)
   - Security recommendations and concerns
   - Repository health assessment

3. **License Researcher** - Evaluates third-party software packages to determine if their licenses comply with organizational policies, providing:
   - **Name**: The identified type of license or "Unknown" if not determinable
   - **Status**: The approval status (Allowed, See Notes, Requires Legal Approval, Not Allowed)
   - **Notes**: Specific guidance about this license type
   - **References**: URLs and sources where license information was found

4. **Package Evaluator** - Coordinates the entire team of specialized agents and provides a comprehensive assessment:
   - **Verdict**: Overall recommendation based on security and license evaluations
   - **Explanation**: Comprehensive explanation of why the package is or isn't advisable to use
   - **Recommendations**: Actionable advice for mitigating identified risks
   - Orchestrates the analysis workflow between all specialized agents

5. **Markdown Report Generator** - Creates beautifully formatted reports with:
   - Professional emojis indicating status (✅ ⚠️ ❌ ❓)
   - Clearly separated sections for package info, license evaluation, and security analysis
   - Formatted blockquotes and lists for better readability
   - Collated references from all sources in one convenient section
   - Designed for easy sharing via chat, email, or documentation

## How It Works

### Package Evaluator Implementation

The Package Evaluator uses a dual approach for maximum reliability:

1. **Direct Approach (Primary)**: The evaluator calls each component agent directly in sequence:
   - First calls `package_researcher` to gather basic package information
   - Then calls `license_researcher` to evaluate license compliance
   - Next calls `security_researcher` to assess vulnerabilities
   - Finally synthesizes all the gathered data to determine the final verdict

2. **Managed Agent Approach (Fallback)**: If the direct approach fails, the evaluator falls back to a multi-agent system:
   - Creates specialized agents for package research, license research, and security research
   - Uses a manager agent to coordinate communication between these specialized agents
   - Each agent has access to web search capabilities to supplement analysis
   - The manager makes the final determination based on all inputs

This dual approach ensures the most reliable results possible, with the direct approach providing faster, more predictable results, and the managed agent approach offering flexibility when dealing with more complex packages or when rate limits or other issues arise.

## Architecture

OSSam uses a multi-agent orchestration system where a manager agent (Package Evaluator) coordinates with specialized agents:

```
                +--------------------+
                | Package Evaluator  |
                | (Manager Agent)    |
                +--------------------+
                          |
        ___________________|____________________
       |                   |                    |
+---------------+ +-------------------+ +------------------+
| Package       | | License           | | Security         |
| Researcher    | | Researcher        | | Researcher       |
+---------------+ +-------------------+ +------------------+
```

This architecture allows each component to focus on its specific area of expertise while the manager agent integrates the results into a comprehensive evaluation.

## Installation

### Prerequisites

- Python 3.7 or higher
- Internet connection for accessing online resources

### Setup

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/ossam.git
   cd ossam
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

The main script `analyze_package.py` provides a unified interface for package analysis:

```
python analyze_package.py "package_name" [options]
```

#### Options:

- `-o, --output FILENAME`: Write results to a file
- `-f, --format FORMAT`: Output format (console, json, or markdown)

### Examples

1. Analyze the Lodash package with console output:
   ```
   python analyze_package.py "lodash"
   ```

2. Analyze Express.js and save results to a JSON file:
   ```
   python analyze_package.py "express" -o express_analysis.json -f json
   ```

3. Analyze a package with a specific version:
   ```
   python analyze_package.py "lodash 4.17.20"
   ```

4. Generate a markdown report for easier sharing:
   ```
   python analyze_package.py "lodash" -f markdown -o lodash_report.md
   ```

## Individual Components

### Package Researcher

You can use the package researcher independently:

```python
from package_researcher import package_researcher

# Analyze a package
results = package_researcher("lodash")
print(results)
```

### Security Researcher

The security researcher can be used independently with package information:

```python
from package_researcher import package_researcher
from security_researcher import security_researcher

# First get package info
package_info = package_researcher("lodash")

# Then perform security analysis
security_results = security_researcher(package_info)
print(security_results)
```

### License Researcher

The License Researcher can be used independently to evaluate license compliance:

```python
from license_researcher import license_researcher

# Example text information about a package
text_info = """
Package: TensorFlow
Repository: https://github.com/tensorflow/tensorflow
The TensorFlow library is licensed under the Apache License 2.0.
It's an open-source machine learning framework developed by Google.
"""

# Evaluate the license
result = license_researcher(text_info)

# Print the results
print(f"License Type: {result['Name']}")
print(f"Status: {result['Status']}")
print(f"Notes: {result['Notes']}")
print(f"References: {result['References']}")
```

### Package Evaluator

The Package Evaluator serves as a manager agent that coordinates the other specialized agents:

```python
from package_evaluator import package_evaluator

# Evaluate a package
result = package_evaluator("lodash")

# Print the results
print(f"Verdict: {result['Verdict']}")
print(f"Explanation: {result['Explanation']}")
```

## Output Structure

### Package Research Output

```json
{
  "Name": "package_name",
  "Latest Package Version": "x.y.z",
  "Requested Package Version": "x.y.z",
  "Primary Language": "language",
  "License Type": "license",
  "Owner/Maintainer": "owner",
  "Description": "description",
  "Link to Source Code": "url",
  "URLs": {
    "Repository URLs": ["url1", "url2"],
    "Documentation URLs": ["url3", "url4"],
    "Package Manager URLs": ["url5", "url6"]
  },
  "References": [
    "url1",
    "url2"
  ]
}
```

### Security Research Output

```json
{
  "Security Assessment": "Assessment summary",
  "Risk Rating": "Low/Medium/High/Critical",
  "Known Vulnerabilities": [
    {
      "CVE ID": "CVE-YYYY-XXXXX",
      "Severity": "HIGH/MEDIUM/LOW",
      "Description": "description",
      "Status": "Fixed in version x.y.z"
    }
  ],
  "Repository Health": {
    "Project Age": "X years",
    "Update Frequency": "description",
    "Contributors": "number",
    "Issue Responsiveness": "description"
  },
  "Identified Concerns": [
    "concern1",
    "concern2"
  ],
  "Recommendations": [
    "recommendation1",
    "recommendation2"
  ],
  "References": [
    "url1",
    "url2"
  ]
}
```

### License Researcher Output

```json
{
  "Name": "License Name",
  "Status": "Allowed/See Notes/Requires Legal Approval/Not Allowed",
  "Notes": "Specific guidance about this license type",
  "References": [
    "url1",
    "url2"
  ]
}
```

### Package Evaluator Output

```json
{
  "Verdict": "Generally Safe/Use with Caution/Do not Use/Seek Clarification",
  "Explanation": "Comprehensive explanation of the recommendation",
  "PackageInfo": { /* Package Researcher Output */ },
  "SecurityInfo": { /* Security Researcher Output */ },
  "LicenseInfo": { /* License Researcher Output */ },
  "Report": "Markdown formatted report with emojis and structured sections"
}
```

### Markdown Report Example

```markdown
# OSS Assessment Report: E2B Secure Open Source Cloud Runtime current

*Generated on: 2025-03-08 18:02:21*


## 📦 Package Information

- **Name:** E2B Secure Open Source Cloud Runtime
- **Requested Version:** current
- **Latest Version:** 1.0.4
- **Primary Language:** TypeScript, Python, JavaScript, Go
- **Description:** E2B is an open-source infrastructure that allows you to run AI-generated code in secure, isolated cloud sandboxes. It provides a secure runtime environment for AI applications and agents, allowing them to use the same tools as humans in a secure cloud environment.
- **Repository:** [https://github.com/e2b-dev/e2b](https://github.com/e2b-dev/e2b)
- **Maintained By:** e2b-dev

## 🗒️ Package Evaluation

- **Advisory:** ❗ Use with Caution
- **Explanation:** This package can be used with caution, but be aware of the following risks: Contains known vulnerabilities that may need mitigation, Has medium security risk that requires attention, Has reported security issues that need to be addressed and Using an older version (current) instead of the latest (1.0.4). The implementation risk rating is Medium due to the presence of a high severity CVE (CVE-2023-6932) and potential security vulnerabilities associated with LLM-integrated frameworks, such as RCE, untrusted code execution, and prompt injection attacks. While E2B focuses on providing secure code execution environments, these vulnerabilities and issues need to be carefully considered and mitigated. The repository's relatively young age and the lack of an explicitly stated number of contributors also contribute to the Medium risk rating. License (MIT) is permitted for use.

## 📜 License Evaluation

- **License:** MIT
- **Status:** ✅ Allowed
- **Notes:** The MIT License is permissive and business-friendly. It allows for commercial use, modification, distribution, and private use, with minimal restrictions.

## 🔒 Security Evaluation

- **Security Risk:** ⚠️ Medium
- **Risk Assessment:** The implementation risk rating is Medium due to the presence of a high severity CVE (CVE-2023-6932) and potential security vulnerabilities associated with LLM-integrated frameworks, such as RCE, untrusted code execution, and prompt injection attacks. While E2B focuses on providing secure code execution environments, these vulnerabilities and issues need to be carefully considered and mitigated. The repository's relatively young age and the lack of an explicitly stated number of contributors also contribute to the Medium risk rating.

### Known Vulnerabilities:

**❓ CVE-2023-6932 (HIGH)**
- Use-after-free vulnerability in the Linux kernel's ipv4: igmp component, which can be exploited for local privilege escalation.
- Status: ❌ Modified


### Other Security Concerns:

- Potential RCE vulnerabilities associated with LLM-integrated frameworks
- Risk of untrusted code execution
- Risk of prompt injection attacks

### Repository Health:

- Relatively young repository (1 year and 10 months to 2 years old)
- Exact number of contributors is not explicitly stated
- Potential RCE vulnerabilities associated with LLM-integrated frameworks
- Risk of untrusted code execution and prompt injection attacks
- Common bugs and issues, including timeout errors and sandbox creation failures

## 📚 References

1. https://github.com/e2b-dev/e2b
2. https://security@langchain.dev
3. https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit?id=e2b706c691905fe78468c361aaabc719d0a496f1
4. https://kernel.dance/e2b706c691905fe78468c361aaabc719d0a496f1
5. https://lists.debian.org/debian-lts-announce/2024/01/msg00004.html
6. https://lists.debian.org/debian-lts-announce/2024/01/msg00005.html
7. http://packetstormsecurity.com/files/177029/Kernel-Live-Patch-Security-Notice-LSN-0100-1.html
```

## License Statuses

- **Allowed**: The license is universally permissible and does not require additional approval
- **See Notes**: The license is generally permissible, but with additional notes and considerations
- **Requires Legal Approval**: The license is undetermined or questionable in certain cases
- **Not Allowed**: In almost all cases, this license is not allowed for commercial use

## Package Verdict Categories

- **Generally Safe**: The package has minimal security concerns, a permissible license, and appears safe to use
- **Use with Caution**: The package may have some security concerns or license stipulations requiring attention
- **Do not Use**: The package has serious security vulnerabilities or licensing issues that make it inadvisable to use
- **Seek Clarification**: More information is needed to make a determination about using this package

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Acknowledgments

- National Vulnerability Database (NVD) for providing vulnerability data
- Open source community for their invaluable resources and tools 