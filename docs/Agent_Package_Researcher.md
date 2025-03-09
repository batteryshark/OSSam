# Agent Design for Package Researcher

## Description
The Package Researcher is an AI agent that gathers and analyzes information about third-party software packages. It uses web search capabilities to find relevant details such as version information, programming language, license type, and source code location. This agent helps developers and project managers make informed decisions about incorporating third-party software into their projects by providing comprehensive information about these packages.

## Input
The agent takes a block of textual information as input. This can include:
- Package name
- Optional version requirements
- Any additional context about the package
- Optional URLs or references to the package

The input only needs to mention the package name - the agent will research all other details.

## Output
The agent produces a structured output containing comprehensive package information:

* **Name**: The identified name of the package.
* **Latest Package Version**: The most current version of the package available online, or "Latest" if no specific version is found.
* **Requested Package Version**: The specific version requested by the user, or the value of "Latest Package Version" if not specified.
* **Primary Language**: The main programming language of the package, or "N/A" if not identifiable.
* **License Type**: The software license under which the package is distributed, or "Not Found" if unavailable.
* **Description**: A high-level summary of the package's purpose, functionality, and common use cases.
* **Link to Source Code**: URL to the package's source code repository (GitHub, GitLab, SourceForge, HuggingFace, etc.).
* **Owner/Maintainer**: Information about who owns or maintains the package.
* **URLs**: Collection of relevant URLs found during research, categorized by type.

## Tools

* **Web Search** - Utilizes the smolagents web search module to find package information. It creates search queries based on the package name to locate details about versions, licenses, languages, and repositories.

* **Package Information Extraction** - Analyzes text to extract URLs, version information, and repository links. It categorizes URLs into repository, documentation, and package manager types.

* **Version Finder** - Searches multiple package repositories and registries to identify the latest version of a package. It uses sophisticated pattern matching to extract version numbers from search results.

* **Owner/Maintainer Lookup** - Identifies the individuals, organizations, or companies responsible for developing and maintaining the package. This helps establish the credibility and support availability for the package. 