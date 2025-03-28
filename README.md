# Package Evaluation System

<p align="center">
  <img src="artwork/OSSam.png" alt="OSSam Logo" width="300"/>
</p>

An AI-powered system that evaluates software packages for security, health, and compliance using specialized agents.

## Features

- Multi-agent analysis for comprehensive package evaluation
- Detailed markdown reports with security, health, and license information
- Efficient caching system for previously evaluated packages
- Optional Slack bot integration

## Installation

1. Clone the repository and install dependencies:
```bash
git clone <repository-url>
cd package-evaluation-system
pip install -r requirements.txt
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

## Usage

### Command Line

Evaluate a package:
```bash
python agent__package_evaluator.py <package_name_or_url>
```

Evaluate from cache:
```bash
python agent__package_evaluator.py
```

### Slack Bot (Optional)

Start the bot:
```bash
python slack_bot.py
```

Then in Slack:
```
@your-bot evaluate <package_name>
```

## Output

The system generates:
- JSON cache files in `cache/` directory
- Markdown reports in `markdown/` directory

Reports include:
- Package Information
- Security Assessment
- Health Metrics
- License Analysis
- Future Outlook

## Requirements

- Python 3.8+
- Required packages:
  - pydantic
  - pydantic-ai
  - python-dotenv
  - packaging
  - aiohttp
  - slack-sdk (optional)

## Disclaimer

This tool provides AI-powered guidance. Users should:
1. Verify critical information independently
2. Consult security/legal teams for important decisions
3. Use as one of many decision-making inputs

## License

MIT License - see LICENSE file for details.
