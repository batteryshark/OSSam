# PydanticAI MCP Server Example
import asyncio
from mcp.server.fastmcp import FastMCP
import sys 
import os 
from dotenv import load_dotenv
load_dotenv()

# Installation required: pip install "pydantic-ai-slim[mcp]"
# MCP integration requires Python 3.10 or higher.
MCP_SERVER_NAME = os.getenv("MCP_SERVER_NAME", "thirdparty-package-evaluator")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = os.getenv("MCP_PORT", 3899)

# Create MCP Server Instance
server = FastMCP(name=MCP_SERVER_NAME, host=MCP_HOST, port=MCP_PORT)
from agent__package_evaluator import evaluate_package_team

@server.tool()
async def thirdparty_package_assessment(package_name: str) -> str:
    """
    Assess the quality of a third-party package.

    Args:
        package_name: The name of the package to assess with an optional version number or 'latest'.
    Returns:
        A string containing a markdown formatted report of the package assessment.
    """
    try:
        print(f"MCP Tool 'thirdparty_package_assessment' called with: package_name={package_name}")
        evaluation_results, evaluation_markdown = await evaluate_package_team(package_name)
        return evaluation_markdown
    except Exception as e:
        error_msg = f"Error assessing package '{package_name}': {str(e)}"
        print(error_msg)
        return f"# Package Assessment Error\n\n{error_msg}"

@server.tool()
async def thirdparty_package_summary(package_name: str) -> str:
    """
    Get a quick summary assessment of a third-party package.

    Args:
        package_name: The name of the package to assess with an optional version number or 'latest'.
    Returns:
        A brief summary of the package assessment including guidance and key concerns.
    """
    try:
        print(f"MCP Tool 'thirdparty_package_summary' called with: package_name={package_name}")
        evaluation_results, evaluation_markdown = await evaluate_package_team(package_name)
        
        # Extract key information for summary
        guidance = evaluation_results.get('guidance', 'Unknown')
        explanation = evaluation_results.get('explanation', 'No explanation available')
        package_info = evaluation_results.get('package_info', {})
        health_info = evaluation_results.get('health_info', {})
        
        # Get health score
        health_score = health_info.get('overall_assessment', {}).get('health_score', 'Unknown')
        
        summary = f"""**Package**: {package_info.get('Name', 'Unknown')} v{package_info.get('Requested_Package_Version', 'Unknown')}
**Guidance**: {guidance}
**Health Score**: {health_score}/100
**Assessment**: {explanation}"""
        
        return summary
    except Exception as e:
        error_msg = f"Error getting package summary for '{package_name}': {str(e)}"
        print(error_msg)
        return error_msg

# Start the server
if __name__ == "__main__":
    try:
        server.run(transport="sse")
    except KeyboardInterrupt:
        print("Server stopped by user")
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)
