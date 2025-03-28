import requests
import json
import os
from dotenv import load_dotenv
from typing import Optional, Dict, Any
from pydantic import BaseModel
load_dotenv()
AGENT_TOOLKIT_BASE_URL = os.getenv("AGENT_TOOLKIT_BASE_URL")
API_KEY = os.getenv("API_KEY")
class ScraperResponse(BaseModel):
    """Response model for URL scraping."""
    status: str
    content: Optional[str] = None
    error: Optional[str] = None

def scrape_url(url: str, render_js: bool = False) -> ScraperResponse:
    headers = {"X-API-Key": API_KEY}
    data = {
        "url": url,
        "render_js": render_js
    }
    try:
        response = requests.post(f"{AGENT_TOOLKIT_BASE_URL}/scrape_url", json=data, headers=headers)
        if response.status_code == 200:
            return ScraperResponse(**response.json())
        else:
            return ScraperResponse(
                status="error",
                error=f"Server error: {response.status_code} {response.text}"
            )
    except Exception as e:
        return ScraperResponse(
            status="error",
            error=f"Request failed: {str(e)}"
        )
    
class WebSearchReference(BaseModel):
    """Model for a single web search reference."""
    content: str
    url: str
    title: str
    confidence: Optional[float] = None

class WebSearchResponse(BaseModel):
    """Response model for web search."""
    status: str
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

def search_web(query: str) -> WebSearchResponse:
    headers = {"X-API-Key": API_KEY}
    data = {"query": query}
    
    try:
        response = requests.post(f"{AGENT_TOOLKIT_BASE_URL}/search_web", json=data, headers=headers)
        if response.status_code == 200:
            return WebSearchResponse(**response.json())
        else:
            return WebSearchResponse(
                status="error",
                error=f"Server error: {response.status_code} {response.text}"
            )
    except Exception as e:
        return WebSearchResponse(
            status="error",
            error=f"Request failed: {str(e)}"
        )    
    
if __name__ == "__main__":
    print(scrape_url("https://www.google.com"))
    print(search_web("What is the capital of France?"))