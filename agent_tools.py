import os
from typing import Dict, Any, Optional, List
import time
import random

from dotenv import load_dotenv
from smolagents import tool, DuckDuckGoSearchTool, GoogleSearchTool



load_dotenv()



@tool
def web_search(search_query: str, max_retries: int = 10) -> str:
    """Search the web for information using multiple search methods.
    
    Args:
        search_query: Search query to send for web search
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        String with search results based on the search query
    """
    for attempt in range(1, max_retries + 1):
        try:
            # Use DuckDuckGo as the primary search tool
            duck_search_tool = DuckDuckGoSearchTool()
            duck_results = duck_search_tool.run(search_query)  # Use .run() here
            return f"DuckDuckGo Search results for '{search_query}':\n\n{duck_results}"

        except Exception as duck_error:
            try:
                # Fallback to Google Search via Gemini if DuckDuckGo fails
                from google import genai
                from google.genai import types

                client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

                # Define your tools
                google_search_tool = types.Tool(google_search=types.GoogleSearch())

                # Use the generate_content method
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=f"Search the web for this information and summarize what you find: {search_query}",
                    config=types.GenerateContentConfig(
                        tools=[google_search_tool]
                    )
                )
                
                return f"Google Search results for '{search_query}':\n\n{response.text}"
            
            except Exception as google_error:
                # Check if we've reached the maximum number of retries
                if attempt < max_retries:
                    # Both searches failed, likely due to rate limiting - let's retry with backoff
                    error_message = str(duck_error).lower() + str(google_error).lower()
                    
                    # Check if error message suggests rate limiting
                    rate_limit_keywords = ["rate limit", "too many requests", "429", "quota exceeded", "throttl"]
                    is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                    
                    if is_rate_limit:
                        print(f"Search failed due to rate limiting. Retrying ({attempt}/{max_retries})...")
                        sleep_with_backoff(attempt=attempt)
                        continue
                    else:
                        # If it's not a rate limit error, increment the attempt but use a smaller backoff
                        print(f"Search failed for other reasons. Retrying ({attempt}/{max_retries})...")
                        sleep_with_backoff(attempt=1)  # Use base backoff
                        continue
                
                # If we've reached the maximum number of retries or it's not a rate limit issue,
                # report the errors
                return f"Search failed after {attempt} attempts:\n - DuckDuckGo error: {duck_error}\n - Google error: {google_error}"

@tool
def gemini_prompt_structured(prompt: str, structured_output: Dict[str, Any]) -> str:
    """Use Gemini to generate a response to a prompt.
    
    Args:
        prompt: The prompt to send to Gemini
        structured_output: The structured output to send to Gemini
    Returns:
        Response from Gemini as text
    """

    # Configure the search request
    from google import genai
    from google.genai import types
    from pydantic import BaseModel

    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    # Get the response
    try:
        response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
         )
    except Exception as e:
        return f"Error: {e}"
    
    # Extract the search results
    return response

@tool
def gemini_prompt(prompt: str) -> str:
    """Use Gemini to generate a response to a prompt.
    
    Args:
        prompt: The prompt to send to Gemini
        
    Returns:
        Response from Gemini as text
    """

    # Configure the search request
    from google import genai
    from google.genai import types

    client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

    # Get the response
    try:
        response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents=prompt,
         )
    except Exception as e:
        return f"Error: {e}"
    
    # Extract the search results
    return response


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
    
    print(f"Sleeping for {sleep_time:.2f} seconds to avoid rate limits (attempt {attempt})...")
    time.sleep(sleep_time)

@tool
def search_web(search_query: str, max_retries: int = 10) -> str:
    """Search the web for information using multiple search methods.
    
    Args:
        search_query: Search query to send for web search
        max_retries: Maximum number of retries if rate limited
        
    Returns:
        String with search results based on the search query
    """
    # Try DuckDuckGo first
    for attempt in range(1, max_retries + 1):
        try:
            # Create a new instance of DuckDuckGoSearchTool
            duck_search_tool = DuckDuckGoSearchTool()
            # Call the run method, not search
            duck_results = duck_search_tool(search_query)
            return f"Search results for '{search_query}':\n\n{duck_results}"
        except Exception as duck_error:
            # If DuckDuckGo fails, try Google Search via Gemini
            try:            
                from google import genai
                from google.genai import types

                client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

                # Define your tools
                google_search_tool = types.Tool(google_search=types.GoogleSearch())

                # Use the generate_content method
                response = client.models.generate_content(
                    model="gemini-2.0-flash",
                    contents=f"Search the web for this information and summarize what you find: {search_query}",
                    config=types.GenerateContentConfig(
                        tools=[google_search_tool]
                    )
                )
                
                # Extract the search results
                return f"Search results for '{search_query}':\n\n{response.text}"
                
            except Exception as google_error:
                # Check if we've reached the maximum number of retries
                if attempt < max_retries:
                    # Both searches failed, likely due to rate limiting - let's retry with backoff
                    error_message = str(duck_error).lower() + str(google_error).lower()
                    
                    # Check if error message suggests rate limiting
                    rate_limit_keywords = ["rate limit", "too many requests", "429", "quota exceeded", "throttl"]
                    is_rate_limit = any(keyword in error_message for keyword in rate_limit_keywords)
                    
                    if is_rate_limit:
                        print(f"Search failed due to rate limiting. Retrying ({attempt}/{max_retries})...")
                        sleep_with_backoff(attempt=attempt)
                        continue
                    else:
                        # If it's not a rate limit error, increment the attempt but use a smaller backoff
                        print(f"Search failed for other reasons. Retrying ({attempt}/{max_retries})...")
                        sleep_with_backoff(attempt=1)  # Use base backoff
                        continue
                
                # If we've reached the maximum number of retries or it's not a rate limit issue,
                # return the error message
                return f"Search failed after {attempt} attempts: DuckDuckGo error: {str(duck_error)}, Google error: {str(google_error)}"
