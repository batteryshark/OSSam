from google import genai
from google.genai import types
import os
from dotenv import load_dotenv

load_dotenv()
search_query = "Why is the sky blue?"
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))

# Define your tools
google_search_tool = types.Tool(google_search=types.GoogleSearch())

# Use the generate_content method with proper tool configuration
response = client.models.generate_content(
    model="gemini-2.0-flash",
    contents=f"Search the web for this information and summarize what you find: {search_query}",
    config=types.GenerateContentConfig(
        tools=[google_search_tool]
    )
)

# Extract the search results
print(f"Search results for {search_query}:")
print(response.text)