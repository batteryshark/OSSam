#!/usr/bin/env python3
import os
from smolagents import LiteLLMModel
from dotenv import load_dotenv

load_dotenv()

gemini_model = LiteLLMModel(
    model_id="gemini/gemini-2.0-flash",
    api_key=os.getenv("GEMINI_API_KEY")
)


gemini_model_lite = LiteLLMModel(
    model_id="gemini/gemini-2.0-flash-lite",
    api_key=os.getenv("GEMINI_API_KEY")
)

ollama_model = LiteLLMModel(
    model_id="ollama/qwen2.5-coder:32b-instruct-q8_0",
    api_key=os.getenv("OLLAMA_API_KEY"),
    num_ctx=16384
)
ollama_reasoning_model = LiteLLMModel(
    model_id="ollama/qwq:32b-fp16",
    api_key=os.getenv("OLLAMA_API_KEY"),
    num_ctx=16384
)

def get_default_model():
    """
    Initialize and return the default model to be used by our agents.
    
    Returns:
        An instance of LiteLLMModel configured with the appropriate settings.
    """
    # Check for environment variables to determine which model to use
    model_provider = os.environ.get("AGENT_MODEL_PROVIDER", "gemini")
    model_name = os.environ.get("AGENT_MODEL_NAME", "gemini-2.0-flash")
    
    # For local models using Ollama
    if model_provider.lower() == "ollama":
        from smolagents import OllamaModel
        model_name = os.environ.get("AGENT_MODEL_NAME", "codellama")
        return OllamaModel(model=model_name)
    
    # For HuggingFace models
    elif model_provider.lower() == "hf":
        from smolagents import HfApiModel
        model_name = os.environ.get("AGENT_MODEL_NAME", "Qwen/Qwen2.5-Coder-32B-Instruct")
        return HfApiModel(model_id=model_name)
    
    # Default to LiteLLM for other providers
    else:
        return LiteLLMModel(model=model_name)

# Additional model configuration functions can be added here
def get_code_agent_model():
    """
    Get a model specifically configured for code-related tasks.
    This may use a different model or configuration than the default.
    
    Returns:
        An LLM model instance optimized for code tasks.
    """
    # This could use a different model than the default
    # For now, we'll just use the default model
    return get_default_model()

def get_security_agent_model():
    """
    Get a model specifically configured for security analysis tasks.
    
    Returns:
        An LLM model instance optimized for security analysis.
    """
    # Could be customized for security-specific tasks
    return get_default_model()

def get_license_agent_model():
    """
    Get a model specifically configured for license analysis tasks.
    
    Returns:
        An LLM model instance optimized for license analysis.
    """
    # Could be customized for license-specific tasks
    return get_default_model()
