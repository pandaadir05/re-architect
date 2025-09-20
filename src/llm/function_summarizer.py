"""
Function summarizer module for RE-Architect.

This module uses LLM-based techniques to generate human-readable summaries of decompiled functions.
"""

import logging
import json
import os
import time
from typing import Dict, List, Optional, Any
import requests

from src.core.config import Config

logger = logging.getLogger("re-architect.llm.summarizer")

class FunctionSummarizer:
    """
    Function summarizer for RE-Architect.
    
    This class uses language models to generate human-readable summaries of decompiled functions.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the function summarizer.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.provider = config.get("llm.provider", "openai")
        self.model = config.get("llm.model", "gpt-4")
        self.api_key = config.get("llm.api_key")
        self.max_tokens = config.get("llm.max_tokens", 8192)
        self.temperature = config.get("llm.temperature", 0.2)
        
        # Create a cache directory if it doesn't exist
        self.cache_dir = config.get("llm.cache_dir", "./cache/llm")
        os.makedirs(self.cache_dir, exist_ok=True)
        
    def summarize_function(self, function_code: str) -> str:
        """
        Legacy method for test compatibility. Summarize a function's code.
        
        Args:
            function_code: The function code to summarize
            
        Returns:
            A summary of the function's behavior
        """
        # This is a simplified version for testing
        return f"This function contains {len(function_code.splitlines())} lines of code."
    
    def summarize(self, function_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a summary for a function.
        
        Args:
            function_info: Dictionary containing function information
            
        Returns:
            Dictionary containing the summary and related information
            
        Raises:
            RuntimeError: If summarization fails
        """
        # Check if we already have a cached summary
        cache_key = f"{function_info['name']}_{hash(function_info['code'])}"
        cache_path = os.path.join(self.cache_dir, f"{cache_key}.json")
        
        if os.path.exists(cache_path):
            logger.debug(f"Using cached summary for {function_info['name']}")
            try:
                with open(cache_path, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                logger.warning(f"Error loading cached summary: {e}")
                # Continue to generate a new summary
        
        logger.info(f"Generating summary for function: {function_info['name']}")
        
        # Prepare the prompt
        prompt = self._create_prompt(function_info)
        
        try:
            # Generate summary using the appropriate provider
            if self.provider == "openai":
                summary_result = self._summarize_openai(prompt)
            elif self.provider == "anthropic":
                summary_result = self._summarize_anthropic(prompt)
            elif self.provider == "local":
                summary_result = self._summarize_local(prompt)
            else:
                raise RuntimeError(f"Unsupported LLM provider: {self.provider}")
            
            # Cache the result
            with open(cache_path, "w") as f:
                json.dump(summary_result, f)
            
            return summary_result
            
        except Exception as e:
            logger.error(f"Error summarizing function {function_info['name']}: {e}")
            return {
                "summary": f"Error generating summary: {str(e)}",
                "purpose": "Unknown (error during analysis)",
                "arguments": [],
                "return_value": "Unknown",
                "error": str(e)
            }
    
    def _create_prompt(self, function_info: Dict[str, Any]) -> str:
        """
        Create a prompt for the language model.
        
        Args:
            function_info: Dictionary containing function information
            
        Returns:
            Prompt string
        """
        code = function_info["code"]
        name = function_info["name"]
        signature = function_info.get("signature", "unknown")
        
        parameters = function_info.get("parameters", [])
        param_str = "\n".join([
            f"- {p.get('name', 'unknown')}: {p.get('dataType', 'unknown')}"
            for p in parameters
        ])
        
        if not param_str:
            param_str = "None"
        
        calls = function_info.get("calls", [])
        calls_str = "\n".join([
            f"- {c.get('toFunction', 'unknown')}"
            for c in calls
        ])
        
        if not calls_str:
            calls_str = "None"
        
        prompt = f"""
Please analyze this decompiled function and provide a concise, human-readable summary.

## Function Information
- Name: {name}
- Signature: {signature}
- Parameters: 
{param_str}
- Calls to other functions:
{calls_str}

## Decompiled Code
```c
{code}
```

Please provide the following information:
1. A brief summary of what the function does (1-3 sentences)
2. The primary purpose of the function
3. Description of each parameter and how it's used
4. Description of the return value and its significance
5. Any notable algorithms, data structures, or patterns used
6. Potential security implications (if any)
7. Any error handling or edge cases

Format your response as a JSON object with the following keys:
- summary: Overall summary of the function
- purpose: Primary purpose
- arguments: Array of objects with name, type, and description for each parameter
- return_value: Description of the return value
- algorithms: Any notable algorithms used
- security_implications: Any security concerns
- error_handling: How errors are handled
"""
        
        return prompt
    
    def _summarize_openai(self, prompt: str) -> Dict[str, Any]:
        """
        Generate a summary using OpenAI API.
        
        Args:
            prompt: Prompt string
            
        Returns:
            Summary dictionary
            
        Raises:
            RuntimeError: If API call fails
        """
        if not self.api_key:
            raise RuntimeError("OpenAI API key not configured")
        
        import openai
        openai.api_key = self.api_key
        
        try:
            # Make API call
            response = openai.ChatCompletion.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert reverse engineer helping to analyze decompiled code."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=2048,
                temperature=self.temperature
            )
            
            # Extract and parse the response
            result_text = response.choices[0].message.content.strip()
            
            try:
                # Try to parse as JSON
                return json.loads(result_text)
            except json.JSONDecodeError:
                # If not valid JSON, extract key information manually
                logger.warning("Failed to parse LLM response as JSON, extracting information manually")
                
                lines = result_text.split("\n")
                summary = ""
                purpose = ""
                arguments = []
                return_value = ""
                
                for line in lines:
                    if line.startswith("Summary:") or line.startswith("1."):
                        summary = line.split(":", 1)[1].strip()
                    elif line.startswith("Purpose:") or line.startswith("2."):
                        purpose = line.split(":", 1)[1].strip()
                    elif line.startswith("Return value:") or line.startswith("4."):
                        return_value = line.split(":", 1)[1].strip()
                
                return {
                    "summary": summary,
                    "purpose": purpose,
                    "arguments": arguments,
                    "return_value": return_value,
                    "raw_response": result_text
                }
                
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {e}")
            raise RuntimeError(f"Error calling OpenAI API: {str(e)}")
    
    def _summarize_anthropic(self, prompt: str) -> Dict[str, Any]:
        """
        Generate a summary using Anthropic API.
        
        Args:
            prompt: Prompt string
            
        Returns:
            Summary dictionary
            
        Raises:
            RuntimeError: If API call fails
        """
        if not self.api_key:
            raise RuntimeError("Anthropic API key not configured")
        
        # Anthropic API endpoint
        api_url = "https://api.anthropic.com/v1/messages"
        
        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01"
        }
        
        data = {
            "model": self.model,
            "messages": [
                {"role": "user", "content": prompt}
            ],
            "max_tokens": 2048,
            "temperature": self.temperature
        }
        
        try:
            response = requests.post(api_url, headers=headers, json=data)
            response.raise_for_status()
            
            result = response.json()
            result_text = result["content"][0]["text"]
            
            try:
                # Try to parse as JSON
                return json.loads(result_text)
            except json.JSONDecodeError:
                # If not valid JSON, extract key information manually
                logger.warning("Failed to parse LLM response as JSON, extracting information manually")
                
                return {
                    "summary": "Summary extraction failed - see raw_response",
                    "purpose": "Purpose extraction failed - see raw_response",
                    "arguments": [],
                    "return_value": "Return value extraction failed - see raw_response",
                    "raw_response": result_text
                }
                
        except Exception as e:
            logger.error(f"Error calling Anthropic API: {e}")
            raise RuntimeError(f"Error calling Anthropic API: {str(e)}")
    
    def _summarize_local(self, prompt: str) -> Dict[str, Any]:
        """
        Generate a summary using a local language model.
        
        Args:
            prompt: Prompt string
            
        Returns:
            Summary dictionary
            
        Raises:
            RuntimeError: If local model fails
        """
        try:
            # This would typically use a local LLM server
            # For now, return a placeholder response
            return {
                "summary": "Local LLM summarization not implemented",
                "purpose": "Please configure an API-based model",
                "arguments": [],
                "return_value": "No information available",
                "algorithms": [],
                "security_implications": "Not analyzed",
                "error_handling": "Not analyzed"
            }
        except Exception as e:
            logger.error(f"Error using local LLM: {e}")
            raise RuntimeError(f"Error using local LLM: {str(e)}")
