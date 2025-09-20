"""
Configuration module for RE-Architect.

This module handles loading, validating, and accessing configuration settings.
"""

import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional, Union
import yaml

logger = logging.getLogger("re-architect.config")

class Config:
    """
    Configuration manager for RE-Architect.
    
    Handles loading and accessing all configuration settings for the pipeline.
    """
    
    # Default configuration values
    DEFAULT_CONFIG = {
        "auth": {
            "jwt_secret_key": "change-this-in-production",
            "jwt_algorithm": "HS256",
            "jwt_expiration_delta": 86400,  # seconds (24 hours)
            "token_location": ["headers"],
            "enable_registration": True,
            "default_role": "analyst"
        },
        "decompiler": {
            "ghidra": {
                "path": None,
                "headless": True,
                "timeout": 300  # seconds
            },
            "ida": {
                "path": None,
                "headless": True,
                "timeout": 300  # seconds
            },
            "binary_ninja": {
                "path": None,
                "timeout": 300  # seconds
            }
        },
        "analysis": {
            "static": {
                "function_analysis_depth": "medium",  # basic, medium, deep
                "data_flow_analysis": True,
                "control_flow_analysis": True
            },
            "dynamic": {
                "enable": False,
                "max_execution_time": 60,  # seconds
                "memory_limit": 2048,  # MB
                "sandbox_type": "container"  # none, container, vm
            }
        },
        "llm": {
            "enable": True,
            "provider": "openai",
            "model": "gpt-4",
            "api_key": None,
            "max_tokens": 8192,
            "temperature": 0.2,
            "cache_dir": "./cache/llm"
        },
        "test_generation": {
            "sanitizers": ["address", "undefined"],
            "fuzzing_time": 60,  # seconds
            "max_test_cases": 10,
            "compiler": "gcc",
            "compiler_flags": ["-O0", "-g"]
        },
        "visualization": {
            "host": "localhost",
            "port": 8000,
            "theme": "light"
        },
        "output": {
            "detail_level": "full",  # basic, standard, full
            "formats": ["json", "html"]
        }
    }
    
    def __init__(self, config_data: Union[Dict[str, Any], str, Path] = None):
        """
        Initialize configuration with provided data or defaults.
        
        Args:
            config_data: Dictionary containing configuration values or path to config file
        """
        # Start with default configuration
        self._config = self.DEFAULT_CONFIG.copy()
        
        # If config_data is a string or Path, assume it's a file path and load it
        if isinstance(config_data, (str, Path)):
            config_data = self._load_config_file(config_data)
        
        # Update with provided configuration if available
        if config_data:
            self._update_recursive(self._config, config_data)
        
        # Flag to track if LLM is enabled
        self.use_llm = self._config["llm"]["enable"]
        
    def _load_config_file(self, config_path: Union[str, Path]) -> Dict[str, Any]:
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Dictionary containing the loaded configuration
            
        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the configuration file contains invalid YAML
        """
        config_path = Path(config_path)
        
        # If file doesn't exist, return empty dict
        if not config_path.exists():
            logger.warning(f"Configuration file not found: {config_path}")
            return {}
        
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
            
            logger.info(f"Loaded configuration from {config_path}")
            return config_data or {}
            
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration file: {e}")
            raise
    
    @classmethod
    def from_file(cls, config_path: Union[str, Path]) -> "Config":
        """
        Load configuration from a YAML file.
        
        Args:
            config_path: Path to the configuration file
            
        Returns:
            Config object initialized with the loaded configuration
            
        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            yaml.YAMLError: If the configuration file contains invalid YAML
        """
        config_path = Path(config_path)
        
        # If file doesn't exist, return default configuration
        if not config_path.exists():
            logger.warning(f"Configuration file not found: {config_path}")
            logger.info("Using default configuration")
            return cls()
        
        try:
            with open(config_path, "r") as f:
                config_data = yaml.safe_load(f)
            
            logger.info(f"Loaded configuration from {config_path}")
            return cls(config_data)
            
        except yaml.YAMLError as e:
            logger.error(f"Error parsing configuration file: {e}")
            raise
    
    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using a dot-separated path.
        
        Args:
            key_path: Dot-separated path to the configuration value (e.g., "llm.model")
            default: Default value to return if the key doesn't exist
            
        Returns:
            Configuration value at the specified path, or the default value if not found
        """
        keys = key_path.split(".")
        value = self._config
        
        try:
            for key in keys:
                value = value[key]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key_path: str, value: Any) -> None:
        """
        Set a configuration value using a dot-separated path.
        
        Args:
            key_path: Dot-separated path to the configuration value (e.g., "llm.model")
            value: Value to set
        """
        keys = key_path.split(".")
        config = self._config
        
        # Navigate to the innermost dictionary
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        # Set the value
        config[keys[-1]] = value
        
        # Update use_llm flag if the llm.enable setting is changed
        if key_path == "llm.enable":
            self.use_llm = value
    
    def disable_llm(self) -> None:
        """Disable LLM-based analysis."""
        self.set("llm.enable", False)
        self.use_llm = False
    
    def enable_llm(self) -> None:
        """Enable LLM-based analysis."""
        self.set("llm.enable", True)
        self.use_llm = True
    
    def _update_recursive(self, base_dict: Dict[str, Any], update_dict: Dict[str, Any]) -> None:
        """
        Recursively update a dictionary with values from another dictionary.
        
        Args:
            base_dict: Dictionary to update
            update_dict: Dictionary containing values to update with
        """
        for key, value in update_dict.items():
            if key in base_dict and isinstance(base_dict[key], dict) and isinstance(value, dict):
                self._update_recursive(base_dict[key], value)
            else:
                base_dict[key] = value
