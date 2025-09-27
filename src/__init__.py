"""
RE-Architect: Advanced Reverse Engineering Platform

A comprehensive reverse engineering platform that combines traditional static analysis 
with modern AI-powered insights for binary analysis and security research.
"""

__version__ = "1.0.0"
__description__ = "Advanced reverse engineering platform with AI-powered analysis"

# Core exports
from src.core.pipeline import ReversePipeline
from src.core.config import Config
from src.core.binary_loader import BinaryLoader

__all__ = [
    "ReversePipeline",
    "Config", 
    "BinaryLoader",
    "__version__",
]
