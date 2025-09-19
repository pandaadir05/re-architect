"""
Base decompiler interface for RE-Architect.

This module defines the base interface for all decompilers.
"""

import abc
import logging
from pathlib import Path
from typing import Dict, List, Optional, Union

from src.core.binary_loader import BinaryInfo

logger = logging.getLogger("re-architect.decompilers.base")

class DecompiledCode:
    """
    Container for decompiled code and related information.
    
    This class stores the decompiled code and associated metadata
    from a decompilation process.
    """
    
    def __init__(self, binary_info: BinaryInfo):
        """
        Initialize decompiled code container.
        
        Args:
            binary_info: Information about the decompiled binary
        """
        self.binary_info = binary_info
        self.functions = {}  # Function address -> decompiled code
        self.function_names = {}  # Function address -> function name
        self.function_metadata = {}  # Function address -> metadata dict
        self.data_segments = {}  # Start address -> (data, size, name)
        self.strings = {}  # Address -> string value
        self.comments = {}  # Address -> comment
        self.types = {}  # Type name -> type definition
        
    def add_function(self, address: int, code: str, name: str, metadata: Dict = None):
        """
        Add a decompiled function.
        
        Args:
            address: Function start address
            code: Decompiled function code
            name: Function name
            metadata: Additional function metadata
        """
        self.functions[address] = code
        self.function_names[address] = name
        self.function_metadata[address] = metadata or {}
        
    def add_data_segment(self, address: int, data: bytes, size: int, name: str):
        """
        Add a data segment.
        
        Args:
            address: Start address
            data: Raw data bytes
            size: Size of the segment
            name: Segment name
        """
        self.data_segments[address] = (data, size, name)
        
    def add_string(self, address: int, value: str):
        """
        Add a string constant.
        
        Args:
            address: String address
            value: String value
        """
        self.strings[address] = value
        
    def add_comment(self, address: int, comment: str):
        """
        Add a comment.
        
        Args:
            address: Comment address
            comment: Comment text
        """
        self.comments[address] = comment
        
    def add_type(self, name: str, definition: str):
        """
        Add a type definition.
        
        Args:
            name: Type name
            definition: Type definition
        """
        self.types[name] = definition
        
    def get_function_count(self) -> int:
        """
        Get the number of decompiled functions.
        
        Returns:
            Number of functions
        """
        return len(self.functions)
        
    def __str__(self) -> str:
        """
        String representation of decompiled code.
        
        Returns:
            Summary string
        """
        return (
            f"DecompiledCode(binary={self.binary_info.path.name}, "
            f"functions={len(self.functions)}, "
            f"data_segments={len(self.data_segments)}, "
            f"strings={len(self.strings)}, "
            f"types={len(self.types)})"
        )

class BaseDecompiler(abc.ABC):
    """
    Base interface for all decompilers.
    
    This abstract class defines the common interface that all decompiler
    implementations must provide.
    """
    
    def __init__(self):
        """Initialize the decompiler."""
        self.name = self.__class__.__name__
        self.logger = logging.getLogger(f"re-architect.decompilers.{self.name.lower()}")
    
    @abc.abstractmethod
    def is_available(self) -> bool:
        """
        Check if the decompiler is available for use.
        
        Returns:
            True if the decompiler is available, False otherwise
        """
        pass
    
    @abc.abstractmethod
    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        """
        Decompile a binary file.
        
        Args:
            binary_info: Information about the binary to decompile
            
        Returns:
            DecompiledCode object containing decompilation results
            
        Raises:
            RuntimeError: If decompilation fails
        """
        pass
    
    @abc.abstractmethod
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the decompiler.
        
        Returns:
            Dictionary containing decompiler information
        """
        pass
    
    def __str__(self) -> str:
        """
        String representation of the decompiler.
        
        Returns:
            Decompiler name
        """
        return self.name
