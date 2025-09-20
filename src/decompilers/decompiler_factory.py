"""
Decompiler factory for RE-Architect.

This module provides a factory for creating decompiler instances.
"""

import logging
from typing import Optional

from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import BaseDecompiler
from src.decompilers.ghidra_decompiler import GhidraDecompiler
from src.decompilers.ida_decompiler import IDADecompiler
from src.decompilers.binary_ninja_decompiler import BinaryNinjaDecompiler

logger = logging.getLogger("re-architect.decompilers.factory")

class DecompilerFactory:
    """
    Factory for creating decompiler instances.
    
    This class handles creating the appropriate decompiler instance based on the
    requested decompiler name or binary information.
    """
    
    def get_decompiler(self, decompiler_name: str = "auto") -> BaseDecompiler:
        """
        Get a decompiler instance.
        
        Args:
            decompiler_name: Name of the decompiler to create (ghidra, ida, binja, auto)
            
        Returns:
            Initialized decompiler instance
            
        Raises:
            ValueError: If the requested decompiler is not supported
        """
        return self.create(decompiler_name)
    
    def create(self, decompiler_name: str = "auto") -> BaseDecompiler:
        """
        Create a decompiler instance.
        
        Args:
            decompiler_name: Name of the decompiler to create (ghidra, ida, binja, auto)
            
        Returns:
            Initialized decompiler instance
            
        Raises:
            ValueError: If the requested decompiler is not supported
        """
        decompiler_name = decompiler_name.lower()
        
        if decompiler_name == "ghidra":
            logger.info("Creating Ghidra decompiler")
            return GhidraDecompiler()
        elif decompiler_name == "ida" or decompiler_name == "ida_pro":
            logger.info("Creating IDA Pro decompiler")
            return IDADecompiler()
        elif decompiler_name == "binja" or decompiler_name == "binary_ninja":
            logger.info("Creating Binary Ninja decompiler")
            return BinaryNinjaDecompiler()
        elif decompiler_name == "auto":
            # We'll pick one based on availability later when we have binary info
            logger.info("Creating auto-selected decompiler (will choose when binary is available)")
            return self._create_auto_decompiler()
        else:
            logger.error(f"Unsupported decompiler: {decompiler_name}")
            raise ValueError(f"Unsupported decompiler: {decompiler_name}")
    
    def _create_auto_decompiler(self) -> BaseDecompiler:
        """
        Create an automatically selected decompiler.
        
        Returns:
            Decompiler instance (defaults to Ghidra if available)
        """
        # Try to create decompilers in order of preference
        for decompiler_class in [GhidraDecompiler, IDADecompiler, BinaryNinjaDecompiler]:
            try:
                decompiler = decompiler_class()
                if decompiler.is_available():
                    logger.info(f"Auto-selected decompiler: {decompiler.name}")
                    return decompiler
            except Exception as e:
                logger.debug(f"Error creating {decompiler_class.__name__}: {e}")
        
        # If we get here, none of the decompilers are available
        # Default to Ghidra (which will handle the error on actual decompilation)
        logger.warning("No available decompilers found, defaulting to Ghidra")
        return GhidraDecompiler()
