"""
Binary Ninja decompiler implementation for RE-Architect.

This module provides the integration with Binary Ninja for decompilation.
"""

import logging
import os
import json
import tempfile
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode, DecompiledFunction

logger = logging.getLogger("re-architect.decompilers.binary_ninja")

class BinaryNinjaDecompiler(BaseDecompiler):
    """
    Binary Ninja decompiler implementation.
    
    This class provides integration with Binary Ninja using its Python API.
    """
    
    def __init__(self, binja_path: Optional[str] = None):
        """
        Initialize the Binary Ninja decompiler.
        
        Args:
            binja_path: Path to Binary Ninja installation directory (optional)
        """
        super().__init__()
        self.name = "BinaryNinjaDecompiler"
        
        # Try to find Binary Ninja path if not provided
        self.binja_path = binja_path or self._find_binja_path()
        
        # Try to import binaryninja module
        self.binja_available = False
        try:
            if self.binja_path:
                import sys
                sys.path.append(os.path.join(self.binja_path, "python"))
            
            import binaryninja
            self.binaryninja = binaryninja
            self.binja_available = True
            logger.info("Binary Ninja Python API available")
        except ImportError as e:
            logger.warning(f"Binary Ninja Python API not available: {e}")
            self.binaryninja = None
        
        # Cache decompiler info
        self._decompiler_info = None
    
    def _find_binja_path(self) -> Optional[str]:
        """
        Find the Binary Ninja installation directory.
        
        Looks for Binary Ninja in common installation locations.
        
        Returns:
            Path to Binary Ninja installation directory, or None if not found
        """
        # Check environment variable
        if "BINARYNINJADIR" in os.environ:
            path = os.environ["BINARYNINJADIR"]
            if os.path.exists(path):
                return path
        
        # Check common installation locations
        common_paths = []
        
        if os.name == "nt":  # Windows
            common_paths.extend([
                "C:/Program Files/Vector35/BinaryNinja",
                "C:/Program Files (x86)/Vector35/BinaryNinja",
                "C:/BinaryNinja",
                os.path.expanduser("~/BinaryNinja")
            ])
        elif os.name == "posix":  # Unix-like
            if "darwin" in os.sys.platform:  # macOS
                common_paths.extend([
                    "/Applications/Binary Ninja.app",
                    "/Applications/Binary Ninja.app/Contents/MacOS",
                    os.path.expanduser("~/Applications/Binary Ninja.app")
                ])
            else:  # Linux
                common_paths.extend([
                    "/opt/binaryninja",
                    "/usr/local/binaryninja", 
                    os.path.expanduser("~/binaryninja"),
                    os.path.expanduser("~/Binary Ninja")
                ])
        
        for path in common_paths:
            if os.path.exists(path):
                # Check for python directory
                python_dir = os.path.join(path, "python")
                if os.path.exists(python_dir):
                    return path
        
        return None
    
    def is_available(self) -> bool:
        """
        Check if Binary Ninja is available on the system.
        
        Returns:
            True if Binary Ninja is available, False otherwise
        """
        return self.binja_available and self.binaryninja is not None
    
    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        """
        Decompile a binary using Binary Ninja.
        
        Args:
            binary_info: Information about the binary to decompile
            
        Returns:
            Object containing the decompiled code
            
        Raises:
            RuntimeError: If decompilation fails or Binary Ninja is not available
        """
        if not self.is_available():
            raise RuntimeError("Binary Ninja is not available")
        
        logger.info(f"Decompiling {binary_info.path} using Binary Ninja")
        
        try:
            # Open the binary
            bv = self.binaryninja.open_view(str(binary_info.path))
            if not bv:
                raise RuntimeError("Failed to open binary in Binary Ninja")
            
            # Wait for analysis to complete
            bv.update_analysis_and_wait()
            
            # Create DecompiledCode object
            decompiled_code = DecompiledCode(binary_info)
            
            # Export functions
            self._export_functions(bv, decompiled_code)
            
            # Export strings
            self._export_strings(bv, decompiled_code)
            
            # Export data types
            self._export_data_types(bv, decompiled_code)
            
            return decompiled_code
            
        except Exception as e:
            logger.exception(f"Error during Binary Ninja decompilation: {e}")
            raise RuntimeError(f"Binary Ninja decompilation failed: {str(e)}")
    
    def _export_functions(self, bv, decompiled_code: DecompiledCode):
        """
        Export functions from Binary Ninja.
        
        Args:
            bv: Binary Ninja BinaryView object
            decompiled_code: DecompiledCode object to populate
        """
        logger.info("Exporting functions from Binary Ninja")
        
        count = 0
        for func in bv.functions:
            try:
                # Get basic function information
                address = func.start
                name = func.name
                
                # Get decompiled code using high-level IL
                hlil = func.hlil
                if hlil and hlil.root:
                    # Convert HLIL to pseudo-C code
                    code_lines = []
                    
                    # Add function signature
                    return_type = str(func.return_type) if func.return_type else "void"
                    params = []
                    for param in func.parameter_vars:
                        param_type = str(param.type) if param.type else "int"
                        params.append(f"{param_type} {param.name}")
                    
                    signature = f"{return_type} {name}({', '.join(params)})"
                    code_lines.append(signature + " {")
                    
                    # Add HLIL representation
                    for instruction in hlil.instructions:
                        code_lines.append(f"    {instruction}")
                    
                    code_lines.append("}")
                    code = "\\n".join(code_lines)
                else:
                    # Fallback to disassembly if no HLIL
                    code_lines = [f"// Disassembly for {name}"]
                    for basic_block in func.basic_blocks:
                        for instruction in basic_block:
                            addr_str = f"0x{instruction.address:x}"
                            code_lines.append(f"{addr_str}: {instruction}")
                    code = "\\n".join(code_lines)
                
                # Extract metadata
                metadata = {
                    "signature": signature if 'signature' in locals() else "",
                    "return_type": str(func.return_type) if func.return_type else "unknown",
                    "parameters": [
                        {
                            "name": param.name,
                            "type": str(param.type) if param.type else "unknown"
                        }
                        for param in func.parameter_vars
                    ],
                    "calls": [
                        {
                            "address": f"0x{ref.address:x}",
                            "name": bv.get_function_at(ref.address).name if bv.get_function_at(ref.address) else "unknown"
                        }
                        for ref in func.call_sites
                    ],
                    "size": len(func),
                    "basic_blocks": len(func.basic_blocks),
                    "calling_convention": str(func.calling_convention) if func.calling_convention else "unknown"
                }
                
                decompiled_code.add_function(address, code, name, metadata)
                count += 1
                
            except Exception as e:
                logger.warning(f"Failed to process function {func.name}: {e}")
        
        logger.info(f"Exported {count} functions")
    
    def _export_strings(self, bv, decompiled_code: DecompiledCode):
        """
        Export strings from Binary Ninja.
        
        Args:
            bv: Binary Ninja BinaryView object
            decompiled_code: DecompiledCode object to populate
        """
        logger.info("Exporting strings from Binary Ninja")
        
        count = 0
        for string in bv.strings:
            try:
                address = string.start
                value = string.value
                decompiled_code.add_string(address, value)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to process string at 0x{string.start:x}: {e}")
        
        logger.info(f"Exported {count} strings")
    
    def _export_data_types(self, bv, decompiled_code: DecompiledCode):
        """
        Export data types from Binary Ninja.
        
        Args:
            bv: Binary Ninja BinaryView object  
            decompiled_code: DecompiledCode object to populate
        """
        logger.info("Exporting data types from Binary Ninja")
        
        count = 0
        for name, type_obj in bv.types.items():
            try:
                # Convert Binary Ninja type to C-like definition
                definition = str(type_obj)
                decompiled_code.add_type(name, definition)
                count += 1
            except Exception as e:
                logger.warning(f"Failed to process type {name}: {e}")
        
        logger.info(f"Exported {count} data types")
    
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the Binary Ninja decompiler.
        
        Returns:
            Dictionary containing decompiler information
        """
        if self._decompiler_info is not None:
            return self._decompiler_info
        
        info = {
            "name": self.name,
            "available": self.is_available(),
            "path": self.binja_path,
            "version": "unknown"
        }
        
        # Try to get version information
        if self.is_available():
            try:
                info["version"] = self.binaryninja.version()
                info["build_id"] = getattr(self.binaryninja, "build_id", "unknown")
            except Exception as e:
                logger.warning(f"Error getting Binary Ninja version: {e}")
        
        self._decompiler_info = info
        return info
        
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the decompiler.
        
        Returns:
            Dictionary containing decompiler information
        """
        return {
            "name": self.name,
            "version": "Not available",
            "capabilities": []
        }