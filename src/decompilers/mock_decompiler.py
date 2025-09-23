"""
Mock decompiler for testing RE-Architect.

This module provides a mock decompiler that generates synthetic decompiled code
for testing purposes when real decompilers are not available.
"""

import logging
from typing import Dict, Any, List

from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode

logger = logging.getLogger("re-architect.decompilers.mock")

class MockDecompiler(BaseDecompiler):
    """
    Mock decompiler for testing purposes.
    
    This decompiler generates synthetic decompiled code based on static analysis
    of the binary, allowing the pipeline to be tested without requiring actual
    decompiler installations.
    """
    
    name = "Mock Decompiler"
    version = "1.0.0"
    
    def __init__(self, config: Dict[str, Any] = None):
        """
        Initialize the mock decompiler.
        
        Args:
            config: Decompiler configuration (not used for mock)
        """
        super().__init__()
        self.config = config or {}
        logger.info("Mock decompiler initialized for testing")
    
    def is_available(self) -> bool:
        """
        Check if the mock decompiler is available.
        
        Returns:
            Always True for mock decompiler
        """
        return True
    
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the mock decompiler.
        
        Returns:
            Dictionary containing mock decompiler information
        """
        return {
            "name": self.name,
            "version": self.version,
            "type": "mock",
            "available": True,
            "capabilities": ["decompilation", "testing"],
            "supported_architectures": ["x86", "x86_64", "arm", "arm64"],
            "supported_formats": ["PE", "ELF", "Mach-O"],
            "description": "Mock decompiler for testing RE-Architect pipeline"
        }
    
    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        """
        Generate mock decompiled code.
        
        Args:
            binary_info: Binary information object
            
        Returns:
            DecompiledCode object with synthetic decompiled code
        """
        logger.info(f"Mock decompiling {binary_info.path}")
        
        # Generate synthetic function data based on the binary
        functions = self._generate_mock_functions(binary_info)
        
        # Generate synthetic decompiled code
        decompiled_code_str = self._generate_mock_code(functions)
        
        # Create DecompiledCode object
        decompiled_result = DecompiledCode(binary_info)
        
        # Add functions to the result
        for func in functions:
            # Extract function-specific code from the full decompiled code
            func_code = self._extract_function_code(decompiled_code_str, func["name"])
            decompiled_result.add_function(
                address=func["address"],
                code=func_code,
                name=func["name"],
                metadata={
                    "signature": func["signature"],
                    "parameters": func["parameters"],
                    "return_type": func["return_type"],
                    "complexity": func["complexity"],
                    "call_graph": func["call_graph"],
                    "strings": func["strings"],
                    "mock": True
                }
            )
        
        # Add metadata
        decompiled_result.metadata = {
            "decompiler": "mock",
            "version": self.version,
            "binary_path": str(binary_info.path),
            "architecture": str(binary_info.architecture.value if hasattr(binary_info.architecture, 'value') else binary_info.architecture),
            "format": str(binary_info.format.value if hasattr(binary_info.format, 'value') else binary_info.format),
            "generated": True,
            "test_mode": True,
            "full_code": decompiled_code_str
        }
        
        return decompiled_result
    
    def _generate_mock_functions(self, binary_info: BinaryInfo) -> List[Dict[str, Any]]:
        """
        Generate mock function data based on binary analysis.
        
        Args:
            binary_info: Binary information object
            
        Returns:
            List of mock function dictionaries
        """
        # Extract some basic info from the binary
        arch = binary_info.architecture.value if hasattr(binary_info.architecture, 'value') else str(binary_info.architecture)
        entry_point = binary_info.entry_point
        
        # Generate mock functions based on common patterns
        mock_functions = [
            {
                "name": "main",
                "address": entry_point,
                "size": 256,
                "signature": "int main(int argc, char** argv)",
                "parameters": [
                    {"name": "argc", "type": "int"},
                    {"name": "argv", "type": "char**"}
                ],
                "return_type": "int",
                "complexity": "medium",
                "call_graph": ["add_numbers", "multiply_numbers", "greet_user"],
                "strings": ["Addition result: %d\\n", "Multiplication result: %d\\n"],
                "mock": True
            },
            {
                "name": "add_numbers",
                "address": entry_point + 0x100,
                "size": 64,
                "signature": "int add_numbers(int a, int b)",
                "parameters": [
                    {"name": "a", "type": "int"},
                    {"name": "b", "type": "int"}
                ],
                "return_type": "int",
                "complexity": "low",
                "call_graph": [],
                "strings": [],
                "mock": True
            },
            {
                "name": "multiply_numbers",
                "address": entry_point + 0x140,
                "size": 64,
                "signature": "int multiply_numbers(int x, int y)",
                "parameters": [
                    {"name": "x", "type": "int"},
                    {"name": "y", "type": "int"}
                ],
                "return_type": "int",
                "complexity": "low",
                "call_graph": [],
                "strings": [],
                "mock": True
            },
            {
                "name": "greet_user",
                "address": entry_point + 0x180,
                "size": 128,
                "signature": "void greet_user(char* name)",
                "parameters": [
                    {"name": "name", "type": "char*"}
                ],
                "return_type": "void",
                "complexity": "low",
                "call_graph": ["printf"],
                "strings": ["Hello, %s!\\n"],
                "mock": True
            }
        ]
        
        return mock_functions
    
    def _generate_mock_code(self, functions: List[Dict[str, Any]]) -> str:
        """
        Generate synthetic decompiled C code.
        
        Args:
            functions: List of function metadata
            
        Returns:
            Generated C code as string
        """
        code_parts = [
            "// Mock decompiled code generated for testing",
            "#include <stdio.h>",
            "#include <string.h>",
            "",
            "// Global variables (mock)",
            "static int global_counter = 0;",
            ""
        ]
        
        # Generate function implementations
        for func in functions:
            if func["name"] == "main":
                code_parts.extend([
                    f"int {func['name']}(int argc, char** argv) {{",
                    "    // Mock implementation of main function",
                    "    int result1 = add_numbers(5, 3);",
                    "    int result2 = multiply_numbers(4, 6);",
                    "    ",
                    "    printf(\"Addition result: %d\\n\", result1);",
                    "    printf(\"Multiplication result: %d\\n\", result2);",
                    "    ",
                    "    char name[] = \"World\";",
                    "    greet_user(name);",
                    "    ",
                    "    return 0;",
                    "}",
                    ""
                ])
            elif func["name"] == "add_numbers":
                params = ', '.join([f"{p['type']} {p['name']}" for p in func['parameters']])
                code_parts.extend([
                    f"{func['return_type']} {func['name']}({params}) {{",
                    "    // Mock implementation of addition function",
                    "    return a + b;",
                    "}",
                    ""
                ])
            elif func["name"] == "multiply_numbers":
                params = ', '.join([f"{p['type']} {p['name']}" for p in func['parameters']])
                code_parts.extend([
                    f"{func['return_type']} {func['name']}({params}) {{",
                    "    // Mock implementation of multiplication function",
                    "    return x * y;",
                    "}",
                    ""
                ])
            elif func["name"] == "greet_user":
                params = ', '.join([f"{p['type']} {p['name']}" for p in func['parameters']])
                code_parts.extend([
                    f"{func['return_type']} {func['name']}({params}) {{",
                    "    // Mock implementation of greeting function",
                    "    printf(\"Hello, %s!\\n\", name);",
                    "}",
                    ""
                ])
        
        return "\n".join(code_parts)
    
    def _extract_function_code(self, full_code: str, function_name: str) -> str:
        """
        Extract code for a specific function from the full decompiled code.
        
        Args:
            full_code: Complete decompiled C code
            function_name: Name of function to extract
            
        Returns:
            Code for the specific function
        """
        lines = full_code.split('\n')
        in_function = False
        function_lines = []
        
        for line in lines:
            if f"{function_name}(" in line and "{" in line:
                in_function = True
                function_lines.append(line)
            elif in_function:
                function_lines.append(line)
                if line.strip() == "}" and len([l for l in function_lines if "{" in l]) == len([l for l in function_lines if "}" in l]):
                    break
        
        return "\n".join(function_lines)