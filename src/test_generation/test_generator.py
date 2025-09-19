"""
Test generator module for RE-Architect.

This module generates safe test harnesses for decompiled functions.
"""

import logging
import os
from typing import Dict, List, Optional, Any, Set

from src.core.config import Config

logger = logging.getLogger("re-architect.test_generation")

class TestGenerator:
    """
    Test generator for RE-Architect.
    
    This class generates safe test harnesses for decompiled functions,
    allowing users to execute and verify function behavior.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the test generator.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.sanitizers = config.get("test_generation.sanitizers", ["address", "undefined"])
        self.fuzzing_time = config.get("test_generation.fuzzing_time", 60)
        self.max_test_cases = config.get("test_generation.max_test_cases", 10)
        self.compiler = config.get("test_generation.compiler", "gcc")
        self.compiler_flags = config.get("test_generation.compiler_flags", ["-O0", "-g"])
    
    def generate(
        self,
        functions: Dict[int, Dict[str, Any]],
        data_structures: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Generate test harnesses for functions.
        
        Args:
            functions: Dictionary of functions to generate tests for
            data_structures: Dictionary of data structures used by the functions
            
        Returns:
            Dictionary mapping function IDs to test harness information
        """
        logger.info("Generating test harnesses")
        
        test_harnesses = {}
        
        # Sort functions by complexity (less complex first)
        sorted_functions = sorted(
            functions.items(),
            key=lambda x: x[1].get("complexity", 999)
        )
        
        # Generate tests for the most promising functions
        count = 0
        for func_id, func_info in sorted_functions:
            # Skip if it's a library function
            if func_info.get("is_library", False):
                continue
            
            # Skip if it's too complex
            if func_info.get("complexity", 0) > 20:
                continue
                
            # Skip if it has too many dependencies
            if len(func_info.get("calls", [])) > 5:
                continue
                
            logger.info(f"Generating test for {func_info['name']}")
            
            try:
                # Generate the test harness
                test_info = self._generate_test_harness(func_id, func_info, functions, data_structures)
                
                if test_info:
                    test_harnesses[func_id] = test_info
                    count += 1
                    
                    # Limit the number of test harnesses
                    if count >= self.max_test_cases:
                        break
                        
            except Exception as e:
                logger.warning(f"Error generating test for {func_info['name']}: {e}")
        
        logger.info(f"Generated {len(test_harnesses)} test harnesses")
        return test_harnesses
    
    def _generate_test_harness(
        self,
        func_id: int,
        func_info: Dict[str, Any],
        all_functions: Dict[int, Dict[str, Any]],
        data_structures: Dict[str, Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        """
        Generate a test harness for a specific function.
        
        Args:
            func_id: Function ID
            func_info: Function information
            all_functions: Dictionary of all functions
            data_structures: Dictionary of data structures
            
        Returns:
            Dictionary containing test harness information, or None if generation fails
        """
        # Extract function name and code
        func_name = func_info["name"]
        func_code = func_info["code"]
        
        # Get function signature
        signature = func_info.get("signature", "")
        
        # Get return type
        return_type = func_info.get("return_type", "int")
        if not return_type:
            return_type = "int"
        
        # Get parameters
        parameters = func_info.get("parameters", [])
        
        # Identify dependencies
        dependencies = self._identify_dependencies(func_info, all_functions, data_structures)
        
        # Generate test source code
        source_code = self._generate_test_source(
            func_name,
            func_code,
            return_type,
            parameters,
            dependencies
        )
        
        # Generate build script
        build_script = self._generate_build_script(func_name, dependencies)
        
        return {
            "function_id": func_id,
            "function_name": func_name,
            "source_code": source_code,
            "build_script": build_script,
            "dependencies": dependencies,
            "has_fuzz_target": self._can_generate_fuzz_target(func_info)
        }
    
    def _identify_dependencies(
        self,
        func_info: Dict[str, Any],
        all_functions: Dict[int, Dict[str, Any]],
        data_structures: Dict[str, Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Identify dependencies for a function.
        
        Args:
            func_info: Function information
            all_functions: Dictionary of all functions
            data_structures: Dictionary of data structures
            
        Returns:
            Dictionary containing dependency information
        """
        # Identify called functions
        called_functions = []
        for call in func_info.get("calls", []):
            target_addr_str = call.get("toAddress", "")
            target_name = call.get("toFunction", "")
            
            # Try to find the actual function info
            target_info = None
            for addr, info in all_functions.items():
                if info["name"] == target_name:
                    target_info = info
                    break
            
            if target_info:
                called_functions.append({
                    "name": target_name,
                    "is_library": target_info.get("is_library", False)
                })
            else:
                called_functions.append({
                    "name": target_name,
                    "is_library": True  # Assume external if not found
                })
        
        # Identify used data structures
        used_structures = []
        for struct_name, struct_info in data_structures.items():
            # Check if the structure is used in the function code
            if struct_name in func_info.get("code", ""):
                used_structures.append(struct_name)
        
        return {
            "called_functions": called_functions,
            "used_structures": used_structures
        }
    
    def _generate_test_source(
        self,
        func_name: str,
        func_code: str,
        return_type: str,
        parameters: List[Dict[str, Any]],
        dependencies: Dict[str, Any]
    ) -> str:
        """
        Generate test source code.
        
        Args:
            func_name: Function name
            func_code: Function code
            return_type: Return type
            parameters: Parameter information
            dependencies: Dependency information
            
        Returns:
            Test source code
        """
        # Start with includes
        lines = [
            "/* Test harness for function {} */".format(func_name),
            "#include <stdio.h>",
            "#include <stdlib.h>",
            "#include <string.h>",
            "#include <stdint.h>",
            "#include <stdbool.h>",
            ""
        ]
        
        # Add any necessary structure definitions
        for struct_name in dependencies["used_structures"]:
            lines.append("/* Structure {} definition (placeholder) */".format(struct_name))
            lines.append("typedef struct {} {{".format(struct_name))
            lines.append("    int placeholder;")
            lines.append("    /* Add actual fields here */")
            lines.append("}} {};".format(struct_name))
            lines.append("")
        
        # Add function declaration
        lines.append("/* Original function declaration */")
        
        # Try to extract function declaration from the code
        declaration = self._extract_function_declaration(func_code, func_name, return_type, parameters)
        lines.append(declaration + ";")
        lines.append("")
        
        # Add function implementation (commented out as reference)
        lines.append("/* Original function implementation (for reference) */")
        lines.append("/*")
        for line in func_code.splitlines():
            lines.append(" * " + line)
        lines.append(" */")
        lines.append("")
        
        # Create test main function
        lines.append("int main(int argc, char **argv) {")
        lines.append("    printf(\"Testing function {}...\\n\");".format(func_name))
        lines.append("")
        
        # Create parameter variables
        lines.append("    /* Create test parameters */")
        for i, param in enumerate(parameters):
            param_name = param.get("name", "param{}".format(i))
            param_type = param.get("dataType", "int")
            
            # Generate appropriate initialization based on type
            if "char*" in param_type or "char *" in param_type or "string" in param_type.lower():
                lines.append("    {} = \"test_string\";".format(param_name))
            elif "int" in param_type:
                lines.append("    {} = 42;".format(param_name))
            elif "float" in param_type or "double" in param_type:
                lines.append("    {} = 3.14;".format(param_name))
            elif "bool" in param_type:
                lines.append("    {} = true;".format(param_name))
            elif "*" in param_type:  # Pointer type
                lines.append("    {} = ({}) malloc(sizeof({}));".format(
                    param_name, param_type, param_type.replace("*", "")
                ))
                lines.append("    if (!{}) {{".format(param_name))
                lines.append("        printf(\"Memory allocation failed\\n\");")
                lines.append("        return 1;")
                lines.append("    }")
            else:
                lines.append("    {} = ({}) 0;  /* Initialize with default value */".format(
                    param_name, param_type
                ))
        
        lines.append("")
        
        # Call the function
        lines.append("    /* Call the function */")
        if return_type != "void":
            lines.append("    {} result = {}({});".format(
                return_type,
                func_name,
                ", ".join(p.get("name", "param{}".format(i)) for i, p in enumerate(parameters))
            ))
            lines.append("    printf(\"Result: %d\\n\", result);")
        else:
            lines.append("    {}({});".format(
                func_name,
                ", ".join(p.get("name", "param{}".format(i)) for i, p in enumerate(parameters))
            ))
        
        lines.append("")
        
        # Free any allocated memory
        lines.append("    /* Clean up */")
        for i, param in enumerate(parameters):
            param_name = param.get("name", "param{}".format(i))
            param_type = param.get("dataType", "int")
            
            if "*" in param_type and "char*" not in param_type and "char *" not in param_type:
                lines.append("    free({});".format(param_name))
        
        lines.append("")
        lines.append("    return 0;")
        lines.append("}")
        
        return "\n".join(lines)
    
    def _extract_function_declaration(
        self,
        func_code: str,
        func_name: str,
        return_type: str,
        parameters: List[Dict[str, Any]]
    ) -> str:
        """
        Extract or construct a function declaration.
        
        Args:
            func_code: Function code
            func_name: Function name
            return_type: Return type
            parameters: Parameter information
            
        Returns:
            Function declaration string
        """
        # Try to extract the declaration from the code
        lines = func_code.splitlines()
        for i, line in enumerate(lines):
            if func_name in line and "(" in line and (i == 0 or "{" not in lines[i-1]):
                # This might be the declaration line
                end_line = i
                while end_line < len(lines) and ")" not in lines[end_line]:
                    end_line += 1
                
                if end_line < len(lines):
                    declaration = " ".join(lines[i:end_line+1])
                    # Remove any trailing '{' and surrounding whitespace
                    declaration = declaration.split("{")[0].strip()
                    return declaration
        
        # If we couldn't extract it, construct one
        param_str = ", ".join([
            "{} {}".format(p.get("dataType", "int"), p.get("name", "param{}".format(i)))
            for i, p in enumerate(parameters)
        ])
        
        if not param_str:
            param_str = "void"
            
        return "{} {}({})".format(return_type, func_name, param_str)
    
    def _generate_build_script(self, func_name: str, dependencies: Dict[str, Any]) -> str:
        """
        Generate a build script for the test harness.
        
        Args:
            func_name: Function name
            dependencies: Dependency information
            
        Returns:
            Build script content
        """
        compiler = self.compiler
        flags = " ".join(self.compiler_flags)
        
        # Add sanitizer flags if enabled
        san_flags = ""
        for sanitizer in self.sanitizers:
            san_flags += f" -fsanitize={sanitizer}"
        
        lines = [
            "#!/bin/bash",
            "# Build script for {} test harness".format(func_name),
            "",
            "# Compile the test",
            "{} {} {} {}_test.c -o {}_test".format(compiler, flags, san_flags, func_name, func_name),
            "",
            "# Check if compilation was successful",
            "if [ $? -eq 0 ]; then",
            "    echo \"Build successful\"",
            "    echo \"Run with: ./{}_test\"".format(func_name),
            "else",
            "    echo \"Build failed\"",
            "fi"
        ]
        
        return "\n".join(lines)
    
    def _can_generate_fuzz_target(self, func_info: Dict[str, Any]) -> bool:
        """
        Determine if we can generate a fuzzing target for this function.
        
        Args:
            func_info: Function information
            
        Returns:
            True if a fuzz target can be generated
        """
        # Check if the function has string or array parameters
        # which are good candidates for fuzzing
        parameters = func_info.get("parameters", [])
        
        for param in parameters:
            param_type = param.get("dataType", "")
            if "*" in param_type or "[]" in param_type:
                return True
        
        return False
