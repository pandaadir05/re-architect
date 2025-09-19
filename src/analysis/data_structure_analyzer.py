"""
Data structure analyzer module for RE-Architect.

This module analyzes decompiled code to identify and reconstruct data structures.
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Any

from src.core.config import Config
from src.decompilers.base_decompiler import DecompiledCode
from src.analysis.static_analyzer import StaticAnalysisResults

logger = logging.getLogger("re-architect.analysis.data_structures")

class DataStructureAnalyzer:
    """
    Data structure analyzer for RE-Architect.
    
    This class analyzes decompiled code to identify and reconstruct data structures
    used in the binary.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the data structure analyzer.
        
        Args:
            config: Configuration object
        """
        self.config = config
    
    def analyze(
        self,
        decompiled_code: DecompiledCode,
        static_analysis: StaticAnalysisResults
    ) -> Dict[str, Dict[str, Any]]:
        """
        Analyze decompiled code to extract data structures.
        
        Args:
            decompiled_code: Decompiled code to analyze
            static_analysis: Results from static analysis
            
        Returns:
            Dictionary mapping structure names to structure information
        """
        logger.info("Starting data structure analysis")
        
        # Start with structures already identified by the decompiler
        structures = self._extract_defined_structures(decompiled_code)
        
        # Analyze function parameters and variables to infer additional structures
        inferred_structures = self._infer_structures(decompiled_code, static_analysis)
        
        # Merge the results (preserving already defined structures)
        for name, struct_info in inferred_structures.items():
            if name not in structures:
                structures[name] = struct_info
        
        logger.info(f"Identified {len(structures)} data structures")
        return structures
    
    def _extract_defined_structures(self, decompiled_code: DecompiledCode) -> Dict[str, Dict[str, Any]]:
        """
        Extract structures already defined in the decompiled code.
        
        Args:
            decompiled_code: Decompiled code to analyze
            
        Returns:
            Dictionary mapping structure names to structure information
        """
        structures = {}
        
        # Process types defined by the decompiler
        for name, definition in decompiled_code.types.items():
            # Only process structures
            if self._is_structure_definition(definition):
                # Parse the structure definition
                structure_info = self._parse_structure_definition(name, definition)
                if structure_info:
                    structures[name] = structure_info
        
        return structures
    
    def _is_structure_definition(self, definition: str) -> bool:
        """
        Check if a definition represents a structure.
        
        Args:
            definition: Type definition to check
            
        Returns:
            True if the definition is a structure
        """
        return definition.strip().startswith("struct ")
    
    def _parse_structure_definition(self, name: str, definition: str) -> Dict[str, Any]:
        """
        Parse a structure definition into a structured format.
        
        Args:
            name: Structure name
            definition: Structure definition
            
        Returns:
            Dictionary containing structure information
        """
        # Remove comments
        definition = re.sub(r"//.*$", "", definition, flags=re.MULTILINE)
        
        # Extract fields
        field_pattern = r"(\w+)\s+(\w+)(?:\[(\d+)\])?;"
        fields = []
        
        for line in definition.splitlines():
            line = line.strip()
            match = re.search(field_pattern, line)
            if match:
                field_type = match.group(1)
                field_name = match.group(2)
                field_array_size = match.group(3)
                
                field_info = {
                    "name": field_name,
                    "type": field_type,
                    "is_array": field_array_size is not None
                }
                
                if field_array_size:
                    field_info["array_size"] = int(field_array_size)
                
                fields.append(field_info)
        
        # Calculate size (this is approximate)
        type_sizes = {
            "char": 1,
            "byte": 1,
            "short": 2,
            "int": 4,
            "long": 4,
            "float": 4,
            "double": 8,
            "pointer": 4,  # Assume 32-bit pointers by default
            "void": 0
        }
        
        size = 0
        for field in fields:
            field_type = field["type"]
            base_size = type_sizes.get(field_type, 4)  # Default to 4 bytes if unknown
            
            if field.get("is_array", False):
                array_size = field.get("array_size", 1)
                field_size = base_size * array_size
            else:
                field_size = base_size
            
            size += field_size
        
        return {
            "name": name,
            "original_definition": definition,
            "fields": fields,
            "size": size,
            "source": "decompiler"
        }
    
    def _infer_structures(
        self,
        decompiled_code: DecompiledCode,
        static_analysis: StaticAnalysisResults
    ) -> Dict[str, Dict[str, Any]]:
        """
        Infer structures from function parameters and usage patterns.
        
        Args:
            decompiled_code: Decompiled code to analyze
            static_analysis: Results from static analysis
            
        Returns:
            Dictionary mapping inferred structure names to structure information
        """
        inferred_structures = {}
        
        # Look for structure usage patterns in functions
        for func_addr, func_info in static_analysis.functions.items():
            # Skip library functions
            if func_info.get("is_library", False):
                continue
            
            func_code = func_info.get("code", "")
            
            # Look for struct dereference patterns
            self._find_struct_dereferences(func_code, inferred_structures)
            
            # Analyze parameters that might be structures
            parameters = func_info.get("parameters", [])
            self._analyze_struct_parameters(parameters, func_code, inferred_structures)
        
        return inferred_structures
    
    def _find_struct_dereferences(
        self,
        code: str,
        inferred_structures: Dict[str, Dict[str, Any]]
    ) -> None:
        """
        Find structure dereference patterns in code.
        
        Args:
            code: Function code to analyze
            inferred_structures: Dictionary to update with inferred structures
        """
        # Look for patterns like "x->field" or "x.field"
        arrow_pattern = r"(\w+)->(\w+)"
        dot_pattern = r"(\w+)\.(\w+)"
        
        # Find all arrow dereferences
        for match in re.finditer(arrow_pattern, code):
            struct_var = match.group(1)
            field_name = match.group(2)
            
            # Generate a structure name if this looks like a structure
            struct_name = f"struct_{struct_var}"
            
            # Add to inferred structures if new
            if struct_name not in inferred_structures:
                inferred_structures[struct_name] = {
                    "name": struct_name,
                    "fields": [],
                    "size": 0,
                    "source": "inferred"
                }
            
            # Add the field if it's new
            struct_info = inferred_structures[struct_name]
            if not any(field["name"] == field_name for field in struct_info["fields"]):
                struct_info["fields"].append({
                    "name": field_name,
                    "type": "unknown",
                    "is_array": False
                })
        
        # Find all dot dereferences
        for match in re.finditer(dot_pattern, code):
            struct_var = match.group(1)
            field_name = match.group(2)
            
            # Generate a structure name if this looks like a structure
            struct_name = f"struct_{struct_var}"
            
            # Add to inferred structures if new
            if struct_name not in inferred_structures:
                inferred_structures[struct_name] = {
                    "name": struct_name,
                    "fields": [],
                    "size": 0,
                    "source": "inferred"
                }
            
            # Add the field if it's new
            struct_info = inferred_structures[struct_name]
            if not any(field["name"] == field_name for field in struct_info["fields"]):
                struct_info["fields"].append({
                    "name": field_name,
                    "type": "unknown",
                    "is_array": False
                })
    
    def _analyze_struct_parameters(
        self,
        parameters: List[Dict[str, Any]],
        code: str,
        inferred_structures: Dict[str, Dict[str, Any]]
    ) -> None:
        """
        Analyze function parameters that might be structures.
        
        Args:
            parameters: List of parameter information
            code: Function code to analyze
            inferred_structures: Dictionary to update with inferred structures
        """
        for param in parameters:
            param_name = param.get("name", "")
            param_type = param.get("dataType", "")
            
            # Check if this parameter might be a structure pointer
            if "struct" in param_type or "*" in param_type:
                # Look for dereference patterns with this parameter
                arrow_pattern = f"{param_name}->([\\w_]+)"
                
                for match in re.finditer(arrow_pattern, code):
                    field_name = match.group(1)
                    
                    # Generate structure name from the parameter type if possible
                    if "struct" in param_type:
                        # Extract name from something like "struct_name *"
                        type_match = re.search(r"struct\s+(\w+)", param_type)
                        if type_match:
                            struct_name = type_match.group(1)
                        else:
                            struct_name = f"struct_{param_name}"
                    else:
                        struct_name = f"struct_{param_name}"
                    
                    # Add to inferred structures if new
                    if struct_name not in inferred_structures:
                        inferred_structures[struct_name] = {
                            "name": struct_name,
                            "fields": [],
                            "size": 0,
                            "source": "inferred"
                        }
                    
                    # Add the field if it's new
                    struct_info = inferred_structures[struct_name]
                    if not any(field["name"] == field_name for field in struct_info["fields"]):
                        struct_info["fields"].append({
                            "name": field_name,
                            "type": "unknown",
                            "is_array": False
                        })
                        
    def _infer_field_types(
        self, 
        decompiled_code: DecompiledCode,
        static_analysis: StaticAnalysisResults,
        structures: Dict[str, Dict[str, Any]]
    ) -> None:
        """
        Infer field types based on usage patterns.
        
        Args:
            decompiled_code: Decompiled code to analyze
            static_analysis: Results from static analysis
            structures: Dictionary mapping structure names to structure information
        """
        for struct_name, struct_info in structures.items():
            if struct_info["source"] == "decompiler":
                # Skip structures with known types
                continue
                
            for field_idx, field in enumerate(struct_info["fields"]):
                if field["type"] != "unknown":
                    continue
                    
                # Try to infer type from usage
                inferred_type = self._infer_field_type(
                    struct_name, 
                    field["name"], 
                    decompiled_code, 
                    static_analysis
                )
                
                if inferred_type:
                    structures[struct_name]["fields"][field_idx]["type"] = inferred_type
    
    def _infer_field_type(
        self,
        struct_name: str,
        field_name: str,
        decompiled_code: DecompiledCode,
        static_analysis: StaticAnalysisResults
    ) -> str:
        """
        Infer the type of a structure field based on usage patterns.
        
        Args:
            struct_name: Name of the structure
            field_name: Name of the field
            decompiled_code: Decompiled code to analyze
            static_analysis: Results from static analysis
            
        Returns:
            Inferred type, or "unknown" if the type could not be inferred
        """
        # For simplicity, we'll use some common naming conventions
        
        # Number-related field names often indicate numeric types
        if re.search(r"(count|size|length|index|num|id|age|year|month|day)", field_name, re.I):
            return "int"
            
        # Fields containing "name" are often strings
        if "name" in field_name.lower():
            return "char*"
            
        # Fields with "ptr" or "pointer" are often pointers
        if re.search(r"(ptr|pointer)", field_name, re.I):
            return "void*"
            
        # Fields with "flag" or "bool" are often booleans
        if re.search(r"(flag|bool|enabled|active)", field_name, re.I):
            return "bool"
            
        # Fields with "data" might be arrays or pointers
        if "data" in field_name.lower():
            return "void*"
            
        return "unknown"
