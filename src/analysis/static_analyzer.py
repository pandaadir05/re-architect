"""
Static analyzer module for RE-Architect.

This module performs static analysis on decompiled code to extract
function information and dependencies.
"""

import logging
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple, Any

from src.core.config import Config
from src.decompilers.base_decompiler import DecompiledCode

logger = logging.getLogger("re-architect.analysis.static")

@dataclass
class FunctionInfo:
    """Information about a function extracted from static analysis."""
    address: int
    name: str
    code: str
    signature: str
    parameters: List[Dict[str, Any]]
    return_type: str
    calls: List[Dict[str, Any]]
    called_by: List[int]
    complexity: float
    size: int
    is_library: bool
    has_loops: bool
    has_switch: bool
    variables: List[Dict[str, Any]]
    basic_blocks: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "address": self.address,
            "name": self.name,
            "code": self.code,
            "signature": self.signature,
            "parameters": self.parameters,
            "return_type": self.return_type,
            "calls": self.calls,
            "called_by": self.called_by,
            "complexity": self.complexity,
            "size": self.size,
            "is_library": self.is_library,
            "has_loops": self.has_loops,
            "has_switch": self.has_switch,
            "variables": self.variables,
            "basic_blocks": self.basic_blocks
        }

@dataclass
class StaticAnalysisResults:
    """Results from static analysis of decompiled code."""
    functions: Dict[int, Dict[str, Any]]
    call_graph: Dict[int, Set[int]]
    reverse_call_graph: Dict[int, Set[int]]
    
    @property
    def function_count(self) -> int:
        """Get the number of analyzed functions."""
        return len(self.functions)

class StaticAnalyzer:
    """
    Static analyzer for RE-Architect.
    
    This class performs static analysis on decompiled code to extract
    function information, detect patterns, and build a call graph.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the static analyzer.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.depth = self.config.get("analysis.static.function_analysis_depth", "medium")
        
    def analyze(self, decompiled_code: DecompiledCode) -> StaticAnalysisResults:
        """
        Analyze decompiled code to extract information.
        
        Args:
            decompiled_code: Decompiled code to analyze
            
        Returns:
            StaticAnalysisResults object containing analysis results
        """
        logger.info("Starting static analysis")
        
        # Extract information about each function
        functions = {}
        for addr, code in decompiled_code.functions.items():
            name = decompiled_code.function_names.get(addr, f"func_{addr:x}")
            metadata = decompiled_code.function_metadata.get(addr, {})
            
            # Analyze the function
            func_info = self._analyze_function(addr, name, code, metadata)
            functions[addr] = func_info.to_dict()
        
        logger.info(f"Analyzed {len(functions)} functions")
        
        # Build call graph
        call_graph, reverse_call_graph = self._build_call_graph(functions)
        
        # Update called_by information
        for addr, calls in reverse_call_graph.items():
            if addr in functions:
                functions[addr]["called_by"] = list(calls)
        
        return StaticAnalysisResults(
            functions=functions,
            call_graph=call_graph,
            reverse_call_graph=reverse_call_graph
        )
    
    def _analyze_function(
        self,
        address: int,
        name: str,
        code: str,
        metadata: Dict[str, Any]
    ) -> FunctionInfo:
        """
        Analyze a single function.
        
        Args:
            address: Function address
            name: Function name
            code: Decompiled function code
            metadata: Additional function metadata
            
        Returns:
            FunctionInfo object containing analysis results
        """
        logger.debug(f"Analyzing function {name} at 0x{address:x}")
        
        # Extract signature
        signature = metadata.get("signature", "")
        
        # Get parameters and return type
        parameters = metadata.get("parameters", [])
        return_type = metadata.get("returnType", "")
        
        # Get calls
        calls = metadata.get("calls", [])
        
        # Initially empty called_by list (will be populated later)
        called_by = []
        
        # Estimate size by counting lines
        size = len(code.splitlines())
        
        # Check if it's a library function
        is_library = self._is_library_function(name)
        
        # Detect loops
        has_loops = self._has_loops(code)
        
        # Detect switch statements
        has_switch = self._has_switch(code)
        
        # Extract variables
        variables = self._extract_variables(code)
        
        # Estimate number of basic blocks
        basic_blocks = self._estimate_basic_blocks(code)
        
        # Calculate cyclomatic complexity
        complexity = self._calculate_complexity(code)
        
        return FunctionInfo(
            address=address,
            name=name,
            code=code,
            signature=signature,
            parameters=parameters,
            return_type=return_type,
            calls=calls,
            called_by=called_by,
            complexity=complexity,
            size=size,
            is_library=is_library,
            has_loops=has_loops,
            has_switch=has_switch,
            variables=variables,
            basic_blocks=basic_blocks
        )
    
    def _is_library_function(self, name: str) -> bool:
        """
        Check if a function is likely a standard library function.
        
        Args:
            name: Function name
            
        Returns:
            True if the function is likely a standard library function
        """
        # Common library function prefixes
        lib_prefixes = ["std::", "str", "mem", "print", "malloc", "free", "calloc", "realloc"]
        
        # Common library functions
        lib_functions = [
            "printf", "sprintf", "scanf", "sscanf", "fprintf", "fscanf",
            "malloc", "calloc", "realloc", "free",
            "strcpy", "strncpy", "strcmp", "strncmp", "strcat", "strncat",
            "memcpy", "memmove", "memset", "memcmp",
            "fopen", "fclose", "fread", "fwrite", "fseek",
            "atoi", "atof", "atol", "strtol", "strtod",
            "exit", "abort", "assert"
        ]
        
        # Check for exact match
        if name in lib_functions:
            return True
        
        # Check for prefix match
        for prefix in lib_prefixes:
            if name.startswith(prefix):
                return True
        
        return False
    
    def _has_loops(self, code: str) -> bool:
        """
        Check if a function contains loops.
        
        Args:
            code: Decompiled function code
            
        Returns:
            True if the function contains loops
        """
        # Look for common loop keywords
        loop_keywords = ["for", "while", "do"]
        
        for keyword in loop_keywords:
            pattern = fr"\b{keyword}\s*\("
            if re.search(pattern, code):
                return True
        
        return False
    
    def _has_switch(self, code: str) -> bool:
        """
        Check if a function contains switch statements.
        
        Args:
            code: Decompiled function code
            
        Returns:
            True if the function contains switch statements
        """
        return "switch" in code
    
    def _extract_variables(self, code: str) -> List[Dict[str, Any]]:
        """
        Extract variable declarations from function code.
        
        Args:
            code: Decompiled function code
            
        Returns:
            List of dictionaries containing variable information
        """
        variables = []
        
        # Simple regex to match variable declarations
        # This is a basic implementation and may miss complex declarations
        var_pattern = r"(\w+)\s+(\w+)\s*(?:=\s*([^;]+))?\s*;"
        
        for match in re.finditer(var_pattern, code):
            var_type = match.group(1)
            var_name = match.group(2)
            initial_value = match.group(3)
            
            variables.append({
                "name": var_name,
                "type": var_type,
                "initial_value": initial_value
            })
        
        return variables
    
    def _estimate_basic_blocks(self, code: str) -> int:
        """
        Estimate the number of basic blocks in a function.
        
        Args:
            code: Decompiled function code
            
        Returns:
            Estimated number of basic blocks
        """
        # This is a simple heuristic: count statements that likely start new blocks
        block_starters = [
            "{", "}", "if", "else", "for", "while", "do", "switch", "case", "default", "return"
        ]
        
        count = 1  # Start with one block
        
        for starter in block_starters:
            pattern = fr"\b{starter}\b"
            count += len(re.findall(pattern, code))
        
        return count
    
    def _calculate_complexity(self, code: str) -> float:
        """
        Calculate cyclomatic complexity of a function.
        
        Args:
            code: Decompiled function code
            
        Returns:
            Estimated cyclomatic complexity
        """
        # McCabe's cyclomatic complexity is: E - N + 2P
        # Where E is the number of edges, N is the number of nodes, and P is the number of connected components
        # For a simple approximation, we'll count decision points and add 1
        
        decision_points = [
            r"\bif\s*\(",
            r"\bfor\s*\(",
            r"\bwhile\s*\(",
            r"\bcase\s+",
            r"\b&&\b",
            r"\b\|\|\b",
            r"\?",  # Ternary operator
            r"\bcatch\s*\("
        ]
        
        complexity = 1  # Base complexity
        
        for pattern in decision_points:
            complexity += len(re.findall(pattern, code))
        
        return complexity
    
    def _build_call_graph(
        self,
        functions: Dict[int, Dict[str, Any]]
    ) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
        """
        Build a call graph from function information.
        
        Args:
            functions: Dictionary mapping function addresses to function information
            
        Returns:
            Tuple containing forward and reverse call graphs
        """
        # Forward call graph: function -> called functions
        call_graph = {}
        
        # Reverse call graph: function -> functions that call it
        reverse_call_graph = {}
        
        # Initialize graphs
        for addr in functions:
            call_graph[addr] = set()
            reverse_call_graph[addr] = set()
        
        # Build the graphs
        for addr, func_info in functions.items():
            # Process each call made by this function
            for call in func_info.get("calls", []):
                to_addr_str = call.get("toAddress", "")
                
                # Extract address from the string (e.g., "00401234" from "ram:00401234")
                match = re.search(r"([0-9a-fA-F]+)$", to_addr_str)
                if match:
                    to_addr = int(match.group(1), 16)
                    
                    # Add to forward graph
                    if addr in call_graph:
                        call_graph[addr].add(to_addr)
                    
                    # Add to reverse graph
                    if to_addr in reverse_call_graph:
                        reverse_call_graph[to_addr].add(addr)
        
        return call_graph, reverse_call_graph
