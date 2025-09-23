"""
Mock data generation for RE-Architect visualization and testing.

This module provides functions to generate realistic mock data for 
testing the visualization components and development purposes.
"""

import random
import time
from typing import Dict, List, Any

def generate_function_mock(func_id: int, name: str = None) -> Dict[str, Any]:
    """
    Generate mock data for a function.
    
    Args:
        func_id: Function ID
        name: Function name (optional)
        
    Returns:
        Dict with mock function data
    """
    if name is None:
        name = f"func_{func_id:04x}"
        
    return {
        "id": str(func_id),
        "name": name,
        "address": 0x400000 + func_id * 0x100,
        "size": random.randint(16, 512),
        "summary": f"Function {name} performs computation and returns a result",
        "complexity": round(random.uniform(1.0, 10.0), 1),
        "has_loops": random.choice([True, False]),
        "parameters": [
            {"name": "arg1", "type": "int", "description": "First argument"},
            {"name": "arg2", "type": "void*", "description": "Pointer argument"}
        ],
        "return_type": random.choice(["int", "void", "char*", "float"]),
        "call_count": random.randint(0, 20),
        "decompiled_code": f"// Decompiled code for {name}\nint {name}(int arg1, void* arg2) {{\n    // Function implementation\n    return 0;\n}}",
        "confidence": random.uniform(0.7, 1.0)
    }

def generate_data_structure_mock(struct_id: int, name: str = None) -> Dict[str, Any]:
    """
    Generate mock data for a data structure.
    
    Args:
        struct_id: Structure ID  
        name: Structure name (optional)
        
    Returns:
        Dict with mock data structure data
    """
    if name is None:
        name = f"struct_{struct_id}"
        
    return {
        "id": str(struct_id),
        "name": name,
        "size": random.choice([8, 16, 32, 64, 128]),
        "alignment": random.choice([4, 8]),
        "fields": [
            {"name": "field1", "type": "int", "offset": 0, "size": 4},
            {"name": "field2", "type": "char*", "offset": 8, "size": 8},
            {"name": "field3", "type": "float", "offset": 16, "size": 4}
        ],
        "usage_count": random.randint(1, 10),
        "confidence": random.uniform(0.6, 0.95)
    }

def generate_test_harness_mock(func_id: int, name: str = None) -> Dict[str, Any]:
    """
    Generate mock data for a test harness.
    
    Args:
        func_id: Function ID
        name: Function name (optional)
        
    Returns:
        Dict with mock test harness data
    """
    if name is None:
        name = f"func_{func_id:04x}"
        
    return {
        "function_id": str(func_id),
        "function_name": name,
        "test_code": f"""// Test harness for {name}
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

// External declaration of the target function
extern int {name}(int arg1, void* arg2);

int main() {{
    // Prepare test data
    int test_value = 42;
    int* ptr_value = (int*)malloc(sizeof(int));
    *ptr_value = 100;
    
    // Call the function
    int result = {name}(test_value, ptr_value);
    
    // Check the result
    printf("Result: %d\\n", result);
    assert(result == (test_value + 10 + *ptr_value));
    
    // Clean up
    free(ptr_value);
    return 0;
}}""",
        "test_cases": [
            {
                "inputs": {"arg1": 42, "arg2": {"type": "pointer", "value": 100}},
                "expected_output": 152,
                "description": "Standard test case"
            },
            {
                "inputs": {"arg1": 0, "arg2": {"type": "pointer", "value": 50}},
                "expected_output": 60,
                "description": "Zero input test case"
            }
        ],
        "coverage": random.uniform(0.5, 1.0),
        "execution_result": random.choice(["Success", "Failure", "Timeout", "Crash"]),
        "confidence": random.uniform(0.5, 1.0)
    }

def generate_mock_analysis_results(
    num_functions: int = 50,
    num_data_structures: int = 15,
    binary_path: str = "/path/to/example.exe"
) -> Dict[str, Any]:
    """
    Generate complete mock analysis results.
    
    Args:
        num_functions: Number of functions to generate
        num_data_structures: Number of data structures to generate
        binary_path: Path to the binary (used in metadata)
        
    Returns:
        Dict with complete mock analysis results
    """
    # Generate functions
    functions = {}
    for i in range(1, num_functions + 1):
        func = generate_function_mock(i)
        functions[str(i)] = func
    
    # Generate data structures
    data_structures = {}
    for i in range(1, num_data_structures + 1):
        struct = generate_data_structure_mock(i)
        data_structures[str(i)] = struct
    
    # Generate test harnesses for subset of functions
    test_harnesses = {}
    for i in range(1, min(10, num_functions) + 1):
        test = generate_test_harness_mock(i)
        test_harnesses[str(i)] = test
    
    # Generate metadata
    metadata = {
        "binary_path": binary_path,
        "analysis_start_time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "analysis_duration": random.uniform(30, 300),  # seconds
        "total_functions": num_functions,
        "analyzed_functions": num_functions,
        "total_data_structures": num_data_structures,
        "binary_size": random.randint(1024, 1024*1024*10),  # bytes
        "architecture": random.choice(["x86_64", "x86", "arm64", "arm"]),
        "format": random.choice(["PE", "ELF", "Mach-O"]),
        "compiler": random.choice(["gcc", "clang", "msvc", "unknown"]),
        "analysis_settings": {
            "decompiler": "ghidra",
            "static_analysis": True,
            "dynamic_analysis": False,
            "llm_enabled": True
        }
    }
    
    # Analysis statistics
    stats = {
        "static": {
            "executed": True,
            "findings": random.randint(0, 50) if random.choice([True, False]) else 0,
            "execution_time": random.uniform(10.0, 100.0) if random.choice([True, False]) else 0.0
        },
        "symbolic": {
            "executed": random.choice([True, False]),
            "findings": random.randint(0, 30) if random.choice([True, False]) else 0,
            "execution_time": random.uniform(20.0, 200.0) if random.choice([True, False]) else 0.0
        }
    }
    
    # Combine all results
    results = {
        "metadata": metadata,
        "functions": functions,
        "data_structures": data_structures,
        "test_harnesses": test_harnesses,
        "statistics": stats
    }
    
    return results