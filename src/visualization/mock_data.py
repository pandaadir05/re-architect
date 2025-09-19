"""
Mock data generator for testing the visualization server.

This module provides utility functions to generate mock data for testing
the visualization server.
"""

import json
import os
import random
from pathlib import Path
from typing import Dict, Any, List, Optional

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
        
    complexity = random.choice(["Low", "Medium", "High"])
    confidence = random.uniform(0.5, 1.0)
    
    return {
        "id": str(func_id),
        "name": name,
        "address": hex(0x400000 + func_id * 0x100),
        "size": random.randint(20, 500),
        "complexity": complexity,
        "decompiled_code": f"// Decompiled function {name}\nint {name}(int arg1, void* arg2) {{\n    // Function implementation\n    int local_var = arg1 + 10;\n    return *((int*)arg2) + local_var;\n}}",
        "summary": f"This function takes an integer and a pointer as arguments. It adds 10 to the integer and then adds the dereferenced pointer value. Complexity: {complexity}",
        "parameters": [
            {"name": "arg1", "type": "int", "description": "Integer input value"},
            {"name": "arg2", "type": "void*", "description": "Pointer to integer value to be read"}
        ],
        "returns": {"type": "int", "description": "Sum of arg1+10 and dereferenced arg2"},
        "calls": [f"func_{random.randint(1, 100):04x}" for _ in range(random.randint(0, 5))],
        "called_by": [f"func_{random.randint(1, 100):04x}" for _ in range(random.randint(0, 3))],
        "confidence": confidence,
        "vulnerabilities": [] if random.random() > 0.2 else [
            {
                "type": random.choice(["Buffer Overflow", "Use After Free", "NULL Dereference"]),
                "severity": random.choice(["Low", "Medium", "High", "Critical"]),
                "description": "Potential vulnerability detected in function",
                "location": {"line": random.randint(1, 10), "column": random.randint(1, 50)}
            }
        ]
    }

def generate_data_structure_mock(struct_id: int, name: str = None) -> Dict[str, Any]:
    """
    Generate mock data for a data structure.
    
    Args:
        struct_id: Structure ID
        name: Structure name (optional)
        
    Returns:
        Dict with mock data structure
    """
    if name is None:
        name = f"struct_{struct_id:04x}"
        
    field_types = ["int", "char", "float", "double", "void*", "char*", "long", "unsigned int"]
    
    return {
        "id": str(struct_id),
        "name": name,
        "size": random.randint(4, 128),
        "fields": [
            {
                "name": f"field_{i}",
                "type": random.choice(field_types),
                "offset": i * random.choice([1, 2, 4, 8]),
                "size": random.choice([1, 2, 4, 8]),
                "description": f"Field {i} of structure {name}"
            }
            for i in range(random.randint(1, 10))
        ],
        "description": f"Structure {name} with multiple fields, likely used for {random.choice(['data storage', 'configuration', 'network packet', 'user interface'])}",
        "references": [f"func_{random.randint(1, 100):04x}" for _ in range(random.randint(0, 5))],
        "confidence": random.uniform(0.5, 1.0)
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
    for i in random.sample(range(1, num_functions + 1), num_functions // 3):
        test = generate_test_harness_mock(i, functions[str(i)]["name"])
        test_harnesses[str(i)] = test
    
    # Generate metadata
    metadata = {
        "file_path": binary_path,
        "file_format": random.choice(["ELF", "PE", "Mach-O"]),
        "architecture": random.choice(["x86", "x86_64", "ARM", "MIPS"]),
        "entry_point": hex(0x400000),
        "size": random.randint(10000, 10000000),
        "sections": [
            {"name": ".text", "address": "0x400000", "size": random.randint(1000, 100000)},
            {"name": ".data", "address": "0x600000", "size": random.randint(1000, 10000)},
            {"name": ".rodata", "address": "0x700000", "size": random.randint(1000, 10000)},
            {"name": ".bss", "address": "0x800000", "size": random.randint(1000, 10000)}
        ],
        "symbols": random.randint(100, 5000),
        "imports": [
            {"name": f"lib{name}.so", "functions": random.randint(5, 50)}
            for name in ["c", "m", "pthread", "z", "ssl"]
        ],
        "timestamp": "2023-06-21T15:30:45Z"
    }
    
    # Generate performance metrics
    performance_metrics = {
        "loading_time": random.uniform(0.1, 2.0),
        "decompilation_time": random.uniform(5.0, 60.0),
        "analysis_time": random.uniform(10.0, 120.0),
        "summarization_time": random.uniform(30.0, 300.0),
        "test_generation_time": random.uniform(20.0, 200.0),
        "total_time": random.uniform(100.0, 600.0)
    }
    
    # Generate analyses
    analyses = {
        "static": {
            "executed": True,
            "findings": random.randint(10, 100),
            "execution_time": random.uniform(5.0, 50.0)
        },
        "dynamic": {
            "executed": random.choice([True, False]),
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
        "performance_metrics": performance_metrics,
        "analyses": analyses
    }
    
    return results

def save_mock_results(results: Dict[str, Any], output_path: str) -> None:
    """
    Save mock results to a JSON file.
    
    Args:
        results: Mock results to save
        output_path: Path to save the results to
    """
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Mock data saved to {output_path}")

if __name__ == "__main__":
    # Generate and save mock results
    results = generate_mock_analysis_results(
        num_functions=100,
        num_data_structures=25,
        binary_path="/samples/example.exe"
    )
    
    save_mock_results(results, "results/mock_analysis.json")
