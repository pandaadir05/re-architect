#!/usr/bin/env python3
"""
Syntax and import checker script for RE-Architect CI/CD pipeline.

This script performs comprehensive syntax and import validation to prevent
CI/CD failures due to syntax errors or undefined names.
"""

import ast
import glob
import sys
import subprocess
from pathlib import Path

def check_python_syntax():
    """Check Python syntax for all Python files in the project."""
    print("Checking Python syntax...")
    
    python_files = (
        glob.glob('src/**/*.py', recursive=True) +
        glob.glob('tests/**/*.py', recursive=True) +
        ['main.py']
    )
    
    errors = []
    for file_path in python_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            ast.parse(content)
            print(f"✓ {file_path}")
        except SyntaxError as e:
            errors.append(f"Syntax error in {file_path}: {e}")
            print(f"✗ {file_path}: {e}")
        except Exception as e:
            errors.append(f"Error reading {file_path}: {e}")
            print(f"✗ {file_path}: {e}")
    
    return errors

def check_undefined_names():
    """Check for undefined names using flake8."""
    print("\nChecking for undefined names...")
    
    try:
        result = subprocess.run([
            sys.executable, '-m', 'flake8', 
            '--select=F821',  # undefined name errors
            'src/', 'tests/', 'main.py'
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✓ No undefined names found")
            return []
        else:
            errors = result.stdout.strip().split('\n') if result.stdout.strip() else []
            for error in errors:
                print(f"✗ {error}")
            return errors
            
    except FileNotFoundError:
        print("Warning: flake8 not found, skipping undefined name check")
        return []

def check_critical_imports():
    """Check that critical optional imports are properly handled."""
    print("\nChecking critical import patterns...")
    
    critical_patterns = {
        'angr': 'src/unpacking/symbolic_unpacker.py',
        'claripy': 'src/unpacking/symbolic_unpacker.py',
        'capstone': 'src/analysis/enhanced_static_analyzer.py',
        'lief': 'src/core/binary_loader.py'
    }
    
    errors = []
    for import_name, expected_file in critical_patterns.items():
        if Path(expected_file).exists():
            with open(expected_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check if the import is handled properly (either imported at top level or in try/except)
            if f'import {import_name}' in content:
                if 'try:' in content and 'except ImportError:' in content:
                    print(f"✓ {import_name} properly handled in {expected_file}")
                elif f'{import_name.upper()}_AVAILABLE' in content:
                    print(f"✓ {import_name} properly handled with availability flag in {expected_file}")
                else:
                    errors.append(f"Import {import_name} in {expected_file} may not be properly handled")
                    print(f"? {import_name} in {expected_file} - verify error handling")
    
    return errors

def main():
    """Run all checks and report results."""
    print("=" * 60)
    print("RE-Architect Syntax and Import Checker")
    print("=" * 60)
    
    all_errors = []
    
    # Run all checks
    all_errors.extend(check_python_syntax())
    all_errors.extend(check_undefined_names())
    all_errors.extend(check_critical_imports())
    
    print("\n" + "=" * 60)
    if all_errors:
        print(f"❌ {len(all_errors)} issue(s) found:")
        for error in all_errors:
            print(f"  - {error}")
        sys.exit(1)
    else:
        print("✅ All checks passed! The codebase is ready for CI/CD.")
        sys.exit(0)

if __name__ == '__main__':
    main()