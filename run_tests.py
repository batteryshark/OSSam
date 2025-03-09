#!/usr/bin/env python3
"""
Run all tests in the tests directory.
"""
import os
import sys
import importlib
import unittest
from pathlib import Path

# Add the parent directory to sys.path to make imports work
sys.path.insert(0, os.path.abspath('.'))

def run_all_tests():
    """
    Discover and run all tests in the tests directory.
    """
    # Get all Python files in the tests directory
    test_dir = Path('tests')
    test_files = [f for f in test_dir.glob('test_*.py') if f.is_file()]
    
    print(f"Found {len(test_files)} test files")
    
    # Create a test suite
    suite = unittest.TestSuite()
    
    # For each test file, try to import and add tests
    for test_file in test_files:
        module_name = f"tests.{test_file.stem}"
        try:
            print(f"Importing {module_name}...")
            module = importlib.import_module(module_name)
            
            # If the module has a 'test_*' function, call it
            for name in dir(module):
                if name.startswith('test_'):
                    func = getattr(module, name)
                    if callable(func):
                        print(f"Running {module_name}.{name}")
                        try:
                            func()
                            print(f"✓ {module_name}.{name} passed")
                        except Exception as e:
                            print(f"✗ {module_name}.{name} failed: {str(e)}")
        except Exception as e:
            print(f"Failed to import {module_name}: {str(e)}")
    
    print("Test run complete")

if __name__ == "__main__":
    run_all_tests() 