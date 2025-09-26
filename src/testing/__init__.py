"""
Advanced testing infrastructure for RE-Architect.

This module provides comprehensive testing capabilities including unit tests,
integration tests, property-based testing, fuzzing, and benchmark tests.
"""

import asyncio
import functools
import hypothesis
import hypothesis.strategies as st
import pytest
import pytest_benchmark
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Type, Union
from unittest.mock import Mock, patch, MagicMock
import concurrent.futures
import threading

# Import testing utilities
try:
    import hypothesis
    from hypothesis import given, strategies as st
    HYPOTHESIS_AVAILABLE = True
except ImportError:
    HYPOTHESIS_AVAILABLE = False

try:
    import pytest_benchmark
    BENCHMARK_AVAILABLE = True
except ImportError:
    BENCHMARK_AVAILABLE = False

# Import fuzzing capabilities
try:
    import atheris
    FUZZING_AVAILABLE = True
except ImportError:
    FUZZING_AVAILABLE = False


class TestDataGenerator:
    """Generate test data for various RE-Architect components."""
    
    @staticmethod
    def generate_binary_data(size: int = 1024) -> bytes:
        """Generate random binary data for testing."""
        import random
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    @staticmethod
    def generate_pe_header() -> bytes:
        """Generate a minimal valid PE header."""
        # DOS header
        dos_header = b'MZ' + b'\x00' * 58 + b'\x80\x00\x00\x00'
        
        # PE signature
        pe_sig = b'PE\x00\x00'
        
        # File header
        file_header = (
            b'\x4c\x01'  # Machine (i386)
            b'\x03\x00'  # NumberOfSections
            b'\x00\x00\x00\x00'  # TimeDateStamp
            b'\x00\x00\x00\x00'  # PointerToSymbolTable
            b'\x00\x00\x00\x00'  # NumberOfSymbols
            b'\xe0\x00'  # SizeOfOptionalHeader
            b'\x0f\x01'  # Characteristics
        )
        
        # Optional header (minimal)
        opt_header = b'\x0b\x01' + b'\x00' * 222  # Magic + padding
        
        return dos_header + pe_sig + file_header + opt_header
    
    @staticmethod
    def generate_elf_header() -> bytes:
        """Generate a minimal valid ELF header."""
        return (
            b'\x7fELF'  # ELF magic
            b'\x01'     # 32-bit
            b'\x01'     # Little endian
            b'\x01'     # ELF version
            b'\x00' * 9  # Padding
            b'\x02\x00'  # Executable file
            b'\x03\x00'  # i386
            b'\x01\x00\x00\x00'  # ELF version
            b'\x00' * 36  # Rest of header
        )
    
    @staticmethod
    def create_test_binary(format_type: str = "pe", size: int = 2048) -> bytes:
        """Create a test binary with specified format."""
        if format_type.lower() == "pe":
            header = TestDataGenerator.generate_pe_header()
        elif format_type.lower() == "elf":
            header = TestDataGenerator.generate_elf_header()
        else:
            header = b'\x00' * 64  # Generic header
        
        # Pad with random data
        remaining_size = max(0, size - len(header))
        padding = TestDataGenerator.generate_binary_data(remaining_size)
        
        return header + padding


class MockFactory:
    """Factory for creating mock objects and test doubles."""
    
    @staticmethod
    def create_mock_binary_info(
        path: str = "/test/binary.exe",
        architecture: str = "x86_64",
        format_type: str = "PE",
        entry_point: int = 0x401000
    ) -> Mock:
        """Create a mock BinaryInfo object."""
        mock_info = Mock()
        mock_info.path = Path(path)
        mock_info.architecture = architecture
        mock_info.format = format_type
        mock_info.entry_point = entry_point
        mock_info.size = 2048
        mock_info.compiler = "MSVC"
        return mock_info
    
    @staticmethod
    def create_mock_decompiled_code(
        functions: Optional[Dict[str, str]] = None
    ) -> Mock:
        """Create a mock DecompiledCode object."""
        if functions is None:
            functions = {
                "main": "int main() { return 0; }",
                "func1": "void func1() { printf(\"Hello\"); }"
            }
        
        mock_code = Mock()
        mock_code.functions = functions
        mock_code.success = True
        mock_code.metadata = {"decompiler": "mock", "version": "1.0"}
        return mock_code
    
    @staticmethod
    def create_mock_config(overrides: Optional[Dict[str, Any]] = None) -> Mock:
        """Create a mock Config object."""
        config = Mock()
        config.get = Mock(side_effect=lambda key, default=None: overrides.get(key, default) if overrides else default)
        config.use_llm = False
        return config


class TestFixtures:
    """Common test fixtures and utilities."""
    
    @staticmethod
    def create_temp_binary(content: Optional[bytes] = None) -> Path:
        """Create a temporary binary file for testing."""
        if content is None:
            content = TestDataGenerator.create_test_binary()
        
        temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.exe')
        temp_file.write(content)
        temp_file.close()
        
        return Path(temp_file.name)
    
    @staticmethod
    def create_temp_directory() -> Path:
        """Create a temporary directory for testing."""
        temp_dir = tempfile.mkdtemp(prefix='re_architect_test_')
        return Path(temp_dir)


class AsyncTestCase(unittest.TestCase):
    """Base class for async test cases."""
    
    def setUp(self) -> None:
        """Set up async test environment."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
    
    def tearDown(self) -> None:
        """Clean up async test environment."""
        self.loop.close()
    
    def run_async(self, coro: Any) -> Any:
        """Run an async coroutine in the test loop."""
        return self.loop.run_until_complete(coro)


def async_test(func: Callable) -> Callable:
    """Decorator for async test functions."""
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(func(self, *args, **kwargs))
        finally:
            loop.close()
    return wrapper


class PerformanceTestCase(unittest.TestCase):
    """Base class for performance tests."""
    
    def setUp(self) -> None:
        """Set up performance monitoring."""
        self.performance_data = []
    
    def measure_performance(self, func: Callable, *args, **kwargs) -> Dict[str, float]:
        """Measure function performance."""
        import psutil
        
        process = psutil.Process()
        start_time = time.time()
        start_memory = process.memory_info().rss / 1024 / 1024
        
        try:
            result = func(*args, **kwargs)
        finally:
            end_time = time.time()
            end_memory = process.memory_info().rss / 1024 / 1024
        
        metrics = {
            'execution_time': end_time - start_time,
            'memory_delta': end_memory - start_memory,
            'peak_memory': end_memory
        }
        
        self.performance_data.append(metrics)
        return metrics
    
    def assert_performance(self, 
                          max_time: Optional[float] = None,
                          max_memory_mb: Optional[float] = None) -> None:
        """Assert performance constraints."""
        if not self.performance_data:
            self.fail("No performance data collected")
        
        latest_metrics = self.performance_data[-1]
        
        if max_time is not None:
            self.assertLessEqual(
                latest_metrics['execution_time'], 
                max_time,
                f"Execution time {latest_metrics['execution_time']:.3f}s exceeds limit {max_time}s"
            )
        
        if max_memory_mb is not None:
            self.assertLessEqual(
                latest_metrics['memory_delta'],
                max_memory_mb,
                f"Memory usage {latest_metrics['memory_delta']:.1f}MB exceeds limit {max_memory_mb}MB"
            )


class PropertyBasedTest:
    """Property-based testing utilities."""
    
    @staticmethod
    def binary_path_strategy() -> Any:
        """Hypothesis strategy for generating binary paths."""
        if not HYPOTHESIS_AVAILABLE:
            return None
        
        return st.builds(
            Path,
            st.text(
                alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd')),
                min_size=1,
                max_size=50
            ).map(lambda x: f"/test/{x}.exe")
        )
    
    @staticmethod
    def binary_data_strategy(min_size: int = 64, max_size: int = 4096) -> Any:
        """Hypothesis strategy for generating binary data."""
        if not HYPOTHESIS_AVAILABLE:
            return None
        
        return st.binary(min_size=min_size, max_size=max_size)
    
    @staticmethod
    def config_data_strategy() -> Any:
        """Hypothesis strategy for generating config data."""
        if not HYPOTHESIS_AVAILABLE:
            return None
        
        return st.dictionaries(
            keys=st.text(min_size=1, max_size=20),
            values=st.one_of(
                st.text(),
                st.integers(),
                st.booleans(),
                st.floats(allow_nan=False, allow_infinity=False)
            )
        )


class FuzzingFramework:
    """Fuzzing framework for RE-Architect components."""
    
    def __init__(self):
        self.corpus_dir = Path("fuzzing_corpus")
        self.corpus_dir.mkdir(exist_ok=True)
    
    def create_binary_corpus(self, count: int = 100) -> List[Path]:
        """Create a corpus of binary files for fuzzing."""
        corpus_files = []
        
        formats = ["pe", "elf"]
        sizes = [512, 1024, 2048, 4096, 8192]
        
        for i in range(count):
            format_type = formats[i % len(formats)]
            size = sizes[i % len(sizes)]
            
            binary_data = TestDataGenerator.create_test_binary(format_type, size)
            
            corpus_file = self.corpus_dir / f"test_binary_{i:03d}_{format_type}.bin"
            with open(corpus_file, 'wb') as f:
                f.write(binary_data)
            
            corpus_files.append(corpus_file)
        
        return corpus_files
    
    def fuzz_binary_loader(self, iterations: int = 1000) -> None:
        """Fuzz the binary loader component."""
        if not FUZZING_AVAILABLE:
            print("Atheris not available, skipping fuzzing")
            return
        
        def fuzz_target(data: bytes) -> None:
            """Fuzzing target for binary loader."""
            try:
                # Create temporary file with fuzzing data
                temp_file = tempfile.NamedTemporaryFile(delete=False)
                temp_file.write(data)
                temp_file.close()
                
                # Test binary loading
                from src.core.binary_loader import BinaryLoader
                loader = BinaryLoader()
                
                try:
                    loader.load(Path(temp_file.name))
                except Exception:
                    # Expected for malformed binaries
                    pass
                
            finally:
                # Cleanup
                if 'temp_file' in locals():
                    Path(temp_file.name).unlink(missing_ok=True)
        
        # Run fuzzing
        atheris.Setup([], fuzz_target)
        atheris.Fuzz()


class TestReporter:
    """Advanced test reporting and metrics."""
    
    def __init__(self, output_dir: Path):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.test_results = []
        self.performance_data = []
    
    def add_test_result(self, 
                       test_name: str,
                       status: str,
                       duration: float,
                       error_message: Optional[str] = None) -> None:
        """Add a test result."""
        self.test_results.append({
            'test_name': test_name,
            'status': status,
            'duration': duration,
            'error_message': error_message,
            'timestamp': time.time()
        })
    
    def add_performance_data(self, 
                           test_name: str,
                           metrics: Dict[str, float]) -> None:
        """Add performance metrics."""
        self.performance_data.append({
            'test_name': test_name,
            'metrics': metrics,
            'timestamp': time.time()
        })
    
    def generate_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report."""
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['status'] == 'passed')
        failed_tests = sum(1 for result in self.test_results if result['status'] == 'failed')
        
        avg_duration = sum(result['duration'] for result in self.test_results) / total_tests if total_tests > 0 else 0
        
        return {
            'summary': {
                'total_tests': total_tests,
                'passed': passed_tests,
                'failed': failed_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                'average_duration': avg_duration
            },
            'test_results': self.test_results,
            'performance_data': self.performance_data,
            'generated_at': time.time()
        }
    
    def save_report(self, filename: str = "test_report.json") -> Path:
        """Save report to file."""
        import json
        
        report_path = self.output_dir / filename
        report = self.generate_report()
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return report_path


# Utility decorators
def skip_if_no_hypothesis(func: Callable) -> Callable:
    """Skip test if hypothesis is not available."""
    return unittest.skipIf(not HYPOTHESIS_AVAILABLE, "Hypothesis not available")(func)

def skip_if_no_benchmark(func: Callable) -> Callable:
    """Skip test if pytest-benchmark is not available."""
    return unittest.skipIf(not BENCHMARK_AVAILABLE, "pytest-benchmark not available")(func)

def requires_external_tool(tool_name: str) -> Callable:
    """Skip test if external tool is not available."""
    def decorator(func: Callable) -> Callable:
        # Check if tool is available
        import shutil
        available = shutil.which(tool_name) is not None
        return unittest.skipIf(not available, f"{tool_name} not available")(func)
    return decorator