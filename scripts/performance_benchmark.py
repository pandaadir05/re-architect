#!/usr/bin/env python3
"""
Performance benchmark runner for RE-Architect project.
This script runs comprehensive performance tests and generates detailed reports.
"""

import time
import psutil
import sys
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import subprocess
import tempfile
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class BenchmarkResult:
    """Result of a performance benchmark."""
    test_name: str
    duration: float
    memory_usage: Dict[str, float]
    cpu_usage: float
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class PerformanceBenchmark:
    """Comprehensive performance benchmark suite."""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.results: List[BenchmarkResult] = []
    
    def measure_system_resources(self) -> Dict[str, float]:
        """Measure current system resource usage."""
        process = psutil.Process()
        
        return {
            "memory_rss_mb": process.memory_info().rss / 1024 / 1024,
            "memory_vms_mb": process.memory_info().vms / 1024 / 1024,
            "memory_percent": process.memory_percent(),
            "cpu_percent": process.cpu_percent(interval=0.1),
            "num_threads": process.num_threads(),
            "num_fds": process.num_fds() if hasattr(process, 'num_fds') else 0
        }
    
    def benchmark_import_time(self) -> BenchmarkResult:
        """Benchmark module import times."""
        logger.info("Benchmarking module import times...")
        
        start_time = time.time()
        start_memory = self.measure_system_resources()
        
        try:
            # Test importing key modules
            modules_to_test = [
                'src.core.pipeline',
                'src.analysis.static_analyzer',
                'src.decompilers.decompiler_factory',
                'src.visualization.server',
                'src.llm.function_summarizer'
            ]
            
            import_times = {}
            for module in modules_to_test:
                module_start = time.time()
                try:
                    __import__(module)
                    import_times[module] = time.time() - module_start
                except ImportError as e:
                    import_times[module] = -1  # Mark as failed
                    logger.warning(f"Failed to import {module}: {e}")
            
            end_time = time.time()
            end_memory = self.measure_system_resources()
            
            return BenchmarkResult(
                test_name="import_performance",
                duration=end_time - start_time,
                memory_usage={
                    "start": start_memory,
                    "end": end_memory,
                    "delta_mb": end_memory["memory_rss_mb"] - start_memory["memory_rss_mb"]
                },
                cpu_usage=end_memory["cpu_percent"],
                success=True,
                metadata={"import_times": import_times}
            )
            
        except Exception as e:
            end_time = time.time()
            return BenchmarkResult(
                test_name="import_performance",
                duration=end_time - start_time,
                memory_usage=start_memory,
                cpu_usage=0,
                success=False,
                error_message=str(e)
            )
    
    def benchmark_file_operations(self) -> BenchmarkResult:
        """Benchmark file I/O operations."""
        logger.info("Benchmarking file operations...")
        
        start_time = time.time()
        start_memory = self.measure_system_resources()
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Test file creation
                test_files = []
                for i in range(100):
                    file_path = temp_path / f"test_file_{i}.txt"
                    with open(file_path, 'w') as f:
                        f.write(f"Test content {i} " * 100)
                    test_files.append(file_path)
                
                # Test file reading
                total_size = 0
                for file_path in test_files:
                    with open(file_path, 'r') as f:
                        content = f.read()
                        total_size += len(content)
                
                # Test file deletion
                for file_path in test_files:
                    file_path.unlink()
            
            end_time = time.time()
            end_memory = self.measure_system_resources()
            
            return BenchmarkResult(
                test_name="file_operations",
                duration=end_time - start_time,
                memory_usage={
                    "start": start_memory,
                    "end": end_memory,
                    "delta_mb": end_memory["memory_rss_mb"] - start_memory["memory_rss_mb"]
                },
                cpu_usage=end_memory["cpu_percent"],
                success=True,
                metadata={
                    "files_processed": len(test_files),
                    "total_bytes": total_size
                }
            )
            
        except Exception as e:
            end_time = time.time()
            return BenchmarkResult(
                test_name="file_operations",
                duration=end_time - start_time,
                memory_usage=start_memory,
                cpu_usage=0,
                success=False,
                error_message=str(e)
            )
    
    def benchmark_concurrent_operations(self) -> BenchmarkResult:
        """Benchmark concurrent processing capabilities."""
        logger.info("Benchmarking concurrent operations...")
        
        start_time = time.time()
        start_memory = self.measure_system_resources()
        
        try:
            def cpu_intensive_task(n: int) -> int:
                """CPU-intensive task for benchmarking."""
                total = 0
                for i in range(n * 1000):
                    total += i ** 2
                return total
            
            # Test thread pool performance
            thread_start = time.time()
            with ThreadPoolExecutor(max_workers=4) as executor:
                thread_futures = [executor.submit(cpu_intensive_task, 100) for _ in range(20)]
                thread_results = [f.result() for f in thread_futures]
            thread_duration = time.time() - thread_start
            
            # Test process pool performance
            process_start = time.time()
            with ProcessPoolExecutor(max_workers=2) as executor:
                process_futures = [executor.submit(cpu_intensive_task, 100) for _ in range(10)]
                process_results = [f.result() for f in process_futures]
            process_duration = time.time() - process_start
            
            end_time = time.time()
            end_memory = self.measure_system_resources()
            
            return BenchmarkResult(
                test_name="concurrent_operations",
                duration=end_time - start_time,
                memory_usage={
                    "start": start_memory,
                    "end": end_memory,
                    "delta_mb": end_memory["memory_rss_mb"] - start_memory["memory_rss_mb"]
                },
                cpu_usage=end_memory["cpu_percent"],
                success=True,
                metadata={
                    "thread_duration": thread_duration,
                    "process_duration": process_duration,
                    "thread_tasks": len(thread_results),
                    "process_tasks": len(process_results)
                }
            )
            
        except Exception as e:
            end_time = time.time()
            return BenchmarkResult(
                test_name="concurrent_operations",
                duration=end_time - start_time,
                memory_usage=start_memory,
                cpu_usage=0,
                success=False,
                error_message=str(e)
            )
    
    def benchmark_memory_allocation(self) -> BenchmarkResult:
        """Benchmark memory allocation and deallocation."""
        logger.info("Benchmarking memory operations...")
        
        start_time = time.time()
        start_memory = self.measure_system_resources()
        
        try:
            # Allocate various data structures
            large_list = []
            large_dict = {}
            
            # Test list operations
            for i in range(100000):
                large_list.append(f"item_{i}")
                if i % 2 == 0:
                    large_dict[f"key_{i}"] = f"value_{i}"
            
            # Test string operations
            large_string = ""
            for i in range(10000):
                large_string += f"segment_{i}_"
            
            # Force garbage collection and memory measurement
            import gc
            gc.collect()
            
            peak_memory = self.measure_system_resources()
            
            # Clean up
            del large_list
            del large_dict
            del large_string
            gc.collect()
            
            end_time = time.time()
            end_memory = self.measure_system_resources()
            
            return BenchmarkResult(
                test_name="memory_allocation",
                duration=end_time - start_time,
                memory_usage={
                    "start": start_memory,
                    "peak": peak_memory,
                    "end": end_memory,
                    "peak_delta_mb": peak_memory["memory_rss_mb"] - start_memory["memory_rss_mb"],
                    "final_delta_mb": end_memory["memory_rss_mb"] - start_memory["memory_rss_mb"]
                },
                cpu_usage=end_memory["cpu_percent"],
                success=True,
                metadata={
                    "allocations_performed": 110000,
                    "gc_collections": gc.get_count()
                }
            )
            
        except Exception as e:
            end_time = time.time()
            return BenchmarkResult(
                test_name="memory_allocation",
                duration=end_time - start_time,
                memory_usage=start_memory,
                cpu_usage=0,
                success=False,
                error_message=str(e)
            )
    
    def benchmark_algorithm_performance(self) -> BenchmarkResult:
        """Benchmark algorithm performance with different data sizes."""
        logger.info("Benchmarking algorithm performance...")
        
        start_time = time.time()
        start_memory = self.measure_system_resources()
        
        try:
            # Test sorting algorithms with different sizes
            import random
            
            sort_times = {}
            data_sizes = [1000, 5000, 10000, 25000]
            
            for size in data_sizes:
                # Generate random data
                data = [random.randint(1, 10000) for _ in range(size)]
                
                # Test built-in sort
                sort_start = time.time()
                sorted_data = sorted(data)
                sort_times[f"sort_{size}"] = time.time() - sort_start
                
                # Test list comprehension performance
                comp_start = time.time()
                filtered_data = [x for x in sorted_data if x % 2 == 0]
                sort_times[f"filter_{size}"] = time.time() - comp_start
                
                # Test dictionary operations
                dict_start = time.time()
                data_dict = {i: v for i, v in enumerate(filtered_data)}
                sort_times[f"dict_{size}"] = time.time() - dict_start
            
            end_time = time.time()
            end_memory = self.measure_system_resources()
            
            return BenchmarkResult(
                test_name="algorithm_performance",
                duration=end_time - start_time,
                memory_usage={
                    "start": start_memory,
                    "end": end_memory,
                    "delta_mb": end_memory["memory_rss_mb"] - start_memory["memory_rss_mb"]
                },
                cpu_usage=end_memory["cpu_percent"],
                success=True,
                metadata={
                    "algorithm_times": sort_times,
                    "data_sizes_tested": data_sizes
                }
            )
            
        except Exception as e:
            end_time = time.time()
            return BenchmarkResult(
                test_name="algorithm_performance",
                duration=end_time - start_time,
                memory_usage=start_memory,
                cpu_usage=0,
                success=False,
                error_message=str(e)
            )
    
    def run_all_benchmarks(self) -> bool:
        """Run all performance benchmarks."""
        logger.info("Starting comprehensive performance benchmark suite...")
        
        benchmarks = [
            self.benchmark_import_time,
            self.benchmark_file_operations,
            self.benchmark_concurrent_operations,
            self.benchmark_memory_allocation,
            self.benchmark_algorithm_performance
        ]
        
        for benchmark_func in benchmarks:
            try:
                result = benchmark_func()
                self.results.append(result)
                
                if result.success:
                    logger.info(f"✓ {result.test_name}: {result.duration:.3f}s")
                else:
                    logger.error(f"✗ {result.test_name}: {result.error_message}")
                    
            except Exception as e:
                logger.error(f"Failed to run benchmark {benchmark_func.__name__}: {e}")
        
        return self.analyze_results()
    
    def analyze_results(self) -> bool:
        """Analyze benchmark results and provide performance summary."""
        total_benchmarks = len(self.results)
        failed_benchmarks = [r for r in self.results if not r.success]
        
        logger.info(f"\n{'='*60}")
        logger.info("PERFORMANCE BENCHMARK RESULTS")
        logger.info(f"{'='*60}")
        
        if not self.results:
            logger.error("No benchmark results available!")
            return False
        
        # Calculate statistics
        successful_results = [r for r in self.results if r.success]
        if successful_results:
            total_time = sum(r.duration for r in successful_results)
            avg_time = total_time / len(successful_results)
            max_time = max(r.duration for r in successful_results)
            min_time = min(r.duration for r in successful_results)
            
            logger.info(f"Total benchmarks: {total_benchmarks}")
            logger.info(f"Successful: {len(successful_results)}")
            logger.info(f"Failed: {len(failed_benchmarks)}")
            logger.info(f"Total execution time: {total_time:.3f}s")
            logger.info(f"Average time per benchmark: {avg_time:.3f}s")
            logger.info(f"Fastest benchmark: {min_time:.3f}s")
            logger.info(f"Slowest benchmark: {max_time:.3f}s")
        
        # Detailed results
        logger.info(f"\nDETAILED RESULTS:")
        for result in self.results:
            if result.success:
                memory_delta = result.memory_usage.get("delta_mb", 0)
                logger.info(f"📊 {result.test_name}:")
                logger.info(f"   Duration: {result.duration:.3f}s")
                logger.info(f"   Memory Delta: {memory_delta:+.2f}MB")
                logger.info(f"   CPU Usage: {result.cpu_usage:.1f}%")
                
                if result.metadata:
                    logger.info(f"   Metadata: {result.metadata}")
            else:
                logger.error(f"❌ {result.test_name}: {result.error_message}")
        
        # Performance assessment
        if not failed_benchmarks:
            logger.info(f"\n🎉 ALL BENCHMARKS COMPLETED SUCCESSFULLY!")
            
            # Performance thresholds (can be adjusted)
            if successful_results:
                slow_benchmarks = [r for r in successful_results if r.duration > 5.0]
                if slow_benchmarks:
                    logger.warning(f"⚠️  {len(slow_benchmarks)} benchmarks took longer than 5s")
                    for benchmark in slow_benchmarks:
                        logger.warning(f"   • {benchmark.test_name}: {benchmark.duration:.3f}s")
                else:
                    logger.info("✨ All benchmarks completed in reasonable time")
            
            return True
        else:
            logger.error(f"\n💥 {len(failed_benchmarks)} BENCHMARKS FAILED!")
            return False
    
    def generate_report(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """Generate detailed performance report."""
        system_info = {
            "cpu_count": psutil.cpu_count(),
            "cpu_freq": psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            "memory_total": psutil.virtual_memory().total,
            "memory_available": psutil.virtual_memory().available,
            "python_version": sys.version,
            "platform": sys.platform
        }
        
        report = {
            "system_info": system_info,
            "summary": {
                "total_benchmarks": len(self.results),
                "successful": len([r for r in self.results if r.success]),
                "failed": len([r for r in self.results if not r.success]),
                "total_duration": sum(r.duration for r in self.results if r.success),
                "timestamp": time.time()
            },
            "results": []
        }
        
        for result in self.results:
            report["results"].append({
                "test_name": result.test_name,
                "duration": result.duration,
                "memory_usage": result.memory_usage,
                "cpu_usage": result.cpu_usage,
                "success": result.success,
                "error_message": result.error_message,
                "metadata": result.metadata
            })
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
            logger.info(f"Performance report saved to: {output_file}")
        
        return report

def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Performance benchmark suite")
    parser.add_argument(
        "--project-root",
        default=".",
        help="Root directory of the project (default: current directory)"
    )
    parser.add_argument(
        "--report",
        help="Generate detailed JSON report to specified file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run benchmarks
    benchmark = PerformanceBenchmark(args.project_root)
    success = benchmark.run_all_benchmarks()
    
    # Generate report if requested
    if args.report:
        benchmark.generate_report(args.report)
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()