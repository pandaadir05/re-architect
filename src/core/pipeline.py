"""
Core pipeline module for RE-Architect.

This module defines the main reverse engineering pipeline that coordinates
the different analysis stages with advanced error handling and monitoring.
"""

import logging
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.core.binary_loader import BinaryLoader
from src.core.config import Config
from src.core.error_handling import (
    StructuredLogger, ErrorHandler, monitored_operation,
    ErrorSeverity, ErrorCategory
)
from src.security import SecurityValidator
from src.decompilers.decompiler_factory import DecompilerFactory
from src.analysis.static_analyzer import StaticAnalyzer
from src.analysis.dynamic_analyzer import DynamicAnalyzer
from src.analysis.data_structure_analyzer import DataStructureAnalyzer
from src.llm.function_summarizer import FunctionSummarizer
from src.test_generation.test_generator import TestGenerator

try:
    from src.optimization import ObfuscationOptimizer
    OPTIMIZATION_AVAILABLE = True
except ImportError:
    ObfuscationOptimizer = None
    OPTIMIZATION_AVAILABLE = False

logger = StructuredLogger("re-architect.pipeline")

class ReversePipeline:
    """
    Main pipeline for the reverse engineering process.
    
    This class orchestrates the entire reverse engineering workflow, from binary loading
    to test harness generation.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the reverse engineering pipeline.
        
        Args:
            config: Configuration object
        """
        self.config = config
        
        # Initialize error handling and monitoring
        self.error_handler = ErrorHandler()
        
        # Other fields will be initialized when analyze() is called
        self.binary_path = None
        self.output_dir = None
        self.decompiler_name = "auto"
        self.generate_tests = False
        
        self.binary_loader = None
        self.decompiler = None
        self.static_analyzer = None
        self.dynamic_analyzer = None
        self.data_structure_analyzer = None
        self.function_summarizer = None
        self.test_generator = None
        
        self.results = {
            "metadata": {},
            "functions": {},
            "data_structures": {},
            "test_harnesses": {},
            "performance_metrics": {},
            "security_report": {},
            "error_summary": {}
        }
        
        # Set up logging context
        logger.set_context(pipeline_id=id(self))
    
    @monitored_operation(
        component="pipeline",
        category=ErrorCategory.ANALYSIS,
        severity=ErrorSeverity.HIGH
    )
    def analyze(self, binary_path, output_dir=None, decompiler="auto", generate_tests=False):
        """
        Analyze a binary file with comprehensive security and error handling.
        
        Args:
            binary_path: Path to the binary file to analyze
            output_dir: Directory to store output files, defaults to a directory next to the binary
            decompiler: Decompiler to use (ghidra, ida, binja, auto)
            generate_tests: Whether to generate test harnesses
            
        Returns:
            Dictionary containing analysis results
            
        Raises:
            SecurityError: If the binary file is unsafe
            ValueError: If parameters are invalid
        """
        try:
            # Validate and sanitize inputs using security module
            validated_binary = SecurityValidator.validate_binary_file(binary_path)
            
            if output_dir:
                validated_output = SecurityValidator.validate_output_directory(output_dir)
            else:
                # Default to a directory next to the binary
                default_output = validated_binary.parent / f"{validated_binary.stem}_analysis"
                validated_output = SecurityValidator.validate_output_directory(default_output)
            
            # Validate decompiler choice
            if decompiler not in ["ghidra", "ida", "binja", "auto", "mock"]:
                raise ValueError(f"Invalid decompiler choice: {decompiler}")
            
            # Set validated paths
            self.binary_path = validated_binary
            self.output_dir = validated_output
            self.decompiler_name = decompiler
            self.generate_tests = generate_tests
            
            # Set logging context
            logger.set_context(
                binary_path=str(self.binary_path),
                output_dir=str(self.output_dir),
                decompiler=self.decompiler_name
            )
            
            logger.info("Starting binary analysis", binary_size=self.binary_path.stat().st_size)
            
            # Run the pipeline
            return self._run()
            
        except Exception as e:
            self.error_handler.handle_error(
                exception=e,
                severity=ErrorSeverity.HIGH,
                category=ErrorCategory.ANALYSIS,
                component="pipeline.analyze",
                context={
                    "binary_path": str(binary_path),
                    "output_dir": str(output_dir) if output_dir else None,
                    "decompiler": decompiler,
                    "generate_tests": generate_tests
                },
                resolution_steps=[
                    "Verify the binary file exists and is readable",
                    "Check that the output directory is writable",
                    "Ensure the selected decompiler is installed and available",
                    "Check system resources (memory, disk space)"
                ]
            )
            raise
        
    def _run(self) -> Dict[str, Any]:
        """
        Internal method to run the pipeline after parameters are set.
        
        Returns:
            Dictionary containing analysis results
        """
        logger.info(f"Starting analysis of {self.binary_path}")
        
        # Record start time for performance metrics
        stage_times = {}
        
        # Initialize components
        self._initialize_components()
        
        # Load binary
        start_time = time.time()
        binary_info = self.binary_loader.load(self.binary_path, auto_unpack=True)
        stage_times["binary_loading"] = time.time() - start_time
        
        # Store binary metadata
        self.results["metadata"] = {
            "file_path": str(self.binary_path),
            "file_size": self.binary_path.stat().st_size,
            "architecture": binary_info.architecture.value if hasattr(binary_info.architecture, 'value') else str(binary_info.architecture),
            "compiler": binary_info.compiler.value if hasattr(binary_info.compiler, 'value') else str(binary_info.compiler),
            "entry_point": binary_info.entry_point
        }
        
        # Decompile binary
        start_time = time.time()
        decompiled_code = self.decompiler.decompile(binary_info)
        stage_times["decompilation"] = time.time() - start_time
        
        # Perform static analysis
        start_time = time.time()
        static_analysis_results = self.static_analyzer.analyze(decompiled_code)
        stage_times["static_analysis"] = time.time() - start_time
        
        # Extract functions and their details
        self.results["functions"] = static_analysis_results.functions
        
        # Analyze data structures
        start_time = time.time()
        data_structures = self.data_structure_analyzer.analyze(
            decompiled_code, 
            static_analysis_results
        )
        stage_times["data_structure_analysis"] = time.time() - start_time
        
        # Store data structure information
        self.results["data_structures"] = data_structures

        # Obfuscation optimization (iterative, post-decompilation)
        try:
            if not OPTIMIZATION_AVAILABLE or ObfuscationOptimizer is None:
                logger.warning("Optimization not available - skipping obfuscation removal")
            else:
                optimizer = ObfuscationOptimizer()
            if optimizer.is_available():
                start_time = time.time()
                report = optimizer.optimize(self.binary_path)
                stage_times["obfuscation_optimization"] = time.time() - start_time
                self.results["obfuscation_optimization"] = {
                    "iterations": report.iterations,
                    "changes_applied": report.changes_applied,
                    "passes_run": report.passes_run,
                    "details": report.details,
                }
        except Exception:
            # Non-fatal: continue pipeline if optimizer unavailable or fails
            pass
        
        # Generate function summaries with LLM if enabled
        if self.function_summarizer:
            start_time = time.time()
            for func_id, func_info in self.results["functions"].items():
                summary = self.function_summarizer.summarize(func_info)
                self.results["functions"][func_id]["summary"] = summary
            stage_times["function_summarization"] = time.time() - start_time
        
        # Generate test harnesses if requested
        if self.test_generator:
            start_time = time.time()
            test_harnesses = self.test_generator.generate(
                self.results["functions"],
                self.results["data_structures"]
            )
            stage_times["test_generation"] = time.time() - start_time
            
            # Store test harnesses
            self.results["test_harnesses"] = test_harnesses
        
        # Store performance metrics
        self.results["performance_metrics"] = stage_times
        
        # Save results to output directory
        self._save_results()
        
        logger.info("Analysis completed successfully")
        return self.results
        
        self.binary_loader = None
        self.decompiler = None
        self.static_analyzer = None
        self.dynamic_analyzer = None
        self.data_structure_analyzer = None
        self.function_summarizer = None
        self.test_generator = None
        
        self.results = {
            "metadata": {},
            "functions": {},
            "data_structures": {},
            "test_harnesses": {},
            "performance_metrics": {}
        }
    
    def _initialize_components(self):
        """Initialize all pipeline components."""
        logger.info("Initializing pipeline components...")
        
        # Initialize binary loader
        self.binary_loader = BinaryLoader()
        
        # Initialize decompiler
        decompiler_factory = DecompilerFactory()
        self.decompiler = decompiler_factory.create(self.decompiler_name)
        
        # Initialize analyzers
        self.static_analyzer = StaticAnalyzer(self.config)
        self.dynamic_analyzer = DynamicAnalyzer(self.config)
        self.data_structure_analyzer = DataStructureAnalyzer(self.config)
        
        # Initialize LLM components if enabled
        if self.config.use_llm:
            self.function_summarizer = FunctionSummarizer(self.config)
        
        # Initialize test generator if requested
        if self.generate_tests:
            self.test_generator = TestGenerator(self.config)
    
    def run(self) -> Dict[str, Any]:
        """
        Run the complete reverse engineering pipeline.
        
        Returns:
            Dictionary containing all analysis results
        """
        logger.info(f"Starting analysis of {self.binary_path}")
        
        # Record start time for performance metrics
        stage_times = {}
        
        # Initialize components
        self._initialize_components()
        
        # Load binary
        start_time = time.time()
        binary_info = self.binary_loader.load(self.binary_path, auto_unpack=True)
        stage_times["binary_loading"] = time.time() - start_time
        
        # Store binary metadata
        self.results["metadata"] = {
            "file_path": str(self.binary_path),
            "file_size": self.binary_path.stat().st_size,
            "architecture": binary_info.architecture.value if hasattr(binary_info.architecture, 'value') else str(binary_info.architecture),
            "compiler": binary_info.compiler.value if hasattr(binary_info.compiler, 'value') else str(binary_info.compiler),
            "entry_point": binary_info.entry_point
        }
        
        # Decompile binary
        start_time = time.time()
        decompiled_code = self.decompiler.decompile(binary_info)
        stage_times["decompilation"] = time.time() - start_time
        
        # Perform static analysis
        start_time = time.time()
        static_analysis_results = self.static_analyzer.analyze(decompiled_code)
        stage_times["static_analysis"] = time.time() - start_time
        
        # Extract functions and their details
        self.results["functions"] = static_analysis_results.functions
        
        # Analyze data structures
        start_time = time.time()
        data_structures = self.data_structure_analyzer.analyze(
            decompiled_code, 
            static_analysis_results
        )
        stage_times["data_structure_analysis"] = time.time() - start_time
        
        # Store data structure information
        self.results["data_structures"] = data_structures
        
        # Generate function summaries with LLM if enabled
        if self.function_summarizer:
            start_time = time.time()
            for func_id, func_info in self.results["functions"].items():
                summary = self.function_summarizer.summarize(func_info)
                self.results["functions"][func_id]["summary"] = summary
            stage_times["function_summarization"] = time.time() - start_time
        
        # Generate test harnesses if requested
        if self.test_generator:
            start_time = time.time()
            test_harnesses = self.test_generator.generate(
                self.results["functions"],
                self.results["data_structures"]
            )
            stage_times["test_generation"] = time.time() - start_time
            
            # Store test harnesses
            self.results["test_harnesses"] = test_harnesses
        
        # Store performance metrics
        self.results["performance_metrics"] = stage_times
        
        # Save results to output directory
        self._save_results()
        
        logger.info("Analysis completed successfully")
        return self.results
    
    def _save_results(self):
        """Save all results to the output directory."""
        import json
        
        # Ensure output directory exists
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Save overview JSON
        with open(self.output_dir / "results.json", "w") as f:
            json.dump(self.results, f, indent=2)
        
        # Save function summaries
        functions_dir = self.output_dir / "functions"
        functions_dir.mkdir(exist_ok=True)
        
        for func_id, func_info in self.results["functions"].items():
            func_file = functions_dir / f"{func_id}.json"
            with open(func_file, "w") as f:
                json.dump(func_info, f, indent=2)
        
        # Save data structure definitions
        data_structures_dir = self.output_dir / "data_structures"
        data_structures_dir.mkdir(exist_ok=True)
        
        for struct_id, struct_info in self.results["data_structures"].items():
            struct_file = data_structures_dir / f"{struct_id}.json"
            with open(struct_file, "w") as f:
                json.dump(struct_info, f, indent=2)
        
        # Save test harnesses if available
        if self.results["test_harnesses"]:
            tests_dir = self.output_dir / "tests"
            tests_dir.mkdir(exist_ok=True)
            
            for test_id, test_info in self.results["test_harnesses"].items():
                # Save test source code
                test_file = tests_dir / f"{test_id}.c"  # Using C as default
                with open(test_file, "w") as f:
                    f.write(test_info["source_code"])
                
                # Save test metadata
                test_meta_file = tests_dir / f"{test_id}_meta.json"
                with open(test_meta_file, "w") as f:
                    json.dump(
                        {k: v for k, v in test_info.items() if k != "source_code"}, 
                        f, 
                        indent=2
                    )
        
        logger.info(f"Results saved to {self.output_dir}")