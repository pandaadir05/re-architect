"""
Main entry point for RE-Architect.

This script provides the command-line interface for RE-Architect, handling
argument parsing, binary loading, and orchestrating the reverse engineering pipeline.
"""

import argparse
import logging
import os
import sys
import time
from pathlib import Path

from src.core.pipeline import ReversePipeline
from src.core.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger("re-architect")

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="RE-Architect: Automated reverse engineering pipeline"
    )
    
    parser.add_argument(
        "binary_path", 
        type=str, 
        help="Path to the binary file to analyze"
    )
    
    parser.add_argument(
        "--output-dir", 
        type=str, 
        default="./output",
        help="Directory to store output files (default: ./output)"
    )
    
    parser.add_argument(
        "--config", 
        type=str, 
        default="./config.yaml",
        help="Path to configuration file (default: ./config.yaml)"
    )
    
    parser.add_argument(
        "--decompiler", 
        type=str, 
        choices=["ghidra", "ida", "binja", "auto"],
        default="auto",
        help="Decompiler to use (default: auto)"
    )
    
    parser.add_argument(
        "--verbose", 
        "-v", 
        action="count", 
        default=0,
        help="Increase verbosity (can be used multiple times)"
    )
    
    parser.add_argument(
        "--no-llm", 
        action="store_true", 
        help="Disable LLM-based analysis"
    )
    
    parser.add_argument(
        "--generate-tests", 
        action="store_true", 
        help="Generate test harnesses for identified functions"
    )
    
    parser.add_argument(
        "--serve", 
        action="store_true", 
        help="Start the web visualization server after analysis"
    )
    
    return parser.parse_args()

def main():
    """Main execution function."""
    start_time = time.time()
    args = parse_args()
    
    # Set verbosity level
    if args.verbose == 0:
        logger.setLevel(logging.INFO)
    elif args.verbose == 1:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.DEBUG)
        # Enable detailed debug logs
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("RE-Architect starting...")
    logger.debug(f"Arguments: {args}")
    
    # Check if binary exists
    binary_path = Path(args.binary_path)
    if not binary_path.exists() or not binary_path.is_file():
        logger.error(f"Binary file not found: {binary_path}")
        return 1
    
    # Create output directory if it doesn't exist
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Load configuration
    config = Config.from_file(args.config)
    if args.no_llm:
        config.disable_llm()
    
    try:
        # Initialize and run the pipeline
        pipeline = ReversePipeline(
            binary_path=binary_path,
            output_dir=output_dir,
            config=config,
            decompiler=args.decompiler,
            generate_tests=args.generate_tests
        )
        
        results = pipeline.run()
        
        # Output processing time
        elapsed_time = time.time() - start_time
        logger.info(f"Analysis completed in {elapsed_time:.2f} seconds")
        
        # Start visualization server if requested
        if args.serve:
            from src.visualization.server import start_server
            start_server(results, host="localhost", port=8000)
        
        return 0
        
    except Exception as e:
        logger.exception(f"Error during analysis: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
