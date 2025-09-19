"""
Script to run the visualization server with mock data for testing.
"""

import os
import sys
import logging
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent.parent))

from src.visualization.server import VisualizationServer
from src.visualization.mock_data import generate_mock_analysis_results, save_mock_results

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler()]
)

logger = logging.getLogger("mock-visualization")

def main():
    """Run the visualization server with mock data."""
    logger.info("Generating mock data for visualization...")
    
    # Generate mock results
    results = generate_mock_analysis_results(
        num_functions=100,
        num_data_structures=25,
        binary_path="/samples/example.exe"
    )
    
    # Save mock results for reference
    results_dir = Path(__file__).resolve().parent.parent.parent / "results"
    results_dir.mkdir(exist_ok=True)
    mock_results_path = results_dir / "mock_analysis.json"
    save_mock_results(results, str(mock_results_path))
    
    # Start visualization server
    logger.info("Starting visualization server with mock data...")
    server = VisualizationServer(host="0.0.0.0", port=5000)
    server.load_results(results)
    
    # Open browser and start server
    logger.info("Server starting. Press Ctrl+C to stop.")
    try:
        server.start(open_browser=True)
    except KeyboardInterrupt:
        logger.info("Server stopped by user.")
    
if __name__ == "__main__":
    main()
