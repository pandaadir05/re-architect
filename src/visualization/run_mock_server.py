#!/usr/bin/env python3
"""
Script to run the visualization server with mock data for testing.
"""

import sys
from pathlib import Path

# Add src to path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.visualization.server import create_mock_server

def main():
    """Run the mock server."""
    print("Starting RE-Architect visualization server with mock data...")
    print("Server will be available at: http://localhost:5000")
    
    server = create_mock_server()
    server.start()

if __name__ == "__main__":
    main()