"""
Web server module for RE-Architect visualization.

Provides a Flask-based web interface for exploring binary analysis results.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from flask import Flask, render_template, jsonify, request, send_from_directory
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

logger = logging.getLogger("re-architect.visualization.server")

class VisualizationServer:
    """
    Web server for visualizing RE-Architect results.
    
    Provides a Flask-based interface for exploring binary analysis results
    including functions, data structures, and test harnesses.
    """
    
    def __init__(self, host: str = "localhost", port: int = 5000, debug: bool = False):
        """
        Initialize the visualization server.
        
        Args:
            host: Host address to bind to
            port: Port to listen on
            debug: Enable debug mode
        """
        if not FLASK_AVAILABLE:
            raise ImportError("Flask is required for visualization server. Install with: pip install flask")
            
        self.host = host
        self.port = port
        self.debug = debug
        self.app = Flask(__name__, template_folder="templates", static_folder="static")
        self.results = None
        
        # Setup routes
        self._setup_routes()
        
    def _setup_routes(self):
        """Setup Flask routes."""
        
        @self.app.route('/')
        def index():
            """Main dashboard."""
            if not self.results:
                return jsonify({"error": "No analysis results loaded"}), 404
            return render_template('dashboard.html', results=self.results)
        
        @self.app.route('/api/functions')
        def api_functions():
            """Get all functions."""
            if not self.results or 'functions' not in self.results:
                return jsonify({"error": "No functions available"}), 404
            return jsonify(self.results['functions'])
        
        @self.app.route('/api/function/<function_id>')
        def api_function_detail(function_id):
            """Get detailed information about a specific function."""
            if not self.results or 'functions' not in self.results:
                return jsonify({"error": "No functions available"}), 404
                
            function = self.results['functions'].get(function_id)
            if not function:
                return jsonify({"error": "Function not found"}), 404
                
            return jsonify(function)
        
        @self.app.route('/api/data-structures')
        def api_data_structures():
            """Get all data structures."""
            if not self.results or 'data_structures' not in self.results:
                return jsonify({"error": "No data structures available"}), 404
            return jsonify(self.results['data_structures'])
        
        @self.app.route('/api/test-harnesses')
        def api_test_harnesses():
            """Get all test harnesses."""
            if not self.results or 'test_harnesses' not in self.results:
                return jsonify({"error": "No test harnesses available"}), 404
            return jsonify(self.results['test_harnesses'])
        
        @self.app.route('/api/metadata')
        def api_metadata():
            """Get analysis metadata."""
            if not self.results or 'metadata' not in self.results:
                return jsonify({"error": "No metadata available"}), 404
            return jsonify(self.results['metadata'])
        
        @self.app.route('/health')
        def health():
            """Health check endpoint."""
            return jsonify({"status": "ok", "results_loaded": self.results is not None})
    
    def load_results(self, results: Dict[str, Any]):
        """
        Load analysis results for visualization.
        
        Args:
            results: Dictionary containing analysis results
        """
        self.results = results
        logger.info("Analysis results loaded for visualization")
    
    def load_results_from_file(self, results_path: str):
        """
        Load analysis results from a JSON file.
        
        Args:
            results_path: Path to the results JSON file
        """
        import json
        
        try:
            with open(results_path, 'r') as f:
                self.results = json.load(f)
            logger.info(f"Analysis results loaded from {results_path}")
        except Exception as e:
            logger.error(f"Failed to load results from {results_path}: {e}")
            raise
    
    def start(self):
        """Start the web server."""
        if not self.results:
            logger.warning("Starting server without loaded results")
        
        logger.info(f"Starting visualization server at http://{self.host}:{self.port}")
        self.app.run(host=self.host, port=self.port, debug=self.debug)
    
    def get_app(self):
        """Get the Flask app instance for testing."""
        return self.app


def create_mock_server(host: str = "localhost", port: int = 5000):
    """
    Create a visualization server with mock data for testing.
    
    Args:
        host: Host address to bind to
        port: Port to listen on
        
    Returns:
        Configured VisualizationServer instance
    """
    server = VisualizationServer(host, port)
    
    # Load mock results
    mock_results = {
        "metadata": {
            "binary_path": "/path/to/example.exe",
            "analysis_time": "2025-01-01T12:00:00",
            "total_functions": 10,
            "total_data_structures": 3
        },
        "functions": {
            "1": {
                "name": "main",
                "address": 4096,
                "size": 64,
                "summary": "Main entry point function",
                "complexity": 2.5
            },
            "2": {
                "name": "helper_func", 
                "address": 4160,
                "size": 32,
                "summary": "Helper function for data processing",
                "complexity": 1.2
            }
        },
        "data_structures": {
            "1": {
                "name": "data_struct",
                "size": 16,
                "fields": ["field1", "field2"]
            }
        },
        "test_harnesses": {
            "1": {
                "function_name": "main",
                "test_code": "// Test code for main function",
                "coverage": 0.85
            }
        }
    }
    
    server.load_results(mock_results)
    return server