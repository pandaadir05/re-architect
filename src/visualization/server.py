"""
Visualization server module for RE-Architect.

This module provides a web-based visualization server for the analysis results.
"""

import logging
import json
import os
import sys
import webbrowser
from pathlib import Path
from typing import Dict, Any, Optional, Union, List

logger = logging.getLogger("re-architect.visualization.server")

class VisualizationServer:
    """
    Web-based visualization server for RE-Architect.
    
    This class provides a server for visualizing the analysis results
    through a web interface.
    """
    
    def __init__(self, host: str = "localhost", port: int = 5000):
        """
        Initialize the visualization server.
        
        Args:
            host: Host address to bind the server to
            port: Port to bind the server to
        """
        self.host = host
        self.port = port
        self.app = None
        self.results = None
    
    def load_results(self, results: Dict[str, Any]) -> None:
        """
        Load analysis results to visualize.
        
        Args:
            results: Analysis results to visualize
        """
        self.results = results
    
    def start(self, open_browser: bool = True) -> None:
        """
        Start the visualization server.
        
        Args:
            open_browser: Whether to open a browser automatically
            
        Raises:
            RuntimeError: If no results have been loaded
        """
        if not self.results:
            raise RuntimeError("No results have been loaded")
        
        try:
            # Create Flask app
            from flask import Flask, render_template, jsonify, request, send_from_directory
            import flask_cors
            
            # Create app
            self.app = Flask("re-architect-viz", 
                             static_folder=os.path.join(os.path.dirname(__file__), '..', '..', 'frontend', 'build'),
                             static_url_path='')
            
            # Enable CORS for development
            flask_cors.CORS(self.app)
            
            # Register authentication routes
            from src.auth import auth_bp
            self.app.register_blueprint(auth_bp, url_prefix='/api/auth')
            
            # Register comparison routes
            from src.comparison.routes import comparison_bp
            self.app.register_blueprint(comparison_bp, url_prefix='/api/comparison')
            
            # Setup request logging
            from src.auth.logging_middleware import RequestLogger
            RequestLogger(self.app)
            
            # API routes
            @self.app.route('/api/metadata')
            def metadata():
                return jsonify(self.results["metadata"])
            
            @self.app.route('/api/functions')
            def functions():
                return jsonify(self.results.get("functions", {}))
            
            @self.app.route('/api/function/<func_id>')
            def function_details(func_id):
                try:
                    func_id_int = int(func_id)
                    if str(func_id_int) in self.results["functions"]:
                        return jsonify(self.results["functions"][str(func_id_int)])
                except ValueError:
                    # Try with string ID
                    if func_id in self.results["functions"]:
                        return jsonify(self.results["functions"][func_id])
                return jsonify({"error": "Function not found"}), 404
            
            @self.app.route('/api/data_structures')
            def data_structures():
                return jsonify(self.results.get("data_structures", {}))
            
            @self.app.route('/api/data_structure/<struct_id>')
            def data_structure_details(struct_id):
                if struct_id in self.results.get("data_structures", {}):
                    return jsonify(self.results["data_structures"][struct_id])
                return jsonify({"error": "Data structure not found"}), 404
            
            @self.app.route('/api/test_harnesses')
            def test_harnesses():
                return jsonify(self.results.get("test_harnesses", {}))
            
            @self.app.route('/api/test_harness/<func_id>')
            def test_harness_details(func_id):
                if func_id in self.results.get("test_harnesses", {}):
                    return jsonify(self.results["test_harnesses"][func_id])
                return jsonify({"error": "Test harness not found"}), 404
                
            @self.app.route('/api/analysis/<analysis_id>')
            def analysis_details(analysis_id):
                if analysis_id in self.results.get("analyses", {}):
                    return jsonify(self.results["analyses"][analysis_id])
                return jsonify({"error": "Analysis not found"}), 404
                
            @self.app.route('/api/performance')
            def performance():
                return jsonify(self.results.get("performance_metrics", {}))
                
            # New API for summary information
            @self.app.route('/api/summary')
            def summary():
                total_functions = len(self.results.get("functions", {}))
                total_data_structures = len(self.results.get("data_structures", {}))
                total_tests = len(self.results.get("test_harnesses", {}))
                
                # Count vulnerabilities if they exist
                vulnerabilities = []
                for func_id, func_data in self.results.get("functions", {}).items():
                    if "vulnerabilities" in func_data:
                        vulnerabilities.extend(func_data["vulnerabilities"])
                
                return jsonify({
                    "total_functions": total_functions,
                    "total_data_structures": total_data_structures,
                    "total_tests": total_tests,
                    "total_vulnerabilities": len(vulnerabilities),
                    "binary_name": os.path.basename(self.results.get("metadata", {}).get("file_path", "unknown")),
                    "analysis_time": sum(self.results.get("performance_metrics", {}).values())
                })
            
            # Serve React frontend
            @self.app.route('/', defaults={'path': ''})
            @self.app.route('/<path:path>')
            def serve(path):
                if path and os.path.exists(os.path.join(self.app.static_folder, path)):
                    return send_from_directory(self.app.static_folder, path)
                return send_from_directory(self.app.static_folder, 'index.html')
            
            # Start server
            url = f"http://{self.host}:{self.port}"
            logger.info(f"Starting visualization server at {url}")
            
            if open_browser:
                webbrowser.open(url)
            
            self.app.run(host=self.host, port=self.port, debug=False)
            
        except ImportError:
            logger.error("Flask not installed. Please install with 'pip install flask flask-cors'")
            raise RuntimeError("Flask not installed. Please install with 'pip install flask flask-cors'")
        except Exception as e:
            logger.error(f"Error starting visualization server: {e}")
            raise RuntimeError(f"Error starting visualization server: {e}")
    
    def stop(self) -> None:
        """Stop the visualization server."""
        # In a real implementation, this would stop the server
        logger.info("Stopping visualization server")

def start_server(results: Dict[str, Any], host: str = "localhost", port: int = 8000) -> None:
    """
    Start a visualization server for the analysis results.
    
    Args:
        results: Analysis results to visualize
        host: Host address to bind the server to
        port: Port to bind the server to
    """
    # Create static HTML files if Flask is not available
    try:
        import flask
        # Use the interactive Flask server
        server = VisualizationServer(host, port)
        server.load_results(results)
        server.start()
    except ImportError:
        # Fall back to static HTML generation
        logger.info("Flask not available, generating static HTML files")
        generate_static_html(results)

def generate_static_html(results: Dict[str, Any], output_dir: str = "./output/html") -> None:
    """
    Generate static HTML files for the analysis results.
    
    Args:
        results: Analysis results to visualize
        output_dir: Directory to write HTML files to
    """
    # Create output directory
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate index.html
    index_html = _generate_index_html(results)
    with open(os.path.join(output_dir, "index.html"), "w") as f:
        f.write(index_html)
    
    # Generate functions.html
    functions_html = _generate_functions_html(results)
    with open(os.path.join(output_dir, "functions.html"), "w") as f:
        f.write(functions_html)
    
    # Generate data_structures.html
    data_structures_html = _generate_data_structures_html(results)
    with open(os.path.join(output_dir, "data_structures.html"), "w") as f:
        f.write(data_structures_html)
    
    # Generate individual function HTML files
    for func_id, func_info in results["functions"].items():
        func_html = _generate_function_html(func_id, func_info, results)
        with open(os.path.join(output_dir, f"function_{func_id}.html"), "w") as f:
            f.write(func_html)
    
    logger.info(f"Generated static HTML files in {output_dir}")
    logger.info(f"Open {os.path.join(output_dir, 'index.html')} to view results")

def _generate_index_html(results: Dict[str, Any]) -> str:
    """Generate the index HTML page."""
    binary_path = results["metadata"]["file_path"]
    binary_name = os.path.basename(binary_path)
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>RE-Architect Results: {binary_name}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .card {{ border: 1px solid #ccc; border-radius: 5px; padding: 20px; margin-bottom: 20px; }}
        .nav {{ background-color: #f5f5f5; padding: 10px; }}
        .nav a {{ margin-right: 20px; color: #333; text-decoration: none; }}
        .nav a:hover {{ text-decoration: underline; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        pre {{ background-color: #f5f5f5; padding: 10px; overflow: auto; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="index.html">Overview</a>
            <a href="functions.html">Functions</a>
            <a href="data_structures.html">Data Structures</a>
        </div>
        
        <h1>RE-Architect Analysis Results</h1>
        
        <div class="card">
            <h2>Binary Information</h2>
            <table>
                <tr>
                    <th>File Path</th>
                    <td>{results["metadata"]["file_path"]}</td>
                </tr>
                <tr>
                    <th>File Size</th>
                    <td>{results["metadata"]["file_size"]} bytes</td>
                </tr>
                <tr>
                    <th>Architecture</th>
                    <td>{results["metadata"]["architecture"].value}</td>
                </tr>
                <tr>
                    <th>Compiler</th>
                    <td>{results["metadata"]["compiler"].value}</td>
                </tr>
                <tr>
                    <th>Entry Point</th>
                    <td>0x{results["metadata"]["entry_point"]:x}</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Analysis Summary</h2>
            <table>
                <tr>
                    <th>Total Functions</th>
                    <td>{len(results["functions"])}</td>
                </tr>
                <tr>
                    <th>Data Structures</th>
                    <td>{len(results["data_structures"])}</td>
                </tr>
                <tr>
                    <th>Test Harnesses</th>
                    <td>{len(results["test_harnesses"])}</td>
                </tr>
            </table>
        </div>
        
        <div class="card">
            <h2>Performance Metrics</h2>
            <table>
                <tr>
                    <th>Stage</th>
                    <th>Time (seconds)</th>
                </tr>
    """
    
    for stage, time in results["performance_metrics"].items():
        html += f"""
                <tr>
                    <td>{stage}</td>
                    <td>{time:.2f}</td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    </div>
</body>
</html>
    """
    
    return html

def _generate_functions_html(results: Dict[str, Any]) -> str:
    """Generate the functions HTML page."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>RE-Architect Results: Functions</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { border: 1px solid #ccc; border-radius: 5px; padding: 20px; margin-bottom: 20px; }
        .nav { background-color: #f5f5f5; padding: 10px; }
        .nav a { margin-right: 20px; color: #333; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        pre { background-color: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="index.html">Overview</a>
            <a href="functions.html">Functions</a>
            <a href="data_structures.html">Data Structures</a>
        </div>
        
        <h1>Functions</h1>
        
        <div class="card">
            <table>
                <tr>
                    <th>Address</th>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Complexity</th>
                    <th>Has Summary</th>
                    <th>Has Test</th>
                </tr>
    """
    
    for func_id, func_info in results["functions"].items():
        has_summary = "summary" in func_info and func_info["summary"]
        has_test = str(func_id) in results["test_harnesses"]
        
        html += f"""
                <tr>
                    <td>0x{func_id:x}</td>
                    <td><a href="function_{func_id}.html">{func_info["name"]}</a></td>
                    <td>{func_info.get("size", 0)}</td>
                    <td>{func_info.get("complexity", 0)}</td>
                    <td>{"Yes" if has_summary else "No"}</td>
                    <td>{"Yes" if has_test else "No"}</td>
                </tr>
        """
    
    html += """
            </table>
        </div>
    </div>
</body>
</html>
    """
    
    return html

def _generate_data_structures_html(results: Dict[str, Any]) -> str:
    """Generate the data structures HTML page."""
    html = """<!DOCTYPE html>
<html>
<head>
    <title>RE-Architect Results: Data Structures</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1, h2, h3 { color: #333; }
        .container { max-width: 1200px; margin: 0 auto; }
        .card { border: 1px solid #ccc; border-radius: 5px; padding: 20px; margin-bottom: 20px; }
        .nav { background-color: #f5f5f5; padding: 10px; }
        .nav a { margin-right: 20px; color: #333; text-decoration: none; }
        .nav a:hover { text-decoration: underline; }
        table { width: 100%; border-collapse: collapse; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        pre { background-color: #f5f5f5; padding: 10px; overflow: auto; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="index.html">Overview</a>
            <a href="functions.html">Functions</a>
            <a href="data_structures.html">Data Structures</a>
        </div>
        
        <h1>Data Structures</h1>
    """
    
    for struct_name, struct_info in results["data_structures"].items():
        html += f"""
        <div class="card">
            <h2>{struct_name}</h2>
            <p><strong>Source:</strong> {struct_info.get("source", "unknown")}</p>
            <p><strong>Size:</strong> {struct_info.get("size", 0)} bytes</p>
            
            <h3>Fields</h3>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Array</th>
                </tr>
        """
        
        for field in struct_info.get("fields", []):
            html += f"""
                <tr>
                    <td>{field.get("name", "unknown")}</td>
                    <td>{field.get("type", "unknown")}</td>
                    <td>{"Yes" if field.get("is_array", False) else "No"}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    html += """
    </div>
</body>
</html>
    """
    
    return html

def _generate_function_html(func_id: int, func_info: Dict[str, Any], results: Dict[str, Any]) -> str:
    """Generate HTML for a single function."""
    html = f"""<!DOCTYPE html>
<html>
<head>
    <title>RE-Architect Results: {func_info["name"]}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
        h1, h2, h3 {{ color: #333; }}
        .container {{ max-width: 1200px; margin: 0 auto; }}
        .card {{ border: 1px solid #ccc; border-radius: 5px; padding: 20px; margin-bottom: 20px; }}
        .nav {{ background-color: #f5f5f5; padding: 10px; }}
        .nav a {{ margin-right: 20px; color: #333; text-decoration: none; }}
        .nav a:hover {{ text-decoration: underline; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; }}
        pre {{ background-color: #f5f5f5; padding: 10px; overflow: auto; }}
        .code {{ font-family: monospace; white-space: pre; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="index.html">Overview</a>
            <a href="functions.html">Functions</a>
            <a href="data_structures.html">Data Structures</a>
        </div>
        
        <h1>Function: {func_info["name"]}</h1>
        
        <div class="card">
            <h2>Information</h2>
            <table>
                <tr>
                    <th>Address</th>
                    <td>0x{func_id:x}</td>
                </tr>
                <tr>
                    <th>Signature</th>
                    <td>{func_info.get("signature", "unknown")}</td>
                </tr>
                <tr>
                    <th>Return Type</th>
                    <td>{func_info.get("return_type", "unknown")}</td>
                </tr>
                <tr>
                    <th>Size</th>
                    <td>{func_info.get("size", 0)}</td>
                </tr>
                <tr>
                    <th>Complexity</th>
                    <td>{func_info.get("complexity", 0)}</td>
                </tr>
                <tr>
                    <th>Has Loops</th>
                    <td>{"Yes" if func_info.get("has_loops", False) else "No"}</td>
                </tr>
                <tr>
                    <th>Has Switch</th>
                    <td>{"Yes" if func_info.get("has_switch", False) else "No"}</td>
                </tr>
            </table>
        </div>
    """
    
    # Add summary if available
    if "summary" in func_info and func_info["summary"]:
        summary = func_info["summary"]
        html += """
        <div class="card">
            <h2>Summary</h2>
        """
        
        if isinstance(summary, dict):
            for key, value in summary.items():
                if key != "raw_response" and value:
                    html += f"<h3>{key.replace('_', ' ').title()}</h3>"
                    if isinstance(value, list):
                        html += "<ul>"
                        for item in value:
                            html += f"<li>{item}</li>"
                        html += "</ul>"
                    else:
                        html += f"<p>{value}</p>"
        else:
            html += f"<p>{summary}</p>"
        
        html += """
        </div>
        """
    
    # Add parameters
    if "parameters" in func_info and func_info["parameters"]:
        html += """
        <div class="card">
            <h2>Parameters</h2>
            <table>
                <tr>
                    <th>Name</th>
                    <th>Type</th>
                </tr>
        """
        
        for param in func_info["parameters"]:
            html += f"""
                <tr>
                    <td>{param.get("name", "unknown")}</td>
                    <td>{param.get("dataType", "unknown")}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    # Add function calls
    if "calls" in func_info and func_info["calls"]:
        html += """
        <div class="card">
            <h2>Function Calls</h2>
            <table>
                <tr>
                    <th>Function</th>
                    <th>Address</th>
                </tr>
        """
        
        for call in func_info["calls"]:
            html += f"""
                <tr>
                    <td>{call.get("toFunction", "unknown")}</td>
                    <td>{call.get("toAddress", "unknown")}</td>
                </tr>
            """
        
        html += """
            </table>
        </div>
        """
    
    # Add code
    html += """
        <div class="card">
            <h2>Decompiled Code</h2>
            <pre class="code">
    """
    
    html += func_info["code"].replace("<", "&lt;").replace(">", "&gt;")
    
    html += """
            </pre>
        </div>
    """
    
    # Add test harness if available
    if str(func_id) in results["test_harnesses"]:
        test_info = results["test_harnesses"][str(func_id)]
        html += """
        <div class="card">
            <h2>Test Harness</h2>
            <pre class="code">
        """
        
        html += test_info["source_code"].replace("<", "&lt;").replace(">", "&gt;")
        
        html += """
            </pre>
            <h3>Build Script</h3>
            <pre class="code">
        """
        
        html += test_info["build_script"].replace("<", "&lt;").replace(">", "&gt;")
        
        html += """
            </pre>
        </div>
        """
    
    html += """
    </div>
</body>
</html>
    """
    
    return html
