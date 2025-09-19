"""
Generate API documentation from OpenAPI specification.

This script generates HTML documentation from the OpenAPI YAML file.
"""

import os
import sys
from pathlib import Path

# Add parent directory to path
sys.path.append(str(Path(__file__).resolve().parent.parent))

try:
    import yaml
    from redoc_cli.cli import generate_html
except ImportError:
    print("Required packages not found. Installing...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pyyaml", "redoc-cli"])
    import yaml
    from redoc_cli.cli import generate_html

def main():
    """Generate API documentation."""
    print("Generating API documentation...")
    
    # Get paths
    root_dir = Path(__file__).resolve().parent.parent
    openapi_path = root_dir / "docs" / "api" / "openapi.yaml"
    output_path = root_dir / "docs" / "api" / "index.html"
    
    # Check if OpenAPI file exists
    if not openapi_path.exists():
        print(f"Error: OpenAPI file not found at {openapi_path}")
        return 1
    
    try:
        # Load the OpenAPI spec to validate it
        with open(openapi_path, 'r') as f:
            spec = yaml.safe_load(f)
        
        # Generate the HTML documentation
        generate_html(str(openapi_path), str(output_path), {
            'title': 'RE-Architect API Documentation',
            'theme': {
                'colors': {
                    'primary': {
                        'main': '#4CAF50'
                    }
                },
                'typography': {
                    'fontSize': '16px',
                    'fontFamily': 'Roboto, sans-serif'
                }
            }
        })
        
        print(f"API documentation generated at {output_path}")
        print(f"Open the documentation in a browser: file://{output_path}")
        
        return 0
    except Exception as e:
        print(f"Error generating API documentation: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
