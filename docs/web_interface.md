# Web Interface Guide

## Overview

RE-Architect provides a web-based interface for interactive exploration of binary analysis results. The visualization server offers an intuitive way to browse functions, data structures, and test harnesses generated during analysis.

## Starting the Web Server

### During Analysis

Start the web server automatically after analysis:

```bash
python main.py binary.exe --serve
```

This will:
1. Perform the complete analysis
2. Start the web server on `http://localhost:5000`
3. Open your default browser (optional)

### With Existing Results

Load previously generated analysis results:

```python
from src.visualization.server import VisualizationServer

server = VisualizationServer(host="localhost", port=5000)
server.load_results_from_file("./output/results.json")
server.start()
```

### Mock Data Server

For testing and development purposes:

```bash
python src/visualization/run_mock_server.py
```

Or using the Makefile:

```bash
make mock-web
```

## Web Interface Features

### Dashboard

The main dashboard provides an overview of analysis results:

- **Analysis Summary**: Binary metadata, analysis time, function count
- **Function Statistics**: Distribution by complexity, size, and type
- **Data Structure Overview**: Recovered structures and their relationships
- **Test Coverage**: Generated test harnesses and coverage metrics

### Function Explorer

Browse and analyze individual functions:

**Function List:**
- Sortable by name, address, size, complexity
- Filterable by various criteria
- Search functionality for quick navigation

**Function Details:**
- Decompiled C code with syntax highlighting
- Assembly code view (if available)
- LLM-generated summary and analysis
- Parameter and return value information
- Call graph visualization
- Security analysis results

**Interactive Features:**
- Code folding and expansion
- Cross-reference navigation
- Function comparison side-by-side

### Data Structure Viewer

Explore recovered data structures:

**Structure Browser:**
- List of all identified structures
- Size and field information
- Usage frequency and locations

**Structure Visualization:**
- Memory layout diagrams
- Field offset calculations
- Type relationship graphs
- Usage patterns

### Test Harness Manager

Review and manage generated test harnesses:

**Test Overview:**
- List of all generated tests
- Coverage information
- Execution status

**Test Details:**
- Complete test source code
- Compilation instructions
- Expected results and validation
- Coverage reports

### Call Graph Visualization

Interactive call graph exploration:

**Graph Features:**
- Hierarchical function relationships
- Zoom and pan capabilities
- Node filtering and highlighting
- Path analysis between functions

**Analysis Tools:**
- Critical path identification
- Dependency analysis
- Dead code detection
- Entry point discovery

## API Endpoints

The web server provides REST API endpoints for programmatic access:

### Functions API

**Get all functions:**
```
GET /api/functions
```

**Get specific function:**
```
GET /api/function/<function_id>
```

Example response:
```json
{
  "id": "1",
  "name": "main",
  "address": "0x401000",
  "size": 64,
  "code": "int main() { return 0; }",
  "summary": "Main entry point function",
  "complexity": 2.5,
  "parameters": [],
  "return_type": "int"
}
```

### Data Structures API

**Get all data structures:**
```
GET /api/data-structures
```

**Get specific structure:**
```
GET /api/data-structure/<structure_id>
```

### Test Harnesses API

**Get all test harnesses:**
```
GET /api/test-harnesses
```

**Get specific test:**
```
GET /api/test-harness/<test_id>
```

### Metadata API

**Get analysis metadata:**
```
GET /api/metadata
```

### Health Check

**Server health status:**
```
GET /health
```

## Configuration

### Server Settings

Configure the web server in `config.yaml`:

```yaml
visualization:
  server:
    host: localhost
    port: 5000
    debug: false
    auth_required: false
  ui:
    theme: dark  # light, dark
    show_disassembly: true
    show_decompiled: true
    show_graph: true
    show_data_flow: true
```

### Authentication (Optional)

Enable basic authentication:

```yaml
visualization:
  server:
    auth_required: true
    username: admin
    password: your_secure_password
```

### Theming

The interface supports light and dark themes:

```yaml
visualization:
  ui:
    theme: dark
    syntax_highlighting: true
    font_size: 12
    font_family: "Monaco, Consolas, monospace"
```

## Custom Styling

### CSS Customization

Create custom styles in `static/css/custom.css`:

```css
/* Custom function highlighting */
.function-critical {
    border-left: 4px solid #ff4444;
}

.function-safe {
    border-left: 4px solid #44ff44;
}

/* Custom complexity colors */
.complexity-low { color: #00ff00; }
.complexity-medium { color: #ffaa00; }
.complexity-high { color: #ff0000; }
```

### JavaScript Extensions

Add custom functionality in `static/js/custom.js`:

```javascript
// Custom function analysis
function analyzeFunction(functionData) {
    // Custom analysis logic
    if (functionData.name.startsWith('_')) {
        return 'internal';
    }
    return 'user';
}

// Custom event handlers
$(document).ready(function() {
    $('.function-item').click(function() {
        // Custom click handling
    });
});
```

## Advanced Features

### Real-time Updates

The web interface can display real-time analysis progress:

```python
from src.visualization.server import VisualizationServer
from src.core.pipeline import ReversePipeline

server = VisualizationServer()

# Start server in background
server.start_background()

# Perform analysis with progress updates
pipeline = ReversePipeline(config)
results = pipeline.analyze_with_progress(
    binary_path="binary.exe",
    progress_callback=server.update_progress
)
```

### Export Features

Export analysis results in various formats:

**PDF Report:**
- Complete analysis summary
- Function listings with code
- Data structure diagrams
- Test harness documentation

**Excel Spreadsheet:**
- Function metadata
- Statistical analysis
- Comparison tables

**JSON Export:**
- Complete machine-readable results
- API-compatible format
- Cross-tool integration

### Integration with IDEs

#### VS Code Extension

Install the RE-Architect VS Code extension:

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "RE-Architect"
4. Install the extension

Features:
- Syntax highlighting for decompiled code
- Function navigation
- Integrated web viewer
- Analysis result browser

#### Sublime Text Plugin

Install via Package Control:

```
Package Control: Install Package
RE-Architect Analysis Viewer
```

## Troubleshooting

### Common Issues

**Server won't start:**
- Check if port 5000 is already in use
- Verify Flask is installed: `pip install flask`
- Check firewall settings

**No results displayed:**
- Ensure analysis results are loaded
- Check the `/health` endpoint
- Verify file permissions on result files

**Slow performance:**
- Reduce the number of functions displayed per page
- Enable result caching
- Optimize browser cache settings

**Visualization not updating:**
- Clear browser cache
- Check browser console for JavaScript errors
- Verify WebSocket connections (if real-time updates enabled)

### Debug Mode

Enable debug mode for development:

```python
server = VisualizationServer(debug=True)
```

Or in configuration:

```yaml
visualization:
  server:
    debug: true
```

Debug mode provides:
- Detailed error messages
- Auto-reload on file changes
- Request/response logging

### Performance Optimization

**Large Binary Analysis:**
```yaml
visualization:
  server:
    max_functions_per_page: 50
    enable_caching: true
    cache_timeout: 3600  # seconds
```

**Memory Optimization:**
```yaml
visualization:
  ui:
    lazy_loading: true
    virtual_scrolling: true
    code_folding: true
```

## Security Considerations

### Network Security

**HTTPS Support:**
```python
app.run(
    host='0.0.0.0',
    port=5000,
    ssl_context='adhoc'  # For development only
)
```

For production, use proper SSL certificates:
```python
ssl_context = ('cert.pem', 'key.pem')
app.run(ssl_context=ssl_context)
```

**Access Control:**
- Enable authentication for sensitive analysis
- Use reverse proxy (nginx) for production deployments
- Implement IP whitelisting if needed

### Content Security

**Input Validation:**
- All user inputs are sanitized
- File uploads are restricted and validated
- XSS protection enabled

**Data Protection:**
- Analysis results are not cached in browser
- Sensitive data can be redacted from display
- Optional data encryption for stored results

## Deployment

### Development Deployment

For local development:

```bash
python main.py binary.exe --serve
```

### Production Deployment

#### Using Gunicorn

```bash
# Install gunicorn
pip install gunicorn

# Start with multiple workers
gunicorn -w 4 -b 0.0.0.0:5000 "src.visualization.server:create_app()"
```

#### Using Docker

```dockerfile
FROM python:3.11

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "src.visualization.server:create_app()"]
```

#### Using nginx Reverse Proxy

```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
    
    location /static {
        alias /app/static;
        expires 1y;
    }
}
```

### Cloud Deployment

#### AWS EC2

1. Launch EC2 instance with Python 3.11+
2. Install dependencies: `pip install -r requirements.txt`
3. Configure security groups for port 5000
4. Start with systemd service

#### Heroku

```bash
# Create Procfile
echo "web: gunicorn src.visualization.server:create_app()" > Procfile

# Deploy
heroku create your-app-name
git push heroku main
```

## Browser Support

**Supported Browsers:**
- Chrome 90+
- Firefox 85+
- Safari 14+
- Edge 90+

**Required Features:**
- JavaScript ES6+ support
- WebSocket support (for real-time updates)
- CSS Grid and Flexbox
- Local Storage

## Contributing

To contribute to the web interface:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/web-enhancement`
3. Make changes in `src/visualization/`
4. Add tests in `tests/visualization/`
5. Submit pull request

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Start development server
python src/visualization/run_mock_server.py

# Run tests
pytest tests/visualization/
```

The web interface is built with:
- Flask (backend)
- Bootstrap (UI framework)
- D3.js (visualizations)
- jQuery (DOM manipulation)
- Prism.js (syntax highlighting)