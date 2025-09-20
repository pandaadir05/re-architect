# RE-Architect Web Interface

This document describes the web-based user interface for RE-Architect, which provides interactive visualizations and analysis of binary files.

## Overview

RE-Architect's web interface consists of a Flask backend that provides a comprehensive view of the binary analysis results, including:

- Dashboard with summary statistics
- Function browser and detailed views
- Data structure visualizations
- Test harness generation and management
- Settings and configuration options

## Architecture

The web interface is based on a Flask server (`src/visualization/server.py`) that provides REST API endpoints for accessing analysis data.

## Backend API Endpoints

The Flask server provides the following API endpoints:

- `/api/metadata`: Returns metadata about the analyzed binary
- `/api/functions`: Returns all functions identified in the binary
- `/api/function/<func_id>`: Returns details about a specific function
- `/api/data_structures`: Returns all data structures identified in the binary
- `/api/data_structure/<struct_id>`: Returns details about a specific data structure
- `/api/test_harnesses`: Returns all generated test harnesses
- `/api/test_harness/<func_id>`: Returns the test harness for a specific function
- `/api/analysis/<analysis_id>`: Returns results of a specific analysis type
- `/api/performance`: Returns performance metrics of the analysis
- `/api/summary`: Returns summary statistics of the analysis

## Web Interface Components

The web interface provides the following views:

- **Dashboard**: Overview page with summary statistics and charts
- **Function Browser**: View and explore identified functions
- **Data Structure Explorer**: Visualization of data structures and their relationships
- **Test Management**: Interface for managing and running generated test harnesses
- **Settings**: Configuration options for the application

## Getting Started

### Running the Visualization Server

To run the visualization server with real analysis results:

```bash
# Using Docker
make web

# Or directly
python -m flask --app src/visualization/server.py run
```

To run with mock data for development:

```bash
# Using make
make mock-web

# Or directly
python src/visualization/run_mock_server.py
```

### Docker Deployment

For deployment using Docker:

```bash
docker-compose up
```

This will start the Flask backend server, with the web interface accessible at `http://localhost:5000`.

## Screenshots

### Dashboard View

![Dashboard](docs/images/dashboard-screenshot.png)
Dashboard view showing summary statistics and recent activities

### Function Analysis View

![Function Analysis](docs/images/function-view-screenshot.png)
Function view showing decompiled code, summary, and call graph

## Development

To modify the web interface:

1. Changes should be made in `src/visualization/server.py` and related files
2. Run tests to ensure changes don't break existing functionality
3. Use the mock server for rapid development without needing full binary analysis
