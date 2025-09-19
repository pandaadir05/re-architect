# RE-Architect Web Interface

This document describes the web-based user interface for RE-Architect, which provides interactive visualizations and analysis of binary files.

## Overview

RE-Architect's web interface consists of a Flask backend serving a React frontend. The interface provides a comprehensive view of the binary analysis results, including:

- Dashboard with summary statistics
- Function browser and detailed views
- Data structure visualizations
- Test harness generation and management
- Settings and configuration options

## Architecture

The web interface is composed of two main components:

1. **Backend**: A Flask server (`src/visualization/server.py`) that serves the React application and provides REST API endpoints for accessing analysis data.
2. **Frontend**: A React application built with TypeScript and Material-UI that provides an intuitive user interface for exploring analysis results.

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

## Frontend Components

The React frontend is organized into the following components:

- **App**: Main application component that sets up routing and global state
- **Navbar**: Top navigation bar with application controls
- **Sidebar**: Navigation sidebar for accessing different parts of the application
- **Dashboard**: Overview page with summary statistics and charts
- **BinaryAnalysis**: Page for exploring the binary structure and properties
- **FunctionView**: Detailed view of a specific function with decompiled code and summaries
- **DataStructureView**: Visualization of data structures and their relationships
- **TestHarness**: Page for managing and running generated test harnesses
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

### Running the Frontend in Development Mode

To run the frontend in development mode:

```bash
# Using make
make frontend

# Or directly
cd frontend && npm start
```

### Docker Deployment

For a complete deployment with both backend and frontend:

```bash
docker-compose up
```

This will start both the Flask backend and the React frontend, with the frontend accessible at `http://localhost:3000` and the API at `http://localhost:5000/api`.

## Screenshots

### Dashboard View

![Dashboard](docs/images/dashboard-screenshot.png)
Dashboard view showing summary statistics and recent activities

### Function Analysis View

![Function Analysis](docs/images/function-view-screenshot.png)
Function view showing decompiled code, summary, and call graph

## Development

To modify the web interface:

1. Backend changes should be made in `src/visualization/server.py`
2. Frontend changes should be made in the `frontend/` directory
3. Run tests to ensure changes don't break existing functionality
4. Use the mock server for rapid development without needing full binary analysis
