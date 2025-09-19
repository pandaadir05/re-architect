# Binary Comparison Feature

This directory contains the React components for the binary comparison feature of the RE-ARCHITECT project.

## Overview

The binary comparison feature allows users to compare two different versions of a binary file, analyzing differences in:

- Functions (added, removed, modified, renamed)
- Data structures (added, removed, modified)
- Call graph structure and relationships
- Performance metrics and characteristics

## Components

### Main Components

- `ComparisonView.tsx`: Main container component for the binary comparison feature
- `ProjectSelector.tsx`: UI for selecting binary projects and versions to compare
- `ComparisonSummary.tsx`: Overview dashboard with similarity scores and change statistics

### Table Components

- `FunctionChangesTable.tsx`: Table displaying function differences between binary versions
- `StructureChangesTable.tsx`: Table displaying data structure differences

### Diff Viewers

- `FunctionDiffViewer.tsx`: Side-by-side code comparison for function implementations
- `StructureDiffViewer.tsx`: Detailed viewer for structure definitions and field changes
- `CallGraphVisualization.tsx`: Visual comparison of call graph relationships

### Supporting Files

- `types.ts`: TypeScript interfaces and types for the comparison feature

## Redux Integration

The comparison feature uses Redux for state management. The relevant slice is in `frontend/src/redux/slices/comparisonSlice.ts`, which handles:

- Loading projects and versions
- Fetching comparison data from the backend API
- Managing the comparison selection state
- Storing comparison results

## API Integration

The comparison feature interacts with several backend API endpoints:

- `/api/projects`: List available binary analysis projects
- `/api/projects/:id/versions`: List versions of a specific project
- `/api/comparisons`: Create or list binary comparisons
- `/api/comparisons/:id`: Get details of a specific comparison
- `/api/comparisons/:id/functions`: Get function changes for a comparison
- `/api/comparisons/:id/structures`: Get structure changes for a comparison
- `/api/comparisons/:id/call-graph`: Get call graph changes for a comparison

## Workflow

1. User selects base and target projects/versions to compare
2. System creates a comparison and runs analysis
3. User can view the comparison summary dashboard
4. User can explore specific function or structure changes
5. User can view detailed differences in side-by-side viewers
6. User can analyze call graph changes and relationships

## Future Enhancements

- Search and filtering capability for large binary comparisons
- Export comparison results to reports (PDF, CSV)
- Automated change annotations using LLMs
- Enhanced call graph visualization with interactive exploration
- Custom comparison configurations (ignore patterns, similarity thresholds)