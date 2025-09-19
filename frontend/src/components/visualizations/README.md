# Visualizations Components

This directory contains visualization components for the RE-Architect project.

## Overview

These visualization components provide interactive data representations for binary analysis results:

1. **DashboardSummary**: Overall summary metrics and statistics
2. **FunctionCallGraph**: Force-directed graph showing function call relationships
3. **DataStructureVisualizer**: Tree and sunburst charts for data structure analysis
4. **PerformanceChart**: Bar/line charts for performance metrics

## Component Descriptions

### DashboardSummary

The DashboardSummary component displays aggregated metrics from binary analysis in an easy-to-read format. It shows:

- Total analyzed functions
- Data structure count
- Overall metrics

### FunctionCallGraph

A force-directed graph visualization using react-force-graph to display function call relationships:

- Nodes represent functions
- Links represent calls between functions
- Node size represents function complexity
- Colors indicate function groups/types

### DataStructureVisualizer

Visualizes data structures using ECharts:

- Tree view of data structure hierarchies
- Size/composition visualization using sunburst charts
- Details of fields, offsets, sizes

### PerformanceChart

Uses Recharts to display performance metrics:

- Load time
- Analysis time
- Memory usage
- Function count comparisons

## Usage

These components can be used individually or combined in dashboard views.

Example usage:

```tsx
import FunctionCallGraph from '../components/visualizations/FunctionCallGraph';
import DataStructureVisualizer from '../components/visualizations/DataStructureVisualizer';

// In your component
return (
  <div>
    <FunctionCallGraph data={functionCallData} />
    <DataStructureVisualizer dataStructures={dataStructures} />
  </div>
);
```

## Redux Integration

These components integrate with Redux state management:

1. Components can receive data directly as props for local usage
2. Components connect to the Redux store for global state access
3. Visualization state is managed in `visualizationSlice.ts`

## Data Requirements

Each visualization component has specific data format requirements. See individual component files for detailed TypeScript interfaces.