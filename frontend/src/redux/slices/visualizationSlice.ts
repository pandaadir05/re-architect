import { createSlice, PayloadAction } from '@reduxjs/toolkit';

// Types for function call graph
export interface FunctionNode {
  id: string;
  group: number;
  size: number;
}

export interface FunctionLink {
  source: string;
  target: string;
  value: number;
}

export interface FunctionCallGraph {
  nodes: FunctionNode[];
  links: FunctionLink[];
}

// Types for data structures
export interface DataStructureField {
  name: string;
  type: string;
  offset: number;
  size: number;
}

export interface DataStructure {
  name: string;
  size: number;
  fields: DataStructureField[];
}

// Types for performance data
export interface PerformanceDataPoint {
  name: string;
  [key: string]: string | number;
}

// Visualization state
interface VisualizationState {
  functionCallGraph: FunctionCallGraph;
  dataStructures: DataStructure[];
  performanceData: PerformanceDataPoint[];
  selectedVisualization: string;
  loading: boolean;
  error: string | null;
}

const initialState: VisualizationState = {
  functionCallGraph: {
    nodes: [],
    links: [],
  },
  dataStructures: [],
  performanceData: [],
  selectedVisualization: 'functionCallGraph',
  loading: false,
  error: null,
};

export const visualizationSlice = createSlice({
  name: 'visualization',
  initialState,
  reducers: {
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload;
    },
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload;
    },
    setFunctionCallGraph: (state, action: PayloadAction<FunctionCallGraph>) => {
      state.functionCallGraph = action.payload;
    },
    setDataStructures: (state, action: PayloadAction<DataStructure[]>) => {
      state.dataStructures = action.payload;
    },
    setPerformanceData: (state, action: PayloadAction<PerformanceDataPoint[]>) => {
      state.performanceData = action.payload;
    },
    setSelectedVisualization: (state, action: PayloadAction<string>) => {
      state.selectedVisualization = action.payload;
    },
  },
});

export const { 
  setLoading, 
  setError, 
  setFunctionCallGraph, 
  setDataStructures,
  setPerformanceData,
  setSelectedVisualization
} = visualizationSlice.actions;

export default visualizationSlice.reducer;