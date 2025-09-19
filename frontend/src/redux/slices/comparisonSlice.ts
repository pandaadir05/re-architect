import { createAsyncThunk, createSlice, PayloadAction } from '@reduxjs/toolkit';
import { API_BASE_URL } from '../../services/api';

// Types
export interface Project {
  id: string;
  name: string;
  binary_path: string;
  timestamp: string | null;
  version: string;
  description: string;
  tags: string[];
}

export interface Function {
  id: string;
  name: string;
  address: string;
  size: number;
  complexity?: number;
  signature?: string;
  decompiled_code?: string;
  summary?: string;
}

export interface Structure {
  id: string;
  name: string;
  size: number;
  is_union: boolean;
  fields: Array<{
    name: string;
    type_name: string;
    offset: number;
    size: number;
  }>;
}

export interface FunctionChange {
  function_id: string;
  change_type: 'ADDED' | 'REMOVED' | 'MODIFIED' | 'RENAMED' | 'UNCHANGED';
  corresponding_id: string | null;
  function_details?: Function;
  corresponding_function_details?: Function;
}

export interface StructureChange {
  structure_id: string;
  change_type: 'ADDED' | 'REMOVED' | 'MODIFIED' | 'RENAMED' | 'UNCHANGED';
  corresponding_id: string | null;
  structure_details?: Structure;
  corresponding_structure_details?: Structure;
}

export interface MetricChange {
  function_id: string;
  function_name: string;
  metric_name: string;
  base_value: number;
  target_value: number;
  change_percentage: number;
}

export interface Comparison {
  id: string;
  name: string;
  project1_id: string;
  project2_id: string;
  timestamp: string | null;
  description: string;
  tags: string[];
  overall_similarity?: number;
  function_similarity?: number;
  structure_similarity?: number;
  call_graph_similarity?: number;
}

// State
interface ComparisonState {
  projects: Project[];
  selectedProject1: string | null;
  selectedProject2: string | null;
  comparisons: Comparison[];
  selectedComparison: string | null;
  functionChanges: FunctionChange[];
  structureChanges: StructureChange[];
  metricChanges: MetricChange[];
  selectedFunction: string | null;
  selectedStructure: string | null;
  loading: boolean;
  error: string | null;
}

const initialState: ComparisonState = {
  projects: [],
  selectedProject1: null,
  selectedProject2: null,
  comparisons: [],
  selectedComparison: null,
  functionChanges: [],
  structureChanges: [],
  metricChanges: [],
  selectedFunction: null,
  selectedStructure: null,
  loading: false,
  error: null,
};

// Thunks
export const fetchProjects = createAsyncThunk(
  'comparison/fetchProjects',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch(`${API_BASE_URL}/comparison/projects`);
      if (!response.ok) {
        throw new Error('Failed to fetch projects');
      }
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

export const fetchComparisons = createAsyncThunk(
  'comparison/fetchComparisons',
  async (_, { rejectWithValue }) => {
    try {
      const response = await fetch(`${API_BASE_URL}/comparison/comparisons`);
      if (!response.ok) {
        throw new Error('Failed to fetch comparisons');
      }
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

export const createComparison = createAsyncThunk(
  'comparison/createComparison',
  async (
    {
      project1Id,
      project2Id,
      name,
      description,
      tags,
    }: {
      project1Id: string;
      project2Id: string;
      name?: string;
      description?: string;
      tags?: string[];
    },
    { rejectWithValue }
  ) => {
    try {
      const response = await fetch(`${API_BASE_URL}/comparison/compare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          project1_id: project1Id,
          project2_id: project2Id,
          name,
          description,
          tags,
        }),
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to create comparison');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

export const fetchFunctionChanges = createAsyncThunk(
  'comparison/fetchFunctionChanges',
  async (
    {
      comparisonId,
      page = 1,
      pageSize = 50,
      changeType,
      name,
      sort,
    }: {
      comparisonId: string;
      page?: number;
      pageSize?: number;
      changeType?: string;
      name?: string;
      sort?: string;
    },
    { rejectWithValue }
  ) => {
    try {
      let url = `${API_BASE_URL}/comparison/${comparisonId}/functions?page=${page}&page_size=${pageSize}`;
      
      if (changeType) {
        url += `&change_type=${changeType}`;
      }
      
      if (name) {
        url += `&name=${encodeURIComponent(name)}`;
      }
      
      if (sort) {
        url += `&sort=${sort}`;
      }
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error('Failed to fetch function changes');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

export const fetchStructureChanges = createAsyncThunk(
  'comparison/fetchStructureChanges',
  async (
    {
      comparisonId,
      page = 1,
      pageSize = 50,
      changeType,
      name,
      sort,
    }: {
      comparisonId: string;
      page?: number;
      pageSize?: number;
      changeType?: string;
      name?: string;
      sort?: string;
    },
    { rejectWithValue }
  ) => {
    try {
      let url = `${API_BASE_URL}/comparison/${comparisonId}/structures?page=${page}&page_size=${pageSize}`;
      
      if (changeType) {
        url += `&change_type=${changeType}`;
      }
      
      if (name) {
        url += `&name=${encodeURIComponent(name)}`;
      }
      
      if (sort) {
        url += `&sort=${sort}`;
      }
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error('Failed to fetch structure changes');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

export const fetchMetricChanges = createAsyncThunk(
  'comparison/fetchMetricChanges',
  async (
    {
      comparisonId,
      page = 1,
      pageSize = 50,
      function: funcName,
      metric,
      sort,
    }: {
      comparisonId: string;
      page?: number;
      pageSize?: number;
      function?: string;
      metric?: string;
      sort?: string;
    },
    { rejectWithValue }
  ) => {
    try {
      let url = `${API_BASE_URL}/comparison/${comparisonId}/metrics?page=${page}&page_size=${pageSize}`;
      
      if (funcName) {
        url += `&function=${encodeURIComponent(funcName)}`;
      }
      
      if (metric) {
        url += `&metric=${encodeURIComponent(metric)}`;
      }
      
      if (sort) {
        url += `&sort=${sort}`;
      }
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error('Failed to fetch metric changes');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

export const fetchFunctionDetail = createAsyncThunk(
  'comparison/fetchFunctionDetail',
  async (
    {
      comparisonId,
      functionId,
    }: {
      comparisonId: string;
      functionId: string;
    },
    { rejectWithValue }
  ) => {
    try {
      const response = await fetch(
        `${API_BASE_URL}/comparison/${comparisonId}/function/${functionId}`
      );
      
      if (!response.ok) {
        throw new Error('Failed to fetch function detail');
      }
      
      return await response.json();
    } catch (error) {
      return rejectWithValue((error as Error).message);
    }
  }
);

// Slice
const comparisonSlice = createSlice({
  name: 'comparison',
  initialState,
  reducers: {
    selectProject1: (state, action: PayloadAction<string>) => {
      state.selectedProject1 = action.payload;
    },
    selectProject2: (state, action: PayloadAction<string>) => {
      state.selectedProject2 = action.payload;
    },
    selectComparison: (state, action: PayloadAction<string>) => {
      state.selectedComparison = action.payload;
    },
    selectFunction: (state, action: PayloadAction<string>) => {
      state.selectedFunction = action.payload;
    },
    selectStructure: (state, action: PayloadAction<string>) => {
      state.selectedStructure = action.payload;
    },
    clearSelection: (state) => {
      state.selectedProject1 = null;
      state.selectedProject2 = null;
      state.selectedComparison = null;
      state.selectedFunction = null;
      state.selectedStructure = null;
    },
    clearError: (state) => {
      state.error = null;
    },
  },
  extraReducers: (builder) => {
    // Fetch Projects
    builder.addCase(fetchProjects.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(fetchProjects.fulfilled, (state, action) => {
      state.loading = false;
      state.projects = action.payload;
    });
    builder.addCase(fetchProjects.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Fetch Comparisons
    builder.addCase(fetchComparisons.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(fetchComparisons.fulfilled, (state, action) => {
      state.loading = false;
      state.comparisons = action.payload;
    });
    builder.addCase(fetchComparisons.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Create Comparison
    builder.addCase(createComparison.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(createComparison.fulfilled, (state, action) => {
      state.loading = false;
      // Add the new comparison to the list if it's not already there
      if (!state.comparisons.some((c) => c.id === action.payload.id)) {
        state.comparisons.push(action.payload);
      }
      // Select the new comparison
      state.selectedComparison = action.payload.id;
    });
    builder.addCase(createComparison.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Fetch Function Changes
    builder.addCase(fetchFunctionChanges.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(fetchFunctionChanges.fulfilled, (state, action) => {
      state.loading = false;
      state.functionChanges = action.payload.function_changes;
    });
    builder.addCase(fetchFunctionChanges.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Fetch Structure Changes
    builder.addCase(fetchStructureChanges.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(fetchStructureChanges.fulfilled, (state, action) => {
      state.loading = false;
      state.structureChanges = action.payload.structure_changes;
    });
    builder.addCase(fetchStructureChanges.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Fetch Metric Changes
    builder.addCase(fetchMetricChanges.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(fetchMetricChanges.fulfilled, (state, action) => {
      state.loading = false;
      state.metricChanges = action.payload.metric_changes;
    });
    builder.addCase(fetchMetricChanges.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });

    // Fetch Function Detail - This will be handled by the component that needs it
    builder.addCase(fetchFunctionDetail.pending, (state) => {
      state.loading = true;
      state.error = null;
    });
    builder.addCase(fetchFunctionDetail.fulfilled, (state) => {
      state.loading = false;
    });
    builder.addCase(fetchFunctionDetail.rejected, (state, action) => {
      state.loading = false;
      state.error = action.payload as string;
    });
  },
});

export const {
  selectProject1,
  selectProject2,
  selectComparison,
  selectFunction,
  selectStructure,
  clearSelection,
  clearError,
} = comparisonSlice.actions;

export default comparisonSlice.reducer;