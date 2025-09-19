import { createAsyncThunk, createSlice, PayloadAction } from '@reduxjs/toolkit';
import { ProjectWithVersions } from '../../components/comparison/models';
import { FunctionChange, StructureChange } from '../../components/comparison/types';
import { API_BASE_URL } from '../../services/api';

// Types
export type Project = ProjectWithVersions;

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
  baseProjectId: string | null;
  baseVersionId: string | null;
  targetProjectId: string | null;
  targetVersionId: string | null;
  comparisons: Comparison[];
  selectedComparisonId: string | null;
  functionChanges: FunctionChange[];
  structureChanges: StructureChange[];
  metricChanges: MetricChange[];
  selectedFunctionId: string | null;
  selectedStructureId: string | null;
  loading: boolean;
  error: string | null;
}

const initialState: ComparisonState = {
  projects: [],
  baseProjectId: null,
  baseVersionId: null,
  targetProjectId: null,
  targetVersionId: null,
  comparisons: [],
  selectedComparisonId: null,
  functionChanges: [],
  structureChanges: [],
  metricChanges: [],
  selectedFunctionId: null,
  selectedStructureId: null,
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

export const fetchComparison = createAsyncThunk(
  'comparison/fetchComparison',
  async (comparisonId: string, { rejectWithValue }) => {
    try {
      const response = await fetch(`${API_BASE_URL}/comparison/comparisons/${comparisonId}`);
      if (!response.ok) {
        throw new Error('Failed to fetch comparison details');
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
    comparisonId: string,
    { rejectWithValue }
  ) => {
    try {
      const url = `${API_BASE_URL}/comparison/${comparisonId}/functions`;
      
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
    comparisonId: string,
    { rejectWithValue }
  ) => {
    try {
      const url = `${API_BASE_URL}/comparison/${comparisonId}/structures`;
      
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
    comparisonId: string,
    { rejectWithValue }
  ) => {
    try {
      const url = `${API_BASE_URL}/comparison/${comparisonId}/metrics`;
      
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
    selectComparison: (state, action: PayloadAction<string>) => {
      state.selectedComparisonId = action.payload;
    },
    selectProject1: (state, action: PayloadAction<string>) => {
      state.baseProjectId = action.payload;
    },
    selectProject2: (state, action: PayloadAction<string>) => {
      state.targetProjectId = action.payload;
    },
    selectFunction: (state, action: PayloadAction<string>) => {
      state.selectedFunctionId = action.payload;
    },
    selectStructure: (state, action: PayloadAction<string>) => {
      state.selectedStructureId = action.payload;
    },
    clearSelection: (state) => {
      state.baseProjectId = null;
      state.baseVersionId = null;
      state.targetProjectId = null;
      state.targetVersionId = null;
      state.selectedComparisonId = null;
      state.selectedFunctionId = null;
      state.selectedStructureId = null;
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
      state.selectedComparisonId = action.payload.id;
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
  selectComparison,
  selectProject1,
  selectProject2,
  selectFunction,
  selectStructure,
  clearSelection,
  clearError,
} = comparisonSlice.actions;

export default comparisonSlice.reducer;