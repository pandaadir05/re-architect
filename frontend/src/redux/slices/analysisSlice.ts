import { createSlice, PayloadAction } from '@reduxjs/toolkit';

export interface Analysis {
  id: string;
  name: string;
  date: string;
  functions: number;
  dataStructures: number;
  status: 'completed' | 'in-progress' | 'failed';
}

interface AnalysisState {
  analyses: Analysis[];
  currentAnalysis: Analysis | null;
  loading: boolean;
  error: string | null;
}

const initialState: AnalysisState = {
  analyses: [],
  currentAnalysis: null,
  loading: false,
  error: null,
};

export const analysisSlice = createSlice({
  name: 'analysis',
  initialState,
  reducers: {
    setLoading: (state, action: PayloadAction<boolean>) => {
      state.loading = action.payload;
    },
    setError: (state, action: PayloadAction<string | null>) => {
      state.error = action.payload;
    },
    setAnalyses: (state, action: PayloadAction<Analysis[]>) => {
      state.analyses = action.payload;
    },
    addAnalysis: (state, action: PayloadAction<Analysis>) => {
      state.analyses.push(action.payload);
    },
    setCurrentAnalysis: (state, action: PayloadAction<Analysis | null>) => {
      state.currentAnalysis = action.payload;
    },
    updateAnalysisStatus: (state, action: PayloadAction<{ id: string; status: Analysis['status'] }>) => {
      const { id, status } = action.payload;
      const analysis = state.analyses.find(a => a.id === id);
      if (analysis) {
        analysis.status = status;
      }
      if (state.currentAnalysis && state.currentAnalysis.id === id) {
        state.currentAnalysis.status = status;
      }
    },
  },
});

export const { 
  setLoading, 
  setError, 
  setAnalyses, 
  addAnalysis, 
  setCurrentAnalysis,
  updateAnalysisStatus
} = analysisSlice.actions;

export default analysisSlice.reducer;