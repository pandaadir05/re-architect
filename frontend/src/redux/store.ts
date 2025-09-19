import { configureStore } from '@reduxjs/toolkit';
import analysisReducer from './slices/analysisSlice';
import uiReducer from './slices/uiSlice';
import visualizationReducer from './slices/visualizationSlice';

export const store = configureStore({
  reducer: {
    analysis: analysisReducer,
    ui: uiReducer,
    visualization: visualizationReducer,
  },
});

// Infer the `RootState` and `AppDispatch` types from the store itself
export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;