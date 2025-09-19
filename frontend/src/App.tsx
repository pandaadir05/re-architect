import React, { useState } from 'react';
import { Routes, Route } from 'react-router-dom';
import { Box, ThemeProvider, createTheme } from '@mui/material';

// Import components
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import BinaryAnalysis from './pages/BinaryAnalysis';
import FunctionView from './pages/FunctionView';
import DataStructureView from './pages/DataStructureView';
import TestHarness from './pages/TestHarness';
import Settings from './pages/Settings';

// Import theme context
import { ThemeContext } from './contexts/ThemeContext';

const App: React.FC = () => {
  // State for theme mode (light/dark)
  const [darkMode, setDarkMode] = useState(true);

  // Create theme based on mode
  const theme = createTheme({
    palette: {
      mode: darkMode ? 'dark' : 'light',
      primary: {
        main: darkMode ? '#7986cb' : '#3f51b5',
      },
      secondary: {
        main: darkMode ? '#4db6ac' : '#00796b',
      },
      background: {
        default: darkMode ? '#121212' : '#f5f5f5',
        paper: darkMode ? '#1e1e1e' : '#ffffff',
      },
    },
  });

  // Toggle theme function
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  return (
    <ThemeContext.Provider value={{ darkMode, toggleDarkMode }}>
      <ThemeProvider theme={theme}>
        <Box sx={{ display: 'flex', height: '100vh' }}>
          <Navbar />
          <Sidebar />
          <Box component="main" sx={{ flexGrow: 1, p: 2, overflow: 'auto' }}>
            <Box sx={{ height: 64 }} /> {/* Toolbar spacing */}
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/analysis" element={<BinaryAnalysis />} />
              <Route path="/functions/:id" element={<FunctionView />} />
              <Route path="/structures/:id" element={<DataStructureView />} />
              <Route path="/tests" element={<TestHarness />} />
              <Route path="/settings" element={<Settings />} />
            </Routes>
          </Box>
        </Box>
      </ThemeProvider>
    </ThemeContext.Provider>
  );
};

export default App;
