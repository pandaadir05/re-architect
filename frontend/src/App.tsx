import { Box, createTheme, CssBaseline, ThemeProvider } from '@mui/material';
import React, { useEffect, useState } from 'react';
import { useDispatch } from 'react-redux';
import { Route, Routes, useLocation } from 'react-router-dom';

// Import components
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import ProtectedRoute from './components/auth/ProtectedRoute';
import BinaryAnalysis from './pages/BinaryAnalysis';
import BinaryComparison from './pages/BinaryComparison';
import Dashboard from './pages/Dashboard';
import DataStructureView from './pages/DataStructureView';
import FunctionView from './pages/FunctionView';
import Settings from './pages/Settings';
import TestHarness from './pages/TestHarness';
import LoginPage from './pages/auth/LoginPage';
import RegisterPage from './pages/auth/RegisterPage';

// Import theme context and authentication
import { ThemeContext } from './contexts/ThemeContext';
import { fetchCurrentUser } from './redux/slices/auth/authSlice';
import { AppDispatch } from './redux/store';

const App: React.FC = () => {
  // State for theme mode (light/dark)
  const [darkMode, setDarkMode] = useState(true);
  const dispatch = useDispatch<AppDispatch>();
  const location = useLocation();

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

  // Check authentication status on initial load
  useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      dispatch(fetchCurrentUser());
    }
  }, [dispatch]);

  // Toggle theme function
  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };
  
  // Determine if we're on an auth page (login/register)
  const isAuthPage = ['/login', '/register'].includes(location.pathname);

  return (
    <ThemeContext.Provider value={{ darkMode, toggleDarkMode }}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {isAuthPage ? (
          <Box sx={{ display: 'flex', height: '100vh', bgcolor: 'background.default' }}>
            <Routes>
              <Route path="/login" element={<LoginPage />} />
              <Route path="/register" element={<RegisterPage />} />
            </Routes>
          </Box>
        ) : (
          <Box sx={{ display: 'flex', height: '100vh' }}>
            <Navbar />
            <Sidebar />
            <Box component="main" sx={{ flexGrow: 1, p: 2, overflow: 'auto' }}>
              <Box sx={{ height: 64 }} /> {/* Toolbar spacing */}
              <Routes>
                <Route path="/" element={
                  <ProtectedRoute>
                    <Dashboard />
                  </ProtectedRoute>
                } />
                <Route path="/analysis" element={
                  <ProtectedRoute>
                    <BinaryAnalysis />
                  </ProtectedRoute>
                } />
                <Route path="/comparison" element={
                  <ProtectedRoute>
                    <BinaryComparison />
                  </ProtectedRoute>
                } />
                <Route path="/functions/:id" element={
                  <ProtectedRoute>
                    <FunctionView />
                  </ProtectedRoute>
                } />
                <Route path="/structures/:id" element={
                  <ProtectedRoute>
                    <DataStructureView />
                  </ProtectedRoute>
                } />
                <Route path="/tests" element={
                  <ProtectedRoute>
                    <TestHarness />
                  </ProtectedRoute>
                } />
                <Route path="/settings" element={
                  <ProtectedRoute adminOnly={true}>
                    <Settings />
                  </ProtectedRoute>
                } />
              </Routes>
            </Box>
          </Box>
        )}
      </ThemeProvider>
    </ThemeContext.Provider>
  );
};

export default App;
