import { render, screen } from '@testing-library/react';
import App from '../App';
import { BrowserRouter } from 'react-router-dom';

// Mock the API service
jest.mock('../services/api', () => ({
  getSummary: jest.fn().mockResolvedValue({
    total_functions: 100,
    total_data_structures: 25,
    total_tests: 33,
    total_vulnerabilities: 5,
    binary_name: 'example.exe',
    analysis_time: 325.5,
  }),
}));

// Mock ThemeContext
jest.mock('../contexts/ThemeContext', () => ({
  useTheme: () => ({
    darkMode: false,
    toggleDarkMode: jest.fn(),
  }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => <>{children}</>,
}));

describe('App Component', () => {
  test('renders without crashing', () => {
    render(
      <BrowserRouter>
        <App />
      </BrowserRouter>
    );
    
    // Basic check to see if the App renders
    expect(document.body).toBeInTheDocument();
  });

  // Add more tests as needed
});
