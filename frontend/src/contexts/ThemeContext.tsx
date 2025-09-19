import React from 'react';

// Define the shape of the context value
interface ThemeContextType {
  darkMode: boolean;
  toggleDarkMode: () => void;
}

// Create context with default values
export const ThemeContext = React.createContext<ThemeContextType>({
  darkMode: true,
  toggleDarkMode: () => {},
});
