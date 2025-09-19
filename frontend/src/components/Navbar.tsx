import React, { useContext } from 'react';
import { Link } from 'react-router-dom';
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Button,
  Box,
  Tooltip,
} from '@mui/material';
import {
  Brightness4 as DarkModeIcon,
  Brightness7 as LightModeIcon,
  GitHub as GitHubIcon,
  Help as HelpIcon,
} from '@mui/icons-material';
import { ThemeContext } from '../contexts/ThemeContext';

const Navbar: React.FC = () => {
  const { darkMode, toggleDarkMode } = useContext(ThemeContext);

  return (
    <AppBar position="fixed" elevation={0} sx={{ zIndex: (theme) => theme.zIndex.drawer + 1 }}>
      <Toolbar>
        {/* Logo */}
        <Typography
          variant="h6"
          component={Link}
          to="/"
          sx={{
            mr: 2,
            fontWeight: 700,
            color: 'white',
            textDecoration: 'none',
            display: 'flex',
            alignItems: 'center',
          }}
        >
          <Box
            component="img"
            src="/logo.svg"
            alt="RE-Architect Logo"
            sx={{ height: 32, mr: 1 }}
          />
          RE-Architect
        </Typography>

        <Box sx={{ flexGrow: 1 }} />

        {/* Action buttons */}
        <Box sx={{ display: 'flex', alignItems: 'center' }}>
          <Button
            color="inherit"
            component={Link}
            to="/analysis"
            sx={{ mx: 1 }}
          >
            Analyze
          </Button>
          
          <Tooltip title={darkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
            <IconButton onClick={toggleDarkMode} color="inherit">
              {darkMode ? <LightModeIcon /> : <DarkModeIcon />}
            </IconButton>
          </Tooltip>
          
          <Tooltip title="Documentation">
            <IconButton
              color="inherit"
              component="a"
              href="/docs"
              target="_blank"
              rel="noopener noreferrer"
            >
              <HelpIcon />
            </IconButton>
          </Tooltip>
          
          <Tooltip title="GitHub Repository">
            <IconButton
              color="inherit"
              component="a"
              href="https://github.com/yourusername/re-architect"
              target="_blank"
              rel="noopener noreferrer"
            >
              <GitHubIcon />
            </IconButton>
          </Tooltip>
        </Box>
      </Toolbar>
    </AppBar>
  );
};

export default Navbar;
