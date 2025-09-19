import {
    Code as CodeIcon,
    Compare as CompareIcon,
    Dashboard as DashboardIcon,
    DataObject as DataObjectIcon,
    Science as ScienceIcon,
    Settings as SettingsIcon,
} from '@mui/icons-material';
import {
    Box,
    Divider,
    Drawer,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Toolbar,
} from '@mui/material';
import React from 'react';
import { Link, useLocation } from 'react-router-dom';

// Define drawer width
const drawerWidth = 240;

const Sidebar: React.FC = () => {
  const location = useLocation();

  // Define menu items
  const menuItems = [
    { text: 'Dashboard', icon: <DashboardIcon />, path: '/' },
    { text: 'Binary Analysis', icon: <CodeIcon />, path: '/analysis' },
    { text: 'Binary Comparison', icon: <CompareIcon />, path: '/comparison' },
    { text: 'Data Structures', icon: <DataObjectIcon />, path: '/structures' },
    { text: 'Test Harnesses', icon: <ScienceIcon />, path: '/tests' },
    { text: 'Settings', icon: <SettingsIcon />, path: '/settings' },
  ];

  return (
    <Drawer
      variant="permanent"
      sx={{
        width: drawerWidth,
        flexShrink: 0,
        '& .MuiDrawer-paper': {
          width: drawerWidth,
          boxSizing: 'border-box',
          backgroundColor: (theme) => 
            theme.palette.mode === 'dark' ? '#1e1e1e' : '#f5f5f5',
        },
      }}
    >
      <Toolbar /> {/* This pushes content below app bar */}
      <Box sx={{ overflow: 'auto', height: '100%' }}>
        <List>
          {menuItems.map((item) => (
            <ListItem
              button
              component={Link}
              to={item.path}
              key={item.text}
              selected={location.pathname === item.path}
              sx={{
                my: 0.5,
                borderRadius: '8px',
                mx: 1,
                '&.Mui-selected': {
                  backgroundColor: (theme) =>
                    theme.palette.mode === 'dark' ? 'rgba(121, 134, 203, 0.2)' : 'rgba(63, 81, 181, 0.1)',
                },
              }}
            >
              <ListItemIcon
                sx={{
                  color: (theme) =>
                    location.pathname === item.path
                      ? theme.palette.primary.main
                      : 'inherit',
                }}
              >
                {item.icon}
              </ListItemIcon>
              <ListItemText primary={item.text} />
            </ListItem>
          ))}
        </List>
        <Divider sx={{ my: 2 }} />
        <Box sx={{ p: 2, position: 'absolute', bottom: 0, width: '100%' }}>
          <Box sx={{ textAlign: 'center', mb: 1, fontSize: '0.8rem', opacity: 0.7 }}>
            RE-Architect v0.1.0
          </Box>
        </Box>
      </Box>
    </Drawer>
  );
};

export default Sidebar;
