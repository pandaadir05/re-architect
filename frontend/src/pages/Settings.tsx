import React, { useState } from 'react';
import { 
  Box, 
  Typography, 
  Paper, 
  Grid,
  TextField,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Divider,
  Alert,
  Card,
  CardContent,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
} from '@mui/material';
import {
  SaveOutlined as SaveIcon,
  ApiOutlined as ApiIcon,
  FolderOutlined as FolderIcon,
  BugReportOutlined as BugIcon,
  SecurityOutlined as SecurityIcon,
} from '@mui/icons-material';

const Settings: React.FC = () => {
  const [settings, setSettings] = useState({
    apiKey: '',
    ghidraPath: 'C:/Program Files/Ghidra',
    idaPath: '',
    binaryNinjaPath: '',
    outputDirectory: './results',
    cacheDirectory: './cache',
    enableDynamicAnalysis: false,
    enableSecurity: true,
  });

  const [saved, setSaved] = useState(false);

  const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = event.target;
    setSettings({
      ...settings,
      [name]: value,
    });
    setSaved(false);
  };

  const handleSwitchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    const { name, checked } = event.target;
    setSettings({
      ...settings,
      [name]: checked,
    });
    setSaved(false);
  };

  const handleSelectChange = (event: React.ChangeEvent<{ name?: string; value: unknown }>) => {
    const name = event.target.name as string;
    setSettings({
      ...settings,
      [name]: event.target.value,
    });
    setSaved(false);
  };

  const handleSave = () => {
    // In a real app, we would save the settings to a backend or local storage
    setSaved(true);
    setTimeout(() => {
      setSaved(false);
    }, 3000);
  };

  return (
    <Box sx={{ pt: 2, pb: 6 }}>
      <Typography variant="h4" gutterBottom>
        Settings
      </Typography>
      
      <Grid container spacing={3}>
        {/* API Settings */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <ApiIcon sx={{ mr: 1 }} />
              <Typography variant="h6">
                API Settings
              </Typography>
            </Box>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  name="apiKey"
                  label="OpenAI API Key"
                  value={settings.apiKey}
                  onChange={handleChange}
                  fullWidth
                  type="password"
                  helperText="Required for LLM function summarization"
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        
        {/* Decompiler Paths */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <FolderIcon sx={{ mr: 1 }} />
              <Typography variant="h6">
                Decompiler Paths
              </Typography>
            </Box>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  name="ghidraPath"
                  label="Ghidra Path"
                  value={settings.ghidraPath}
                  onChange={handleChange}
                  fullWidth
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  name="idaPath"
                  label="IDA Pro Path (optional)"
                  value={settings.idaPath}
                  onChange={handleChange}
                  fullWidth
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  name="binaryNinjaPath"
                  label="Binary Ninja Path (optional)"
                  value={settings.binaryNinjaPath}
                  onChange={handleChange}
                  fullWidth
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        
        {/* Output Settings */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <SaveIcon sx={{ mr: 1 }} />
              <Typography variant="h6">
                Output Settings
              </Typography>
            </Box>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <TextField
                  name="outputDirectory"
                  label="Output Directory"
                  value={settings.outputDirectory}
                  onChange={handleChange}
                  fullWidth
                />
              </Grid>
              <Grid item xs={12} md={6}>
                <TextField
                  name="cacheDirectory"
                  label="Cache Directory"
                  value={settings.cacheDirectory}
                  onChange={handleChange}
                  fullWidth
                />
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        
        {/* Analysis Options */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3, mb: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <BugIcon sx={{ mr: 1 }} />
              <Typography variant="h6">
                Analysis Options
              </Typography>
            </Box>
            
            <Grid container spacing={3}>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      name="enableDynamicAnalysis"
                      checked={settings.enableDynamicAnalysis}
                      onChange={handleSwitchChange}
                    />
                  }
                  label="Enable Dynamic Analysis"
                />
                <Typography variant="body2" color="text.secondary" sx={{ ml: 3 }}>
                  Run code in a sandboxed environment (requires Docker)
                </Typography>
              </Grid>
              <Grid item xs={12} md={6}>
                <FormControlLabel
                  control={
                    <Switch
                      name="enableSecurity"
                      checked={settings.enableSecurity}
                      onChange={handleSwitchChange}
                    />
                  }
                  label="Enable Security Analysis"
                />
                <Typography variant="body2" color="text.secondary" sx={{ ml: 3 }}>
                  Detect potential vulnerabilities and security issues
                </Typography>
              </Grid>
            </Grid>
          </Paper>
        </Grid>
        
        {/* System Information */}
        <Grid item xs={12}>
          <Paper sx={{ p: 3 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', mb: 2 }}>
              <SecurityIcon sx={{ mr: 1 }} />
              <Typography variant="h6">
                System Information
              </Typography>
            </Box>
            
            <List dense>
              <ListItem>
                <ListItemText
                  primary="Version"
                  secondary="RE-Architect v0.1.0"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Python Version"
                  secondary="3.11.4"
                />
              </ListItem>
              <ListItem>
                <ListItemText
                  primary="Operating System"
                  secondary="Windows 10"
                />
              </ListItem>
            </List>
          </Paper>
        </Grid>
      </Grid>
      
      <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
        {saved && (
          <Alert severity="success" sx={{ mr: 2 }}>
            Settings saved successfully!
          </Alert>
        )}
        <Button
          variant="contained"
          color="primary"
          onClick={handleSave}
          startIcon={<SaveIcon />}
        >
          Save Settings
        </Button>
      </Box>
    </Box>
  );
};

export default Settings;
