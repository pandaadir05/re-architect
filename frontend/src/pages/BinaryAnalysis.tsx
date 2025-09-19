import React, { useState } from 'react';
import {
  Box,
  Typography,
  Button,
  Paper,
  Stepper,
  Step,
  StepLabel,
  StepContent,
  TextField,
  CircularProgress,
  Alert,
  Divider,
  Grid,
  Card,
  CardContent,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
} from '@mui/material';
import {
  Upload as UploadIcon,
  Settings as SettingsIcon,
  PlayArrow as StartIcon,
} from '@mui/icons-material';

const BinaryAnalysis: React.FC = () => {
  // State for the stepper
  const [activeStep, setActiveStep] = useState(0);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [analysisComplete, setAnalysisComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Analysis options
  const [analysisOptions, setAnalysisOptions] = useState({
    decompiler: 'ghidra',
    staticAnalysis: true,
    dynamicAnalysis: false,
    llmSummarization: true,
    dataStructureRecovery: true,
    testGeneration: true,
  });

  // Handle file selection
  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files.length > 0) {
      setSelectedFile(event.target.files[0]);
      setError(null);
    }
  };
  
  // Handle analysis options change
  const handleOptionChange = (event: React.ChangeEvent<{ name?: string; value: unknown }>) => {
    const name = event.target.name as string;
    setAnalysisOptions({
      ...analysisOptions,
      [name]: event.target.value,
    });
  };
  
  // Handle toggle switches
  const handleSwitchChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    setAnalysisOptions({
      ...analysisOptions,
      [event.target.name]: event.target.checked,
    });
  };

  // Handle next step
  const handleNext = () => {
    if (activeStep === 0 && !selectedFile) {
      setError('Please select a file to analyze');
      return;
    }
    setActiveStep((prevActiveStep) => prevActiveStep + 1);
    setError(null);
  };

  // Handle back step
  const handleBack = () => {
    setActiveStep((prevActiveStep) => prevActiveStep - 1);
    setError(null);
  };

  // Handle start analysis
  const handleStartAnalysis = () => {
    setAnalyzing(true);
    setError(null);
    
    // Simulate analysis process
    setTimeout(() => {
      setAnalyzing(false);
      setAnalysisComplete(true);
    }, 3000);
  };

  // Steps for the stepper
  const steps = [
    {
      label: 'Select Binary File',
      description: 'Upload the binary file you want to analyze.',
      content: (
        <Box sx={{ mt: 2, mb: 2 }}>
          <Button
            variant="contained"
            component="label"
            startIcon={<UploadIcon />}
            sx={{ mb: 2 }}
          >
            Select File
            <input
              type="file"
              hidden
              onChange={handleFileChange}
              accept=".exe,.dll,.so,.dylib,.bin,.elf"
            />
          </Button>
          
          {selectedFile && (
            <Alert severity="success" sx={{ mt: 2 }}>
              Selected file: {selectedFile.name} ({(selectedFile.size / 1024).toFixed(2)} KB)
            </Alert>
          )}
          
          {error && (
            <Alert severity="error" sx={{ mt: 2 }}>
              {error}
            </Alert>
          )}
        </Box>
      ),
    },
    {
      label: 'Configure Analysis Options',
      description: 'Set the options for the analysis process.',
      content: (
        <Box sx={{ mt: 2, mb: 2 }}>
          <Grid container spacing={3}>
            <Grid item xs={12}>
              <FormControl fullWidth>
                <InputLabel id="decompiler-label">Decompiler</InputLabel>
                <Select
                  labelId="decompiler-label"
                  name="decompiler"
                  value={analysisOptions.decompiler}
                  onChange={handleOptionChange}
                  label="Decompiler"
                >
                  <MenuItem value="ghidra">Ghidra</MenuItem>
                  <MenuItem value="ida">IDA Pro</MenuItem>
                  <MenuItem value="binary_ninja">Binary Ninja</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            
            <Grid item xs={12}>
              <Divider sx={{ my: 1 }}>Analysis Features</Divider>
            </Grid>
            
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={analysisOptions.staticAnalysis}
                    onChange={handleSwitchChange}
                    name="staticAnalysis"
                  />
                }
                label="Static Analysis"
              />
            </Grid>
            
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={analysisOptions.dynamicAnalysis}
                    onChange={handleSwitchChange}
                    name="dynamicAnalysis"
                  />
                }
                label="Dynamic Analysis"
              />
            </Grid>
            
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={analysisOptions.llmSummarization}
                    onChange={handleSwitchChange}
                    name="llmSummarization"
                  />
                }
                label="LLM Function Summarization"
              />
            </Grid>
            
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={analysisOptions.dataStructureRecovery}
                    onChange={handleSwitchChange}
                    name="dataStructureRecovery"
                  />
                }
                label="Data Structure Recovery"
              />
            </Grid>
            
            <Grid item xs={12} sm={6}>
              <FormControlLabel
                control={
                  <Switch
                    checked={analysisOptions.testGeneration}
                    onChange={handleSwitchChange}
                    name="testGeneration"
                  />
                }
                label="Test Harness Generation"
              />
            </Grid>
          </Grid>
        </Box>
      ),
    },
    {
      label: 'Start Analysis',
      description: 'Start the binary analysis process.',
      content: (
        <Box sx={{ mt: 2, mb: 2 }}>
          {!analyzing && !analysisComplete && (
            <>
              <Typography variant="body1" paragraph>
                Ready to analyze {selectedFile?.name}. The analysis will use the following settings:
              </Typography>
              
              <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
                <Typography variant="body2">
                  <strong>Decompiler:</strong> {analysisOptions.decompiler}
                </Typography>
                <Typography variant="body2">
                  <strong>Static Analysis:</strong> {analysisOptions.staticAnalysis ? 'Enabled' : 'Disabled'}
                </Typography>
                <Typography variant="body2">
                  <strong>Dynamic Analysis:</strong> {analysisOptions.dynamicAnalysis ? 'Enabled' : 'Disabled'}
                </Typography>
                <Typography variant="body2">
                  <strong>LLM Summarization:</strong> {analysisOptions.llmSummarization ? 'Enabled' : 'Disabled'}
                </Typography>
                <Typography variant="body2">
                  <strong>Data Structure Recovery:</strong> {analysisOptions.dataStructureRecovery ? 'Enabled' : 'Disabled'}
                </Typography>
                <Typography variant="body2">
                  <strong>Test Generation:</strong> {analysisOptions.testGeneration ? 'Enabled' : 'Disabled'}
                </Typography>
              </Paper>
              
              <Button
                variant="contained"
                color="primary"
                startIcon={<StartIcon />}
                onClick={handleStartAnalysis}
              >
                Start Analysis
              </Button>
            </>
          )}
          
          {analyzing && (
            <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
              <CircularProgress size={60} sx={{ mb: 2 }} />
              <Typography variant="h6">Analyzing {selectedFile?.name}</Typography>
              <Typography variant="body2" color="text.secondary">
                This may take a few minutes depending on the file size and complexity.
              </Typography>
            </Box>
          )}
          
          {analysisComplete && (
            <Alert severity="success" sx={{ mt: 2 }}>
              Analysis completed successfully! You can now view the results.
            </Alert>
          )}
        </Box>
      ),
    },
  ];

  return (
    <Box sx={{ pt: 2, pb: 6 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 4, display: 'flex', alignItems: 'center' }}>
        <SettingsIcon sx={{ mr: 1 }} />
        Binary Analysis
      </Typography>
      
      <Paper sx={{ p: 3 }}>
        <Stepper activeStep={activeStep} orientation="vertical">
          {steps.map((step, index) => (
            <Step key={step.label}>
              <StepLabel>
                <Typography variant="h6">{step.label}</Typography>
              </StepLabel>
              <StepContent>
                <Typography variant="body2" color="text.secondary" paragraph>
                  {step.description}
                </Typography>
                {step.content}
                <Box sx={{ mb: 2 }}>
                  <div>
                    <Button
                      variant="contained"
                      onClick={handleNext}
                      sx={{ mt: 1, mr: 1 }}
                      disabled={analyzing || (index === steps.length - 1 && !analysisComplete)}
                    >
                      {index === steps.length - 1 ? 'Finish' : 'Continue'}
                    </Button>
                    <Button
                      disabled={index === 0 || analyzing}
                      onClick={handleBack}
                      sx={{ mt: 1, mr: 1 }}
                    >
                      Back
                    </Button>
                  </div>
                </Box>
              </StepContent>
            </Step>
          ))}
        </Stepper>
      </Paper>
    </Box>
  );
};

export default BinaryAnalysis;
