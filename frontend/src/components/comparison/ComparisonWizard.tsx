import {
    Box,
    Button,
    Dialog,
    DialogActions,
    DialogContent,
    DialogContentText,
    DialogTitle,
    Divider,
    FormControl,
    InputLabel,
    MenuItem,
    Paper,
    Select,
    Step,
    StepLabel,
    Stepper,
    TextField,
    Typography
} from '@mui/material';
import { useState } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { createComparison } from '../../redux/slices/comparisonSlice';

// Type definitions
interface Project {
  id: string;
  name: string;
  versions: Version[];
}

interface Version {
  id: string;
  name: string;
}

// Step labels for the wizard
const steps = ['Select Projects', 'Configure Comparison', 'Review & Submit'];

/**
 * ComparisonWizard component for creating new binary comparisons
 * This wizard guides the user through the process of selecting projects and creating a comparison
 */
interface ComparisonWizardProps {
  open: boolean;
  onClose: () => void;
}

const ComparisonWizard = ({ open, onClose }: ComparisonWizardProps) => {
  const dispatch = useAppDispatch();
  const { projects, loading } = useAppSelector((state) => state.comparison);

  // Wizard state
  const [activeStep, setActiveStep] = useState(0);
  
  // Form state
  const [baseProjectId, setBaseProjectId] = useState<string>('');
  const [baseVersionId, setBaseVersionId] = useState<string>('');
  const [targetProjectId, setTargetProjectId] = useState<string>('');
  const [targetVersionId, setTargetVersionId] = useState<string>('');
  const [comparisonName, setComparisonName] = useState<string>('');
  const [description, setDescription] = useState<string>('');
  const [similarityThreshold, setSimilarityThreshold] = useState<number>(0.7);
  const [ignorePatterns, setIgnorePatterns] = useState<string>('');

  // Get versions for selected projects
  const baseProject = projects.find((p: Project) => p.id === baseProjectId);
  const targetProject = projects.find((p: Project) => p.id === targetProjectId);

  // Validation
  const isStepValid = () => {
    switch (activeStep) {
      case 0: // Project selection
        return baseProjectId && baseVersionId && targetProjectId && targetVersionId;
      case 1: // Configuration
        return comparisonName.trim() !== '';
      default:
        return true;
    }
  };

  const handleNext = () => {
    if (activeStep === steps.length - 1) {
      // Final step - submit the comparison
      submitComparison();
    } else {
      setActiveStep((prevStep) => prevStep + 1);
    }
  };

  const handleBack = () => {
    setActiveStep((prevStep) => prevStep - 1);
  };

  const submitComparison = () => {
    // Dispatch action to create a new comparison
    dispatch(createComparison({
      project1Id: baseProjectId,
      project2Id: targetProjectId,
      name: comparisonName,
      description,
      tags: ignorePatterns.split(',').map((p: string) => p.trim()).filter(Boolean)
    }));
    
    // Close the dialog
    onClose();
  };

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="md"
      fullWidth
    >
      <DialogTitle>Create New Comparison</DialogTitle>
      <Divider />
      
      <DialogContent sx={{ p: 4 }}>
        {/* Stepper */}
        <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
          {steps.map((label) => (
            <Step key={label}>
              <StepLabel>{label}</StepLabel>
            </Step>
          ))}
        </Stepper>

        {/* Step 1: Select Projects */}
        {activeStep === 0 && (
          <Box>
            <DialogContentText sx={{ mb: 3 }}>
              Select the base and target projects and versions to compare.
            </DialogContentText>

            <Paper variant="outlined" sx={{ p: 2, mb: 3 }}>
              <Typography variant="h6" gutterBottom>Base Binary</Typography>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <FormControl fullWidth margin="normal">
                  <InputLabel>Project</InputLabel>
                  <Select
                    value={baseProjectId}
                    label="Project"
                    onChange={(e: any) => setBaseProjectId(e.target.value)}
                  >
                    {projects.map((project: Project) => (
                      <MenuItem key={project.id} value={project.id}>{project.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <FormControl fullWidth margin="normal">
                  <InputLabel>Version</InputLabel>
                  <Select
                    value={baseVersionId}
                    label="Version"
                    disabled={!baseProjectId}
                    onChange={(e: any) => setBaseVersionId(e.target.value)}
                  >
                    {baseProject?.versions.map((version: Version) => (
                      <MenuItem key={version.id} value={version.id}>{version.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
            </Paper>

            <Paper variant="outlined" sx={{ p: 2 }}>
              <Typography variant="h6" gutterBottom>Target Binary</Typography>
              <Box sx={{ display: 'flex', gap: 2 }}>
                <FormControl fullWidth margin="normal">
                  <InputLabel>Project</InputLabel>
                  <Select
                    value={targetProjectId}
                    label="Project"
                    onChange={(e: any) => setTargetProjectId(e.target.value)}
                  >
                    {projects.map((project: Project) => (
                      <MenuItem key={project.id} value={project.id}>{project.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>

                <FormControl fullWidth margin="normal">
                  <InputLabel>Version</InputLabel>
                  <Select
                    value={targetVersionId}
                    label="Version"
                    disabled={!targetProjectId}
                    onChange={(e: any) => setTargetVersionId(e.target.value)}
                  >
                    {targetProject?.versions.map((version: Version) => (
                      <MenuItem key={version.id} value={version.id}>{version.name}</MenuItem>
                    ))}
                  </Select>
                </FormControl>
              </Box>
            </Paper>
          </Box>
        )}

        {/* Step 2: Configure Comparison */}
        {activeStep === 1 && (
          <Box>
            <DialogContentText sx={{ mb: 3 }}>
              Configure the comparison settings.
            </DialogContentText>

            <TextField
              margin="normal"
              label="Comparison Name"
              fullWidth
              value={comparisonName}
              onChange={(e: any) => setComparisonName(e.target.value)}
              helperText="Give your comparison a descriptive name"
              required
            />

            <TextField
              margin="normal"
              label="Description"
              fullWidth
              multiline
              rows={2}
              value={description}
              onChange={(e: any) => setDescription(e.target.value)}
              helperText="Optional description of this comparison"
            />

            <Box sx={{ display: 'flex', gap: 2, mt: 2 }}>
              <TextField
                margin="normal"
                label="Similarity Threshold"
                type="number"
                inputProps={{ min: 0, max: 1, step: 0.05 }}
                value={similarityThreshold}
                onChange={(e: any) => setSimilarityThreshold(Number(e.target.value))}
                helperText="Minimum similarity score (0-1) for function matching"
                sx={{ width: '50%' }}
              />

              <TextField
                margin="normal"
                label="Ignore Patterns"
                fullWidth
                value={ignorePatterns}
                onChange={(e: any) => setIgnorePatterns(e.target.value)}
                helperText="Comma-separated list of function name patterns to ignore"
                sx={{ width: '50%' }}
              />
            </Box>
          </Box>
        )}

        {/* Step 3: Review & Submit */}
        {activeStep === 2 && (
          <Box>
            <DialogContentText sx={{ mb: 3 }}>
              Review your comparison settings before submitting.
            </DialogContentText>

            <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
              <Typography variant="subtitle2" color="text.secondary">Comparison Name</Typography>
              <Typography variant="body1" sx={{ mb: 1 }}>{comparisonName}</Typography>

              <Typography variant="subtitle2" color="text.secondary">Description</Typography>
              <Typography variant="body1" sx={{ mb: 1 }}>{description || "(None provided)"}</Typography>

              <Typography variant="subtitle2" color="text.secondary">Base Project</Typography>
              <Typography variant="body1" sx={{ mb: 1 }}>
                {baseProject?.name} - {baseProject?.versions.find((v: Version) => v.id === baseVersionId)?.name}
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">Target Project</Typography>
              <Typography variant="body1" sx={{ mb: 1 }}>
                {targetProject?.name} - {targetProject?.versions.find((v: Version) => v.id === targetVersionId)?.name}
              </Typography>

              <Typography variant="subtitle2" color="text.secondary">Advanced Settings</Typography>
              <Typography variant="body1" sx={{ mb: 0.5 }}>
                Similarity Threshold: {similarityThreshold}
              </Typography>
              <Typography variant="body1">
                Ignore Patterns: {ignorePatterns || "(None)"}
              </Typography>
            </Paper>

            <Typography variant="body2" color="text.secondary">
              Click "Create Comparison" to start the analysis process. This may take several minutes depending on the size of the binaries.
            </Typography>
          </Box>
        )}
      </DialogContent>

      <DialogActions sx={{ px: 3, pb: 2 }}>
        <Button onClick={onClose}>Cancel</Button>
        <Box sx={{ flex: '1 1 auto' }} />
        {activeStep > 0 && (
          <Button onClick={handleBack}>Back</Button>
        )}
        <Button 
          variant="contained" 
          onClick={handleNext}
          disabled={!isStepValid() || loading}
        >
          {activeStep === steps.length - 1 ? 'Create Comparison' : 'Next'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};

export default ComparisonWizard;