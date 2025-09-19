import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import ContentCopyIcon from '@mui/icons-material/ContentCopy';
import GetAppIcon from '@mui/icons-material/GetApp';
import {
    Box,
    Button,
    Card,
    CardContent,
    Chip,
    Divider,
    Grid,
    IconButton,
    Paper,
    Tab,
    Tabs,
    Tooltip,
    Typography,
} from '@mui/material';
import React, { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { fetchFunctionDetail } from '../../redux/slices/comparisonSlice';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel = (props: TabPanelProps) => {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`diff-tabpanel-${index}`}
      aria-labelledby={`diff-tab-${index}`}
      {...other}
      style={{ width: '100%' }}
    >
      {value === index && (
        <Box sx={{ py: 2, width: '100%' }}>
          {children}
        </Box>
      )}
    </div>
  );
};

// Component for displaying code with line numbers
const CodeBlock: React.FC<{ code: string, title: string }> = ({ code, title }) => {
  const lines = code?.split('\n') || ['No code available'];
  
  const copyToClipboard = () => {
    if (code) {
      navigator.clipboard.writeText(code);
    }
  };

  return (
    <Paper 
      variant="outlined" 
      sx={{ 
        p: 1, 
        bgcolor: 'background.default',
        height: '100%', 
        display: 'flex',
        flexDirection: 'column'
      }}
    >
      <Box sx={{ 
        display: 'flex', 
        justifyContent: 'space-between', 
        alignItems: 'center',
        mb: 1, 
        borderBottom: '1px solid',
        borderColor: 'divider',
        pb: 1
      }}>
        <Typography variant="subtitle2">{title}</Typography>
        <Tooltip title="Copy code">
          <IconButton size="small" onClick={copyToClipboard}>
            <ContentCopyIcon fontSize="small" />
          </IconButton>
        </Tooltip>
      </Box>
      <Box sx={{ 
        fontFamily: 'Consolas, monospace', 
        fontSize: '0.875rem',
        overflow: 'auto',
        flexGrow: 1,
        display: 'flex'
      }}>
        {/* Line numbers */}
        <Box sx={{ 
          color: 'text.secondary',
          bgcolor: 'background.paper',
          pr: 1,
          pl: 1, 
          textAlign: 'right',
          borderRight: '1px solid',
          borderColor: 'divider',
          userSelect: 'none'
        }}>
          {lines.map((_, i) => (
            <div key={i}>{i + 1}</div>
          ))}
        </Box>
        
        {/* Code content */}
        <Box sx={{ pl: 2, whiteSpace: 'pre' }}>
          {lines.map((line, i) => (
            <div key={i}>{line || ' '}</div>
          ))}
        </Box>
      </Box>
    </Paper>
  );
};

// Component to show differences between two code blocks
const DiffViewer: React.FC<{ baseFunctionCode: string, targetFunctionCode: string }> = ({ 
  baseFunctionCode, 
  targetFunctionCode 
}) => {
  // In a real implementation, this would use a diff algorithm to highlight changes
  // For now, we just display the code side by side
  
  return (
    <Grid container spacing={2} sx={{ height: '60vh' }}>
      <Grid item xs={6}>
        <CodeBlock code={baseFunctionCode} title="Base Version" />
      </Grid>
      <Grid item xs={6}>
        <CodeBlock code={targetFunctionCode} title="Target Version" />
      </Grid>
    </Grid>
  );
};

/**
 * Component for viewing detailed function differences 
 */
const FunctionDiffViewer: React.FC<{ 
  functionId: string, 
  comparisonId: string,
  onBack: () => void 
}> = ({ functionId, comparisonId, onBack }) => {
  const [tabValue, setTabValue] = useState(0);
  const dispatch = useAppDispatch();
  const { functionChanges } = useAppSelector((state) => state.comparison);
  
  // Find the selected function
  const selectedFunction = functionChanges.find(func => func.id === functionId);
  
  useEffect(() => {
    if (functionId && comparisonId) {
      // Fetch detailed function information
      dispatch(fetchFunctionDetail({ comparisonId, functionId }));
    }
  }, [functionId, comparisonId, dispatch]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
  };

  if (!selectedFunction) {
    return (
      <Card elevation={3}>
        <CardContent>
          <Typography>Function not found</Typography>
          <Button 
            startIcon={<ArrowBackIcon />} 
            onClick={onBack}
            sx={{ mt: 2 }}
          >
            Back to List
          </Button>
        </CardContent>
      </Card>
    );
  }

  const changeTypeColor = () => {
    switch (selectedFunction.change_type) {
      case 'ADDED': return 'success';
      case 'REMOVED': return 'error';
      case 'MODIFIED': return 'warning';
      case 'RENAMED': return 'info';
      default: return 'default';
    }
  };

  return (
    <Card elevation={3}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <IconButton onClick={onBack}>
              <ArrowBackIcon />
            </IconButton>
            <Typography variant="h5" component="div" sx={{ ml: 1 }}>
              {selectedFunction.function_name}
            </Typography>
            <Chip 
              label={selectedFunction.change_type} 
              color={changeTypeColor()}
              size="small"
              sx={{ ml: 2 }}
            />
          </Box>
          <Button
            variant="outlined"
            size="small"
            startIcon={<GetAppIcon />}
          >
            Export Diff
          </Button>
        </Box>

        <Grid container spacing={2} sx={{ mb: 2 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Base Address</Typography>
              <Typography variant="subtitle1">{selectedFunction.base_address || 'N/A'}</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Target Address</Typography>
              <Typography variant="subtitle1">{selectedFunction.target_address || 'N/A'}</Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Similarity</Typography>
              <Typography variant="subtitle1">
                {selectedFunction.similarity !== undefined 
                  ? `${(selectedFunction.similarity * 100).toFixed(1)}%` 
                  : 'N/A'}
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Status</Typography>
              <Typography variant="subtitle1">{selectedFunction.change_type}</Typography>
            </Paper>
          </Grid>
        </Grid>
        
        <Divider sx={{ my: 2 }} />

        <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 2 }}>
          <Tabs value={tabValue} onChange={handleTabChange} aria-label="function diff tabs">
            <Tab label="Code Diff" />
            <Tab label="Assembly" />
            <Tab label="Call Graph" />
            <Tab label="Metrics" />
          </Tabs>
        </Box>
        
        <TabPanel value={tabValue} index={0}>
          <DiffViewer 
            baseFunctionCode={selectedFunction.base_decompiled_code || '// No code available'} 
            targetFunctionCode={selectedFunction.target_decompiled_code || '// No code available'}
          />
        </TabPanel>
        
        <TabPanel value={tabValue} index={1}>
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
            Assembly view is not implemented in this prototype
          </Typography>
        </TabPanel>
        
        <TabPanel value={tabValue} index={2}>
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
            Call graph visualization is not implemented in this prototype
          </Typography>
        </TabPanel>
        
        <TabPanel value={tabValue} index={3}>
          <Typography variant="body2" color="text.secondary" sx={{ textAlign: 'center', py: 4 }}>
            Function metrics comparison is not implemented in this prototype
          </Typography>
        </TabPanel>
      </CardContent>
    </Card>
  );
};

export default FunctionDiffViewer;