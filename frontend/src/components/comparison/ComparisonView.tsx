import AddIcon from '@mui/icons-material/Add';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import HomeIcon from '@mui/icons-material/Home';
import SearchIcon from '@mui/icons-material/Search';
import {
    Box,
    Breadcrumbs,
    Button,
    Container,
    Grid,
    InputAdornment,
    Link,
    Paper,
    Tab,
    Tabs,
    TextField,
    Typography,
} from '@mui/material';
import React, { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { fetchComparison, fetchFunctionChanges, fetchProjects, fetchStructureChanges } from '../../redux/slices/comparisonSlice';
import CallGraphVisualization from './CallGraphVisualization';
import ComparisonSummary from './ComparisonSummary';
import FunctionChangesTable from './FunctionChangesTable';
import FunctionDiffViewer from './FunctionDiffViewer';
import ProjectSelector from './ProjectSelector';
import StructureChangesTable from './StructureChangesTable';
import StructureDiffViewer from './StructureDiffViewer';

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

const TabPanel: React.FC<TabPanelProps> = ({ children, value, index, ...other }) => {
  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`comparison-tabpanel-${index}`}
      aria-labelledby={`comparison-tab-${index}`}
      {...other}
    >
      {value === index && (
        <Box sx={{ py: 3 }}>
          {children}
        </Box>
      )}
    </div>
  );
};

/**
 * Main comparison view component
 */
const ComparisonView: React.FC = () => {
  const [tabValue, setTabValue] = useState(0);
  const [selectedFunctionId, setSelectedFunctionId] = useState<string | null>(null);
  const [selectedStructureId, setSelectedStructureId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  
  const dispatch = useAppDispatch();
  const { 
    selectedComparisonId,
    comparisons,
    loading,
    error
  } = useAppSelector((state) => state.comparison);

  // Load projects on component mount
  useEffect(() => {
    dispatch(fetchProjects());
  }, [dispatch]);

  // Load comparison data when a comparison is selected
  useEffect(() => {
    if (selectedComparisonId) {
      dispatch(fetchComparison(selectedComparisonId));
      dispatch(fetchFunctionChanges(selectedComparisonId));
      dispatch(fetchStructureChanges(selectedComparisonId));
    }
  }, [selectedComparisonId, dispatch]);

  // Get selected comparison
  const selectedComparison = selectedComparisonId 
    ? comparisons.find(c => c.id === selectedComparisonId) 
    : null;

  // Event handlers
  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
    setSearchQuery(''); // Clear search query when switching tabs
  };

  const handleViewFunction = (functionId: string) => {
    setSelectedFunctionId(functionId);
  };

  const handleViewStructure = (structureId: string) => {
    setSelectedStructureId(structureId);
  };

  const handleBackToFunctions = () => {
    setSelectedFunctionId(null);
    setSearchQuery(''); // Clear search when going back to list
  };

  const handleBackToStructures = () => {
    setSelectedStructureId(null);
    setSearchQuery(''); // Clear search when going back to list
  };

  return (
    <Container maxWidth="xl" sx={{ mt: 4, mb: 4 }}>
      {/* Breadcrumbs */}
      <Breadcrumbs sx={{ mb: 2 }}>
        <Link
          underline="hover"
          sx={{ display: 'flex', alignItems: 'center' }}
          color="inherit"
          href="/"
        >
          <HomeIcon sx={{ mr: 0.5 }} fontSize="inherit" />
          Home
        </Link>
        <Typography
          sx={{ display: 'flex', alignItems: 'center' }}
          color="text.primary"
        >
          <CompareArrowsIcon sx={{ mr: 0.5 }} fontSize="inherit" />
          Binary Comparison
        </Typography>
      </Breadcrumbs>

      {/* Header with title and actions */}
      <Grid container justifyContent="space-between" alignItems="center" sx={{ mb: 3 }}>
        <Grid item>
          <Typography variant="h4" component="h1" gutterBottom>
            Binary Comparison
          </Typography>
        </Grid>
        <Grid item>
          <Button 
            variant="contained" 
            startIcon={<AddIcon />}
          >
            New Comparison
          </Button>
        </Grid>
      </Grid>

      {/* Content */}
      {!selectedComparisonId ? (
        <ProjectSelector />
      ) : (
        <>
          {/* Comparison tabs */}
          <Paper sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, justifyContent: 'space-between', alignItems: 'center', px: 2, pt: 1 }}>
              <Tabs 
                value={tabValue} 
                onChange={handleTabChange}
                indicatorColor="primary"
                textColor="primary"
                sx={{ borderBottom: 0 }}
              >
                <Tab label="Overview" />
                <Tab label="Functions" />
                <Tab label="Structures" />
                <Tab label="Call Graph" />
              </Tabs>
              
              {/* Search box - only show for Functions and Structures tabs */}
              {(tabValue === 1 || tabValue === 2) && (
                <TextField
                  size="small"
                  placeholder={`Search ${tabValue === 1 ? 'functions' : 'structures'}...`}
                  value={searchQuery}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
                  sx={{ mb: 1, width: { xs: '100%', sm: '250px' } }}
                  InputProps={{
                    startAdornment: (
                      <InputAdornment position="start">
                        <SearchIcon fontSize="small" />
                      </InputAdornment>
                    ),
                  }}
                />
              )}
            </Box>
          </Paper>

          {/* Tab panels */}
          <TabPanel value={tabValue} index={0}>
            <ComparisonSummary comparisonId={selectedComparisonId} />
          </TabPanel>
          
          <TabPanel value={tabValue} index={1}>
            {selectedFunctionId ? (
              <FunctionDiffViewer
                comparisonId={selectedComparisonId}
                functionId={selectedFunctionId}
                onBack={handleBackToFunctions}
              />
            ) : (
              <FunctionChangesTable 
                comparisonId={selectedComparisonId} 
                onViewFunction={handleViewFunction}
                searchQuery={searchQuery}
              />
            )}
          </TabPanel>
          
          <TabPanel value={tabValue} index={2}>
            {selectedStructureId ? (
              <StructureDiffViewer
                comparisonId={selectedComparisonId}
                structureId={selectedStructureId}
                onBack={handleBackToStructures}
              />
            ) : (
              <StructureChangesTable 
                comparisonId={selectedComparisonId}
                onViewStructure={handleViewStructure}
                searchQuery={searchQuery}
              />
            )}
          </TabPanel>
          
          <TabPanel value={tabValue} index={3}>
            {selectedComparisonId && (
              <CallGraphVisualization comparisonId={selectedComparisonId} />
            )}
          </TabPanel>
        </>
      )}
    </Container>
  );
};

export default ComparisonView;