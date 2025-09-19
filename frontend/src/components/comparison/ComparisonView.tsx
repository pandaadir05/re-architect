import React, { useEffect, useState } from 'react';
import {
  Box,
  Container,
  Grid,
  Paper,
  Typography,
  Tab,
  Tabs,
  Breadcrumbs,
  Link,
  Button,
} from '@mui/material';
import { useAppSelector, useAppDispatch } from '../../redux/hooks';
import { fetchProjects, fetchComparison, fetchFunctionChanges, fetchStructureChanges } from '../../redux/slices/comparisonSlice';
import ProjectSelector from './ProjectSelector';
import ComparisonSummary from './ComparisonSummary';
import FunctionChangesTable from './FunctionChangesTable';
import StructureChangesTable from './StructureChangesTable';
import HomeIcon from '@mui/icons-material/Home';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import AddIcon from '@mui/icons-material/Add';

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

  // Tab change handler
  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setTabValue(newValue);
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
            <Tabs 
              value={tabValue} 
              onChange={handleTabChange}
              indicatorColor="primary"
              textColor="primary"
              sx={{ borderBottom: 1, borderColor: 'divider' }}
            >
              <Tab label="Overview" />
              <Tab label="Functions" />
              <Tab label="Structures" />
              <Tab label="Call Graph" />
            </Tabs>
          </Paper>

          {/* Tab panels */}
          <TabPanel value={tabValue} index={0}>
            <ComparisonSummary comparisonId={selectedComparisonId} />
          </TabPanel>
          
          <TabPanel value={tabValue} index={1}>
            <FunctionChangesTable comparisonId={selectedComparisonId} />
          </TabPanel>
          
          <TabPanel value={tabValue} index={2}>
            <StructureChangesTable comparisonId={selectedComparisonId} />
          </TabPanel>
          
          <TabPanel value={tabValue} index={3}>
            <Paper elevation={3} sx={{ p: 3, textAlign: 'center' }}>
              <Typography variant="h6" color="text.secondary">
                Call Graph Visualization
              </Typography>
              <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
                This feature is coming soon
              </Typography>
            </Paper>
          </TabPanel>
        </>
      )}
    </Container>
  );
};

export default ComparisonView;