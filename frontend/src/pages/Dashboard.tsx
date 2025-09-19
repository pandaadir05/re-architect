import {
    Memory as BinaryIcon,
    Folder as FolderIcon,
    History as HistoryIcon,
    BarChart as StatsIcon,
} from '@mui/icons-material';
import {
    Box,
    Button,
    Card,
    CardActionArea,
    CardContent,
    Chip,
    Divider,
    Grid,
    List,
    ListItem,
    ListItemIcon,
    ListItemText,
    Paper,
    Typography,
    CircularProgress,
    Alert,
} from '@mui/material';
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import DashboardSummary from '../components/visualizations/DashboardSummary';
import FunctionCallGraph from '../components/visualizations/FunctionCallGraph';
import DataStructureVisualizer from '../components/visualizations/DataStructureVisualizer';
import PerformanceChart from '../components/visualizations/PerformanceChart';
import api from '../services/api';

// Define interfaces for our data types
interface Analysis {
  id: string;
  name: string;
  date: string;
  functions: number;
  dataStructures: number;
  status: string;
}

interface FunctionNode {
  id: string;
  group: number;
  size: number;
}

interface FunctionLink {
  source: string;
  target: string;
  value: number;
}

interface DataStructureField {
  name: string;
  type: string;
  offset: number;
  size: number;
}

interface DataStructure {
  name: string;
  size: number;
  fields: DataStructureField[];
}

interface PerformanceDataPoint {
  name: string;
  [key: string]: string | number;
}

interface VisualizationData {
  functionCallData: {
    nodes: FunctionNode[];
    links: FunctionLink[];
  };
  dataStructures: DataStructure[];
  performanceData: PerformanceDataPoint[];
}

// Dashboard component
const Dashboard: React.FC = () => {
  // State management for data loading
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Sample recent binary analysis data
  const [recentAnalyses] = useState<Analysis[]>([
    {
      id: 'analysis-1',
      name: 'example.exe',
      date: '2025-09-18',
      functions: 128,
      dataStructures: 24,
      status: 'completed',
    },
    {
      id: 'analysis-2',
      name: 'libsample.so',
      date: '2025-09-15',
      functions: 85,
      dataStructures: 16,
      status: 'completed',
    },
    {
      id: 'analysis-3',
      name: 'firmware.bin',
      date: '2025-09-10',
      functions: 213,
      dataStructures: 41,
      status: 'completed',
    },
  ]);
  
  // Mock visualization data
  const [visualizationData] = useState<VisualizationData>({
    functionCallData: {
      nodes: [
        { id: 'main', group: 1, size: 25 },
        { id: 'initialize', group: 1, size: 15 },
        { id: 'processData', group: 2, size: 20 },
        { id: 'calculateResult', group: 2, size: 18 },
        { id: 'displayOutput', group: 3, size: 15 },
        { id: 'cleanupResources', group: 1, size: 10 },
        { id: 'logError', group: 4, size: 8 },
      ],
      links: [
        { source: 'main', target: 'initialize', value: 2 },
        { source: 'main', target: 'processData', value: 3 },
        { source: 'processData', target: 'calculateResult', value: 5 },
        { source: 'calculateResult', target: 'displayOutput', value: 2 },
        { source: 'main', target: 'cleanupResources', value: 1 },
        { source: 'processData', target: 'logError', value: 1 },
        { source: 'calculateResult', target: 'logError', value: 1 },
      ]
    },
    dataStructures: [
      {
        name: 'UserData',
        size: 128,
        fields: [
          { name: 'id', type: 'uint32', offset: 0, size: 4 },
          { name: 'username', type: 'char[32]', offset: 4, size: 32 },
          { name: 'email', type: 'char[64]', offset: 36, size: 64 },
          { name: 'flags', type: 'uint32', offset: 100, size: 4 },
          { name: 'lastLogin', type: 'time_t', offset: 104, size: 8 },
          { name: 'permissions', type: 'uint16[8]', offset: 112, size: 16 },
        ]
      },
      {
        name: 'FileHeader',
        size: 24,
        fields: [
          { name: 'signature', type: 'char[4]', offset: 0, size: 4 },
          { name: 'version', type: 'uint16', offset: 4, size: 2 },
          { name: 'flags', type: 'uint16', offset: 6, size: 2 },
          { name: 'dataOffset', type: 'uint32', offset: 8, size: 4 },
          { name: 'dataSize', type: 'uint32', offset: 12, size: 4 },
          { name: 'timestamp', type: 'uint64', offset: 16, size: 8 },
        ]
      }
    ],
    performanceData: [
      { name: 'Load Time', binary1: 0.4, binary2: 0.7, binary3: 1.2 },
      { name: 'Analysis Time', binary1: 2.1, binary2: 3.5, binary3: 5.8 },
      { name: 'Memory Usage (MB)', binary1: 45, binary2: 120, binary3: 280 },
      { name: 'Function Count', binary1: 124, binary2: 342, binary3: 580 },
    ]
  });
  
  // In a real application, you would fetch data from your API
  useEffect(() => {
    const fetchDashboardData = async () => {
      try {
        setLoading(true);
        // const response = await api.get('/dashboard');
        // Process data here
        setLoading(false);
      } catch (err) {
        setLoading(false);
        setError('Failed to load dashboard data');
        console.error(err);
      }
    };

    // Uncomment to fetch actual data
    // fetchDashboardData();
  }, []);

  return (
    <Box sx={{ pt: 2, pb: 6 }}>
      <Typography variant="h4" gutterBottom sx={{ mb: 4 }}>
        Dashboard
      </Typography>

      {/* Main action cards */}
      <Grid container spacing={3} sx={{ mb: 6 }}>
        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardActionArea component={Link} to="/analysis" sx={{ height: '100%' }}>
              <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
                <Box display="flex" alignItems="center" mb={2}>
                  <BinaryIcon fontSize="large" color="primary" />
                  <Typography variant="h5" ml={1}>
                    Analyze New Binary
                  </Typography>
                </Box>
                <Typography variant="body1" color="text.secondary" sx={{ mb: 2 }}>
                  Upload a binary file to start the reverse engineering process. 
                  RE-Architect will analyze the file and generate function summaries, 
                  identify data structures, and create test harnesses.
                </Typography>
                <Box sx={{ mt: 'auto' }}>
                  <Button variant="contained" color="primary">
                    Start New Analysis
                  </Button>
                </Box>
              </CardContent>
            </CardActionArea>
          </Card>
        </Grid>

        <Grid item xs={12} md={6}>
          <Card sx={{ height: '100%' }}>
            <CardContent sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
              <Box display="flex" alignItems="center" mb={2}>
                <StatsIcon fontSize="large" color="primary" />
                <Typography variant="h5" ml={1}>
                  System Overview
                </Typography>
              </Box>

              <Grid container spacing={2}>
                <Grid item xs={6}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h3" color="primary">
                      {recentAnalyses.length}
                    </Typography>
                    <Typography variant="body2">Completed Analyses</Typography>
                  </Paper>
                </Grid>
                <Grid item xs={6}>
                  <Paper sx={{ p: 2, textAlign: 'center' }}>
                    <Typography variant="h3" color="primary">
                      {recentAnalyses.reduce((sum: number, analysis: Analysis) => sum + analysis.functions, 0)}
                    </Typography>
                    <Typography variant="body2">Functions Analyzed</Typography>
                  </Paper>
                </Grid>
              </Grid>

              <Box sx={{ mt: 2 }}>
                <Button variant="outlined" component={Link} to="/settings">
                  View System Status
                </Button>
              </Box>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Visualizations section */}
      <Typography variant="h5" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
        <StatsIcon fontSize="medium" sx={{ mr: 1 }} />
        Data Visualizations
      </Typography>
      
      {loading ? (
        <Box sx={{ display: 'flex', justifyContent: 'center', my: 4 }}>
          <CircularProgress />
        </Box>
      ) : error ? (
        <Alert severity="error" sx={{ mb: 4 }}>{error}</Alert>
      ) : (
        <>
          <Grid container spacing={3} sx={{ mb: 4 }}>
            {/* Dashboard Summary */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3, mb: 3 }}>
                <Typography variant="h6" gutterBottom>Dashboard Overview</Typography>
                <DashboardSummary data={recentAnalyses} />
              </Paper>
            </Grid>
            
            {/* Function Call Graph */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" gutterBottom>Function Call Graph</Typography>
                <Box sx={{ height: 'calc(100% - 40px)' }}>
                  <FunctionCallGraph data={visualizationData.functionCallData} />
                </Box>
              </Paper>
            </Grid>
            
            {/* Data Structure Visualizer */}
            <Grid item xs={12} md={6}>
              <Paper sx={{ p: 3, height: 400 }}>
                <Typography variant="h6" gutterBottom>Data Structure Visualization</Typography>
                <Box sx={{ height: 'calc(100% - 40px)' }}>
                  <DataStructureVisualizer dataStructures={visualizationData.dataStructures} />
                </Box>
              </Paper>
            </Grid>
            
            {/* Performance Chart */}
            <Grid item xs={12}>
              <Paper sx={{ p: 3 }}>
                <Typography variant="h6" gutterBottom>Performance Metrics</Typography>
                <PerformanceChart data={visualizationData.performanceData} />
              </Paper>
            </Grid>
          </Grid>
        </>
      )}
      
      {/* Recent analyses */}
      <Typography variant="h5" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
        <HistoryIcon fontSize="medium" sx={{ mr: 1 }} />
        Recent Analyses
      </Typography>

      <Paper sx={{ mb: 4 }}>
        <List>
          {recentAnalyses.map((analysis: Analysis, index: number) => (
            <React.Fragment key={analysis.id}>
              <ListItem
                component={Link}
                to={`/analysis/${analysis.id}`}
                sx={{
                  textDecoration: 'none',
                  color: 'text.primary',
                  '&:hover': {
                    backgroundColor: 'action.hover',
                  },
                }}
              >
                <ListItemIcon>
                  <FolderIcon color="primary" />
                </ListItemIcon>
                <ListItemText
                  primary={analysis.name}
                  secondary={`Analyzed on ${analysis.date} • ${analysis.functions} functions • ${analysis.dataStructures} data structures`}
                />
                <Chip
                  label={analysis.status}
                  color={analysis.status === 'completed' ? 'success' : 'warning'}
                  size="small"
                />
              </ListItem>
              {index < recentAnalyses.length - 1 && <Divider component="li" />}
            </React.Fragment>
          ))}
        </List>
      </Paper>
    </Box>
  );
};

export default Dashboard;
