import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Box,
  Typography,
  Grid,
  Card,
  CardContent,
  CardActionArea,
  Button,
  Paper,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Chip,
} from '@mui/material';
import {
  Memory as BinaryIcon,
  History as HistoryIcon,
  BarChart as StatsIcon,
  Folder as FolderIcon,
} from '@mui/icons-material';

// Dashboard component
const Dashboard: React.FC = () => {
  // Sample recent binary analysis data
  const [recentAnalyses] = useState([
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
                      {recentAnalyses.reduce((sum, analysis) => sum + analysis.functions, 0)}
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

      {/* Recent analyses */}
      <Typography variant="h5" sx={{ mb: 2, display: 'flex', alignItems: 'center' }}>
        <HistoryIcon fontSize="medium" sx={{ mr: 1 }} />
        Recent Analyses
      </Typography>

      <Paper sx={{ mb: 4 }}>
        <List>
          {recentAnalyses.map((analysis, index) => (
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
