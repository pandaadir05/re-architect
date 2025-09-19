import React from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  Paper,
  Typography,
  LinearProgress,
} from '@mui/material';
import { useAppSelector } from '../../redux/hooks';
import AddIcon from '@mui/icons-material/Add';
import RemoveIcon from '@mui/icons-material/Remove';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
import CheckIcon from '@mui/icons-material/Check';

/**
 * Component for displaying a summary of comparison results
 */
const ComparisonSummary: React.FC<{ comparisonId: string }> = ({ comparisonId }) => {
  const { comparisons, functionChanges, structureChanges, metricChanges } = useAppSelector(
    (state) => state.comparison
  );

  // Find the selected comparison
  const comparison = comparisons.find(c => c.id === comparisonId);

  if (!comparison) {
    return (
      <Card>
        <CardContent>
          <Typography>No comparison selected</Typography>
        </CardContent>
      </Card>
    );
  }

  // Count changes by type
  const addedFunctions = functionChanges.filter(c => c.change_type === 'ADDED').length;
  const removedFunctions = functionChanges.filter(c => c.change_type === 'REMOVED').length;
  const modifiedFunctions = functionChanges.filter(c => c.change_type === 'MODIFIED').length;
  const renamedFunctions = functionChanges.filter(c => c.change_type === 'RENAMED').length;
  const unchangedFunctions = functionChanges.filter(c => c.change_type === 'UNCHANGED').length;

  const addedStructures = structureChanges.filter(c => c.change_type === 'ADDED').length;
  const removedStructures = structureChanges.filter(c => c.change_type === 'REMOVED').length;
  const modifiedStructures = structureChanges.filter(c => c.change_type === 'MODIFIED').length;
  const unchangedStructures = structureChanges.filter(c => c.change_type === 'UNCHANGED').length;

  // Find metrics with significant changes
  const significantMetrics = metricChanges
    .filter(m => Math.abs(m.change_percentage) > 20)
    .slice(0, 5);

  return (
    <Card elevation={3} sx={{ mb: 4 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Typography variant="h5">{comparison.name}</Typography>
          <Box>
            {comparison.tags?.map((tag, index) => (
              <Chip 
                key={index} 
                label={tag} 
                size="small" 
                color="primary" 
                variant="outlined" 
                sx={{ mr: 0.5 }}
              />
            ))}
          </Box>
        </Box>

        <Typography variant="body2" color="text.secondary" gutterBottom>
          {comparison.description || 'No description provided'}
        </Typography>

        <Divider sx={{ my: 2 }} />

        {/* Similarity scores */}
        <Typography variant="h6" gutterBottom>Similarity Scores</Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Overall</Typography>
              <LinearProgress 
                variant="determinate" 
                value={(comparison.overall_similarity || 0) * 100} 
                sx={{ my: 1, height: 8, borderRadius: 4 }} 
              />
              <Typography variant="h6">
                {Math.round((comparison.overall_similarity || 0) * 100)}%
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Functions</Typography>
              <LinearProgress 
                variant="determinate" 
                value={(comparison.function_similarity || 0) * 100} 
                color="success"
                sx={{ my: 1, height: 8, borderRadius: 4 }} 
              />
              <Typography variant="h6">
                {Math.round((comparison.function_similarity || 0) * 100)}%
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Structures</Typography>
              <LinearProgress 
                variant="determinate" 
                value={(comparison.structure_similarity || 0) * 100} 
                color="secondary"
                sx={{ my: 1, height: 8, borderRadius: 4 }} 
              />
              <Typography variant="h6">
                {Math.round((comparison.structure_similarity || 0) * 100)}%
              </Typography>
            </Paper>
          </Grid>
          <Grid item xs={12} sm={6} md={3}>
            <Paper elevation={0} sx={{ p: 2, bgcolor: 'background.default' }}>
              <Typography variant="body2" color="text.secondary">Call Graph</Typography>
              <LinearProgress 
                variant="determinate" 
                value={(comparison.call_graph_similarity || 0) * 100} 
                color="info"
                sx={{ my: 1, height: 8, borderRadius: 4 }} 
              />
              <Typography variant="h6">
                {Math.round((comparison.call_graph_similarity || 0) * 100)}%
              </Typography>
            </Paper>
          </Grid>
        </Grid>

        {/* Change summary */}
        <Grid container spacing={3}>
          {/* Function changes */}
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" gutterBottom>Function Changes</Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'success.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <AddIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{addedFunctions} Added</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'error.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <RemoveIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{removedFunctions} Removed</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'warning.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <SwapHorizIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{modifiedFunctions} Modified</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'info.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <SwapHorizIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{renamedFunctions} Renamed</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'grey.200',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <CheckIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{unchangedFunctions} Unchanged</Typography>
              </Paper>
            </Box>
          </Grid>

          {/* Structure changes */}
          <Grid item xs={12} md={6}>
            <Typography variant="subtitle1" gutterBottom>Structure Changes</Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'success.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <AddIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{addedStructures} Added</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'error.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <RemoveIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{removedStructures} Removed</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'warning.light',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <SwapHorizIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{modifiedStructures} Modified</Typography>
              </Paper>
              <Paper 
                elevation={0} 
                sx={{ 
                  p: 1, 
                  bgcolor: 'grey.200',
                  display: 'flex',
                  alignItems: 'center'
                }}
              >
                <CheckIcon fontSize="small" sx={{ mr: 0.5 }} />
                <Typography>{unchangedStructures} Unchanged</Typography>
              </Paper>
            </Box>
          </Grid>

          {/* Significant metric changes */}
          {significantMetrics.length > 0 && (
            <Grid item xs={12}>
              <Typography variant="subtitle1" sx={{ mt: 1 }}>Significant Performance Changes</Typography>
              <Grid container spacing={2} sx={{ mt: 1 }}>
                {significantMetrics.map((metric, index) => (
                  <Grid item xs={12} sm={6} md={4} key={index}>
                    <Paper 
                      elevation={0} 
                      sx={{ 
                        p: 2, 
                        bgcolor: metric.change_percentage > 0 ? 'success.light' : 'error.light',
                      }}
                    >
                      <Typography variant="body2">{metric.function_name}</Typography>
                      <Typography variant="subtitle1">
                        {metric.metric_name}: {metric.change_percentage > 0 ? '+' : ''}
                        {metric.change_percentage.toFixed(1)}%
                      </Typography>
                      <Typography variant="caption">
                        {metric.base_value.toFixed(2)} → {metric.target_value.toFixed(2)}
                      </Typography>
                    </Paper>
                  </Grid>
                ))}
              </Grid>
            </Grid>
          )}
        </Grid>
      </CardContent>
    </Card>
  );
};

export default ComparisonSummary;