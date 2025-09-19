import { Box, Paper, Typography } from '@mui/material';
import React from 'react';
import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { PerformanceMetrics } from '../../services/api';

interface PerformanceChartProps {
  metrics: PerformanceMetrics;
  width?: number | string;
  height?: number | string;
}

/**
 * Component to visualize performance metrics from binary analysis
 */
const PerformanceChart: React.FC<PerformanceChartProps> = ({
  metrics,
  width = '100%',
  height = 400,
}) => {
  // Transform metrics data for the chart
  const getChartData = () => {
    return [
      {
        name: 'Loading',
        time: metrics?.loading_time || 0,
        color: '#8884d8',
      },
      {
        name: 'Decompilation',
        time: metrics?.decompilation_time || 0,
        color: '#82ca9d',
      },
      {
        name: 'Analysis',
        time: metrics?.analysis_time || 0,
        color: '#ffc658',
      },
      {
        name: 'Summarization',
        time: metrics?.summarization_time || 0,
        color: '#ff8042',
      },
      {
        name: 'Test Gen',
        time: metrics?.test_generation_time || 0,
        color: '#0088FE',
      },
    ];
  };

  // Format time for tooltip
  const formatTime = (value: number | undefined | null) => {
    if (value === undefined || value === null) {
      return 'N/A';
    }
    return `${value.toFixed(2)} seconds`;
  };

  return (
    <Paper elevation={2} sx={{ p: 2, height, width }}>
      <Typography variant="h6" gutterBottom>
        Performance Metrics
      </Typography>
      <Box sx={{ height: 'calc(100% - 40px)', width: '100%' }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={getChartData()} margin={{ top: 20, right: 30, left: 20, bottom: 20 }}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" />
            <YAxis label={{ value: 'Time (seconds)', angle: -90, position: 'insideLeft' }} />
            <Tooltip formatter={(value: number) => formatTime(value)} />
            <Legend />
            <Bar dataKey="time" name="Processing Time" fill="#8884d8" />
          </BarChart>
        </ResponsiveContainer>
        <Typography variant="body2" color="textSecondary" align="right" sx={{ mt: 1 }}>
          Total Processing Time: {formatTime(metrics?.total_time)}
        </Typography>
      </Box>
    </Paper>
  );
};

export default PerformanceChart;