import React from 'react';
import { Box, Paper, Typography } from '@mui/material';

interface StatsCardProps {
  title: string;
  value: number | string;
  icon?: React.ReactNode;
  color?: string;
  description?: string;
}

/**
 * StatsCard component for displaying metrics on the dashboard
 */
const StatsCard: React.FC<StatsCardProps> = ({
  title,
  value,
  icon,
  color = 'primary.main',
  description
}) => {
  return (
    <Paper
      elevation={2}
      sx={{
        p: 3,
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between'
      }}
    >
      <Box display="flex" justifyContent="space-between" alignItems="flex-start">
        <Box>
          <Typography variant="body2" color="textSecondary">
            {title}
          </Typography>
          <Typography variant="h4" color="textPrimary" sx={{ mt: 1, fontWeight: 'bold' }}>
            {value}
          </Typography>
          {description && (
            <Typography variant="body2" color="textSecondary" sx={{ mt: 1 }}>
              {description}
            </Typography>
          )}
        </Box>
        {icon && (
          <Box
            sx={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              backgroundColor: `${color}15`, // Using alpha transparency
              borderRadius: '50%',
              p: 1,
              color
            }}
          >
            {icon}
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default StatsCard;
