import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  Chip,
  Divider,
  Grid,
  Paper,
  Typography,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TablePagination,
  IconButton,
  Tooltip,
} from '@mui/material';
import { useAppSelector } from '../../redux/hooks';
import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import RemoveCircleOutlineIcon from '@mui/icons-material/RemoveCircleOutline';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import VisibilityIcon from '@mui/icons-material/Visibility';
import { ChangeType, FunctionChange } from './types';

// Color mapping based on change type
const getChangeTypeColor = (changeType: ChangeType) => {
  switch (changeType) {
    case 'ADDED': return 'success';
    case 'REMOVED': return 'error';
    case 'MODIFIED': return 'warning';
    case 'RENAMED': return 'info';
    case 'UNCHANGED': return 'default';
    default: return 'default';
  }
};

// Icon mapping based on change type
const getChangeTypeIcon = (changeType: ChangeType) => {
  switch (changeType) {
    case 'ADDED': return <AddCircleOutlineIcon fontSize="small" />;
    case 'REMOVED': return <RemoveCircleOutlineIcon fontSize="small" />;
    case 'MODIFIED':
    case 'RENAMED': return <CompareArrowsIcon fontSize="small" />;
    default: return null;
  }
};

/**
 * Component for displaying function changes in a comparison
 */
const FunctionChangesTable: React.FC<{ comparisonId: string }> = ({ comparisonId }) => {
  const { functionChanges } = useAppSelector((state) => state.comparison);
  
  // Pagination state
  const [page, setPage] = useState(0);
  const [rowsPerPage, setRowsPerPage] = useState(10);

  // Change handlers
  const handleChangePage = (event: unknown, newPage: number) => {
    setPage(newPage);
  };

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10));
    setPage(0);
  };

  // Filter functions to this comparison
  // In a real application, we would filter by comparisonId
  // Here we're just displaying all functions for demonstration
  const filteredFunctions = functionChanges;
  
  const displayedFunctions = filteredFunctions
    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  // Group functions by change type for statistics
  const groupedByType = filteredFunctions.reduce<Record<ChangeType, number>>((acc, func) => {
    if (!acc[func.change_type]) {
      acc[func.change_type] = 0;
    }
    acc[func.change_type]++;
    return acc;
  }, {} as Record<ChangeType, number>);

  return (
    <Card elevation={3} sx={{ mb: 4 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">Function Changes</Typography>
          <Box sx={{ display: 'flex', gap: 1 }}>
            {Object.entries(groupedByType).map(([type, count]) => (
              <Chip
                key={type}
                label={`${type}: ${count}`}
                size="small"
                color={getChangeTypeColor(type as ChangeType)}
                variant="outlined"
              />
            ))}
          </Box>
        </Box>

        <TableContainer component={Paper}>
          <Table sx={{ minWidth: 650 }} size="small">
            <TableHead>
              <TableRow>
                <TableCell width={50}>Type</TableCell>
                <TableCell>Function Name</TableCell>
                <TableCell>Base Address</TableCell>
                <TableCell>Target Address</TableCell>
                <TableCell align="right" width={100}>Similarity</TableCell>
                <TableCell align="center" width={80}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {displayedFunctions.map((func) => (
                <TableRow
                  key={func.id}
                  sx={{
                    '&:last-child td, &:last-child th': { border: 0 },
                    backgroundColor: func.change_type === 'ADDED' ? 'success.lightest' :
                                     func.change_type === 'REMOVED' ? 'error.lightest' :
                                     func.change_type === 'MODIFIED' ? 'warning.lightest' :
                                     func.change_type === 'RENAMED' ? 'info.lightest' : 'inherit',
                  }}
                >
                  <TableCell>
                    <Tooltip title={func.change_type}>
                      {getChangeTypeIcon(func.change_type)}
                    </Tooltip>
                  </TableCell>
                  <TableCell component="th" scope="row">
                    {func.function_name}
                  </TableCell>
                  <TableCell>{func.base_address || '-'}</TableCell>
                  <TableCell>{func.target_address || '-'}</TableCell>
                  <TableCell align="right">
                    {func.similarity !== undefined ? `${(func.similarity * 100).toFixed(1)}%` : '-'}
                  </TableCell>
                  <TableCell align="center">
                    <Tooltip title="View Function Details">
                      <IconButton size="small">
                        <VisibilityIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
              {displayedFunctions.length === 0 && (
                <TableRow>
                  <TableCell colSpan={6} align="center">
                    <Typography variant="body2" sx={{ py: 2 }}>No function changes found</Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        
        <TablePagination
          rowsPerPageOptions={[5, 10, 25]}
          component="div"
          count={filteredFunctions.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </CardContent>
    </Card>
  );
};

export default FunctionChangesTable;