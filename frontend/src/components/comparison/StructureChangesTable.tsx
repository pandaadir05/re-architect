import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import CompareArrowsIcon from '@mui/icons-material/CompareArrows';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import KeyboardArrowUpIcon from '@mui/icons-material/KeyboardArrowUp';
import RemoveCircleOutlineIcon from '@mui/icons-material/RemoveCircleOutline';
import VisibilityIcon from '@mui/icons-material/Visibility';
import {
    Box,
    Card,
    CardContent,
    Chip,
    Collapse,
    IconButton,
    Paper,
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TablePagination,
    TableRow,
    Tooltip,
    Typography
} from '@mui/material';
import React, { useState } from 'react';
import { useAppSelector } from '../../redux/hooks';
import { ChangeType, StructureChange } from './types';

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

// Row component for expandable table rows
const StructureRow: React.FC<{ 
  structure: StructureChange, 
  onViewStructure?: (structureId: string) => void 
}> = ({ structure, onViewStructure }) => {
  const [open, setOpen] = useState(false);
  const hasFieldChanges = structure.field_changes && structure.field_changes.length > 0;

  return (
    <>
      <TableRow
        sx={{
          '&:last-child td, &:last-child th': { border: 0 },
          backgroundColor: structure.change_type === 'ADDED' ? 'success.lightest' :
                           structure.change_type === 'REMOVED' ? 'error.lightest' :
                           structure.change_type === 'MODIFIED' ? 'warning.lightest' :
                           'inherit',
        }}
      >
        <TableCell>
          <Tooltip title={structure.change_type}>
            {getChangeTypeIcon(structure.change_type)}
          </Tooltip>
        </TableCell>
        <TableCell component="th" scope="row">
          {structure.structure_name}
        </TableCell>
        <TableCell align="right">
          {structure.similarity !== undefined ? `${(structure.similarity * 100).toFixed(1)}%` : '-'}
        </TableCell>
        <TableCell align="center">
          {hasFieldChanges ? (
            <IconButton size="small" onClick={() => setOpen(!open)}>
              {open ? <KeyboardArrowUpIcon /> : <KeyboardArrowDownIcon />}
            </IconButton>
          ) : (
            <Tooltip title="View Structure Details">
              <IconButton 
                size="small"
                onClick={() => onViewStructure && onViewStructure(structure.id)}
              >
                <VisibilityIcon fontSize="small" />
              </IconButton>
            </Tooltip>
          )}
        </TableCell>
      </TableRow>
      {hasFieldChanges && (
        <TableRow>
          <TableCell style={{ paddingBottom: 0, paddingTop: 0 }} colSpan={4}>
            <Collapse in={open} timeout="auto" unmountOnExit>
              <Box sx={{ margin: 1, backgroundColor: 'background.paper', p: 1, borderRadius: 1 }}>
                <Typography variant="body2" gutterBottom component="div">
                  Field Changes
                </Typography>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell width={50}>Type</TableCell>
                      <TableCell>Field Name</TableCell>
                      <TableCell>Base Type</TableCell>
                      <TableCell>Target Type</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {structure.field_changes.map((field, index) => (
                      <TableRow key={index}>
                        <TableCell>
                          <Tooltip title={field.change_type}>
                            {getChangeTypeIcon(field.change_type)}
                          </Tooltip>
                        </TableCell>
                        <TableCell>{field.field_name}</TableCell>
                        <TableCell>{field.base_type || '-'}</TableCell>
                        <TableCell>{field.target_type || '-'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </Box>
            </Collapse>
          </TableCell>
        </TableRow>
      )}
    </>
  );
};

/**
 * Component for displaying structure changes in a comparison
 */
const StructureChangesTable: React.FC<{ 
  comparisonId: string, 
  onViewStructure?: (structureId: string) => void,
  searchQuery?: string
}> = ({ 
  comparisonId,
  onViewStructure,
  searchQuery = ''
}) => {
  const { structureChanges } = useAppSelector((state) => state.comparison);
  
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

  // Filter structures to this comparison and by search query
  const filteredStructures = structureChanges.filter(structure => {
    // First filter by comparison ID if implemented
    // const matchesComparison = structure.comparisonId === comparisonId;
    
    // Then filter by search query if provided
    const matchesSearch = searchQuery ? 
      structure.structure_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      // Also search in field names if the structure has field changes
      (structure.field_changes?.some(field => 
        field.field_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (field.base_type && field.base_type.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (field.target_type && field.target_type.toLowerCase().includes(searchQuery.toLowerCase()))
      ) || false)
      : true;
      
    return /* matchesComparison && */ matchesSearch;
  });
  
  const displayedStructures = filteredStructures
    .slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage);

  // Group structures by change type for statistics
  const groupedByType = filteredStructures.reduce<Record<ChangeType, number>>((acc, struct) => {
    if (!acc[struct.change_type]) {
      acc[struct.change_type] = 0;
    }
    acc[struct.change_type]++;
    return acc;
  }, {} as Record<ChangeType, number>);

  return (
    <Card elevation={3} sx={{ mb: 4 }}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
          <Typography variant="h6">Structure Changes</Typography>
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
                <TableCell>Structure Name</TableCell>
                <TableCell align="right" width={100}>Similarity</TableCell>
                <TableCell align="center" width={80}>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {displayedStructures.map((structure) => (
                <StructureRow 
                  key={structure.id} 
                  structure={structure} 
                  onViewStructure={onViewStructure} 
                />
              ))}
              {displayedStructures.length === 0 && (
                <TableRow>
                  <TableCell colSpan={4} align="center">
                    <Typography variant="body2" sx={{ py: 2 }}>No structure changes found</Typography>
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
        
        <TablePagination
          rowsPerPageOptions={[5, 10, 25]}
          component="div"
          count={filteredStructures.length}
          rowsPerPage={rowsPerPage}
          page={page}
          onPageChange={handleChangePage}
          onRowsPerPageChange={handleChangeRowsPerPage}
        />
      </CardContent>
    </Card>
  );
};

export default StructureChangesTable;