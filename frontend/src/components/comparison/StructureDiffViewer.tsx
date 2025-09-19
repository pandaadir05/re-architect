import AddCircleOutlineIcon from '@mui/icons-material/AddCircleOutline';
import ArrowBackIcon from '@mui/icons-material/ArrowBack';
import GetAppIcon from '@mui/icons-material/GetApp';
import RemoveCircleOutlineIcon from '@mui/icons-material/RemoveCircleOutline';
import SwapHorizIcon from '@mui/icons-material/SwapHoriz';
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
    Table,
    TableBody,
    TableCell,
    TableContainer,
    TableHead,
    TableRow,
    Tooltip,
    Typography,
} from '@mui/material';
import React from 'react';
import { useAppSelector } from '../../redux/hooks';
import { ChangeType } from './types';

/**
 * Component to display structure definition differences
 */
const StructureDiffViewer: React.FC<{
  structureId: string,
  comparisonId: string,
  onBack: () => void
}> = ({ structureId, comparisonId, onBack }) => {
  const { structureChanges } = useAppSelector((state) => state.comparison);
  
  // Find the selected structure
  const selectedStructure = structureChanges.find(struct => struct.id === structureId);
  
  if (!selectedStructure) {
    return (
      <Card elevation={3}>
        <CardContent>
          <Typography>Structure not found</Typography>
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

  const changeTypeColor = (changeType: ChangeType) => {
    switch (changeType) {
      case 'ADDED': return 'success';
      case 'REMOVED': return 'error';
      case 'MODIFIED': return 'warning';
      case 'RENAMED': return 'info';
      default: return 'default';
    }
  };
  
  const getChangeIcon = (changeType: ChangeType) => {
    switch (changeType) {
      case 'ADDED': return <AddCircleOutlineIcon fontSize="small" sx={{ color: 'success.main' }} />;
      case 'REMOVED': return <RemoveCircleOutlineIcon fontSize="small" sx={{ color: 'error.main' }} />;
      case 'MODIFIED': return <SwapHorizIcon fontSize="small" sx={{ color: 'warning.main' }} />;
      default: return null;
    }
  };

  // Helper function to render the structure definition box
  const renderDefinitionBox = (title: string, definition: string | undefined) => (
    <Paper 
      elevation={0} 
      sx={{ 
        bgcolor: 'background.default',
        height: '100%',
        p: 2,
        fontFamily: 'monospace',
        whiteSpace: 'pre-wrap',
        overflowX: 'auto',
        border: 1,
        borderColor: 'divider',
        borderRadius: 1
      }}
    >
      <Typography variant="subtitle2" gutterBottom>{title}</Typography>
      <Box sx={{ fontFamily: 'Consolas, monospace', fontSize: '0.9rem' }}>
        {definition || 'No definition available'}
      </Box>
    </Paper>
  );

  return (
    <Card elevation={3}>
      <CardContent>
        <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center' }}>
            <IconButton onClick={onBack}>
              <ArrowBackIcon />
            </IconButton>
            <Typography variant="h5" component="div" sx={{ ml: 1 }}>
              {selectedStructure.structure_name}
            </Typography>
            <Chip 
              label={selectedStructure.change_type} 
              color={changeTypeColor(selectedStructure.change_type)}
              size="small"
              sx={{ ml: 2 }}
            />
          </Box>
          <Button
            variant="outlined"
            size="small"
            startIcon={<GetAppIcon />}
          >
            Export Definition
          </Button>
        </Box>

        <Divider sx={{ my: 2 }} />
        
        {/* Structure definitions */}
        <Typography variant="h6" gutterBottom>Structure Definition</Typography>
        <Grid container spacing={2} sx={{ mb: 3 }}>
          <Grid item xs={12} md={6}>
            {renderDefinitionBox('Base Version', selectedStructure.base_definition)}
          </Grid>
          <Grid item xs={12} md={6}>
            {renderDefinitionBox('Target Version', selectedStructure.target_definition)}
          </Grid>
        </Grid>
        
        {/* Field changes table */}
        {selectedStructure.field_changes && selectedStructure.field_changes.length > 0 && (
          <Box sx={{ mt: 4 }}>
            <Typography variant="h6" gutterBottom>Field Changes</Typography>
            <TableContainer component={Paper} variant="outlined">
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell width={50}>Type</TableCell>
                    <TableCell>Field Name</TableCell>
                    <TableCell>Base Type</TableCell>
                    <TableCell>Target Type</TableCell>
                    <TableCell>Status</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {selectedStructure.field_changes.map((field, index) => (
                    <TableRow
                      key={index}
                      sx={{
                        backgroundColor: field.change_type === 'ADDED' ? 'success.lightest' :
                                        field.change_type === 'REMOVED' ? 'error.lightest' :
                                        field.change_type === 'MODIFIED' ? 'warning.lightest' : 'inherit',
                      }}
                    >
                      <TableCell>
                        <Tooltip title={field.change_type}>
                          {getChangeIcon(field.change_type)}
                        </Tooltip>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {field.field_name}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {field.base_type || '-'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                          {field.target_type || '-'}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Chip 
                          label={field.change_type} 
                          size="small" 
                          color={changeTypeColor(field.change_type)}
                          variant="outlined"
                        />
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          </Box>
        )}
        
        {/* If no field changes are available */}
        {(!selectedStructure.field_changes || selectedStructure.field_changes.length === 0) && (
          <Box sx={{ mt: 4, textAlign: 'center', p: 4 }}>
            <Typography color="text.secondary">
              No field changes detected or available for this structure
            </Typography>
          </Box>
        )}
      </CardContent>
    </Card>
  );
};

export default StructureDiffViewer;