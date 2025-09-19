import { Box, Button, Card, CardContent, FormControl, Grid, InputLabel, MenuItem, Select, Typography } from '@mui/material';
import { useEffect, useState } from 'react';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { createComparison, fetchProjects, selectProject1, selectProject2 } from '../../redux/slices/comparisonSlice';

/**
 * Component for selecting two projects to compare
 */
const ProjectSelector = () => {
  const dispatch = useAppDispatch();
  const { projects, baseProjectId, targetProjectId, loading, error } = useAppSelector(
    (state) => state.comparison
  );
  
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  
  // Load projects on component mount
  useEffect(() => {
    dispatch(fetchProjects());
  }, [dispatch]);
  
  const handleCompare = () => {
    if (baseProjectId && targetProjectId) {
      dispatch(
        createComparison({
          project1Id: baseProjectId,
          project2Id: targetProjectId,
          name: name || undefined,
          description: description || undefined,
        })
      );
    }
  };
  
  return (
    <Card elevation={3}>
      <CardContent>
        <Typography variant="h5" gutterBottom>
          Compare Binary Versions
        </Typography>
        <Typography variant="body2" color="text.secondary" paragraph>
          Select two binary analysis projects to compare their functions, data structures, and performance metrics.
        </Typography>
        
        <Grid container spacing={3}>
          <Grid item xs={12} md={5}>
            <FormControl fullWidth margin="normal">
              <InputLabel>Base Project</InputLabel>
              <Select
                value={baseProjectId || ''}
                onChange={(e) => dispatch(selectProject1(e.target.value))}
                disabled={loading}
                label="Base Project"
              >
                {projects.map((project) => (
                  <MenuItem 
                    key={project.id} 
                    value={project.id}
                    disabled={project.id === targetProjectId}
                  >
                    {project.name} (v{project.versions && project.versions.length > 0 ? project.versions[0].version_name : 'N/A'})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12} md={2} sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
            <Typography variant="h5" sx={{ my: 2 }}>
              vs
            </Typography>
          </Grid>
          
          <Grid item xs={12} md={5}>
            <FormControl fullWidth margin="normal">
              <InputLabel>Target Project</InputLabel>
              <Select
                value={targetProjectId || ''}
                onChange={(e) => dispatch(selectProject2(e.target.value))}
                disabled={loading}
                label="Target Project"
              >
                {projects.map((project) => (
                  <MenuItem 
                    key={project.id} 
                    value={project.id}
                    disabled={project.id === baseProjectId}
                  >
                    {project.name} (v{project.versions && project.versions.length > 0 ? project.versions[0].version_name : 'N/A'})
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          
          <Grid item xs={12}>
            <Box sx={{ mt: 2, display: 'flex', justifyContent: 'center' }}>
              <Button
                variant="contained"
                color="primary"
                onClick={handleCompare}
                disabled={!baseProjectId || !targetProjectId || loading}
              >
                {loading ? 'Comparing...' : 'Compare Projects'}
              </Button>
            </Box>
          </Grid>
          
          {error && (
            <Grid item xs={12}>
              <Typography color="error" align="center">
                {error}
              </Typography>
            </Grid>
          )}
        </Grid>
      </CardContent>
    </Card>
  );
};

export default ProjectSelector;