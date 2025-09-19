import {
    Button,
    Card,
    CardContent,
    Chip,
    Divider,
    FormControl,
    Grid,
    InputLabel,
    MenuItem,
    Paper,
    Select,
    SelectChangeEvent,
    Stack,
    Typography
} from '@mui/material';
import React, { useEffect, useRef, useState } from 'react';
import { useAppSelector } from '../../redux/hooks';

/**
 * Simple call graph visualization component
 * This is a placeholder with a basic visualization for the prototype
 * In a real application, this would use a proper visualization library like D3.js or Vis.js
 */
const CallGraphVisualization: React.FC<{ comparisonId: string }> = ({ comparisonId }) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [viewMode, setViewMode] = useState<string>('split');
  const [depth, setDepth] = useState<number>(2);
  
  const { comparisons } = useAppSelector((state) => state.comparison);
  const selectedComparison = comparisons.find(c => c.id === comparisonId);
  
  // Function to generate a simple call graph visualization
  const drawCallGraph = () => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    
    // Clear canvas
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    
    // Set dimensions
    const width = canvas.width;
    const height = canvas.height;
    
    // Draw a simple placeholder visualization based on view mode
    if (viewMode === 'split') {
      // Split view - left and right graphs
      
      // Draw separator line
      ctx.beginPath();
      ctx.moveTo(width / 2, 0);
      ctx.lineTo(width / 2, height);
      ctx.strokeStyle = '#ccc';
      ctx.stroke();
      
      // Base version title
      ctx.fillStyle = '#333';
      ctx.font = '14px Arial';
      ctx.fillText('Base Version', 20, 20);
      
      // Target version title
      ctx.fillStyle = '#333';
      ctx.fillText('Target Version', width / 2 + 20, 20);
      
      // Draw some placeholder nodes for base version
      drawSampleNodes(ctx, 100, height / 2, depth, width / 2 - 120);
      
      // Draw some placeholder nodes for target version
      drawSampleNodes(ctx, width - 100, height / 2, depth, width / 2 - 120);
      
    } else if (viewMode === 'diff') {
      // Diff view - combined graph with differences highlighted
      
      // Draw central node
      ctx.fillStyle = '#333';
      ctx.font = '16px Arial';
      ctx.fillText('Diff View', width / 2 - 30, 20);
      
      // Draw sample unified graph with differences
      drawUnifiedGraph(ctx, width / 2, height / 2, depth, width - 100);
    }
  };
  
  // Helper to draw sample nodes
  const drawSampleNodes = (
    ctx: CanvasRenderingContext2D, 
    centerX: number, 
    centerY: number, 
    depth: number, 
    width: number
  ) => {
    // Root node
    ctx.beginPath();
    ctx.arc(centerX, 60, 20, 0, Math.PI * 2);
    ctx.fillStyle = '#3f51b5';
    ctx.fill();
    
    // Draw children at level 1
    const level1Count = 3;
    const level1Y = 130;
    const spacing = width / (level1Count + 1);
    
    for (let i = 1; i <= level1Count; i++) {
      const x = centerX - width / 2 + i * spacing;
      
      // Draw connection to parent
      ctx.beginPath();
      ctx.moveTo(centerX, 80);
      ctx.lineTo(x, level1Y - 20);
      ctx.strokeStyle = '#666';
      ctx.stroke();
      
      // Draw node
      ctx.beginPath();
      ctx.arc(x, level1Y, 15, 0, Math.PI * 2);
      ctx.fillStyle = '#7986cb';
      ctx.fill();
      
      // Only continue if we haven't reached maximum depth
      if (depth > 1) {
        // Draw children at level 2
        const level2Count = 2;
        const level2Y = level1Y + 70;
        const subSpacing = spacing / (level2Count + 1);
        
        for (let j = 1; j <= level2Count; j++) {
          const subX = x - spacing / 2 + j * subSpacing;
          
          // Draw connection to parent
          ctx.beginPath();
          ctx.moveTo(x, level1Y + 15);
          ctx.lineTo(subX, level2Y - 15);
          ctx.strokeStyle = '#999';
          ctx.stroke();
          
          // Draw node
          ctx.beginPath();
          ctx.arc(subX, level2Y, 10, 0, Math.PI * 2);
          ctx.fillStyle = '#c5cae9';
          ctx.fill();
        }
      }
    }
  };
  
  // Helper to draw unified graph with differences
  const drawUnifiedGraph = (
    ctx: CanvasRenderingContext2D, 
    centerX: number, 
    centerY: number, 
    depth: number, 
    width: number
  ) => {
    // Root node
    ctx.beginPath();
    ctx.arc(centerX, 60, 20, 0, Math.PI * 2);
    ctx.fillStyle = '#3f51b5';
    ctx.fill();
    
    // First level nodes
    const nodes = [
      { x: centerX - 120, y: 140, status: 'unchanged' },
      { x: centerX, y: 140, status: 'modified' },
      { x: centerX + 120, y: 140, status: 'added' },
      { x: centerX + 200, y: 140, status: 'removed' },
    ];
    
    // Draw connections and nodes
    nodes.forEach(node => {
      // Draw connection
      ctx.beginPath();
      ctx.moveTo(centerX, 80);
      ctx.lineTo(node.x, node.y - 20);
      ctx.strokeStyle = node.status === 'removed' ? '#f44336' : '#666';
      ctx.stroke();
      
      // Draw node with status color
      ctx.beginPath();
      ctx.arc(node.x, node.y, 15, 0, Math.PI * 2);
      
      // Select color based on status
      switch (node.status) {
        case 'added':
          ctx.fillStyle = '#4caf50';
          break;
        case 'removed':
          ctx.fillStyle = '#f44336';
          break;
        case 'modified':
          ctx.fillStyle = '#ff9800';
          break;
        default:
          ctx.fillStyle = '#7986cb';
      }
      
      ctx.fill();
      
      // Add status label
      ctx.fillStyle = '#333';
      ctx.font = '10px Arial';
      ctx.fillText(node.status, node.x - 20, node.y + 30);
    });
    
    // Draw legend
    const legendY = centerY + 130;
    const legendItems = [
      { color: '#7986cb', label: 'Unchanged' },
      { color: '#4caf50', label: 'Added' },
      { color: '#f44336', label: 'Removed' },
      { color: '#ff9800', label: 'Modified' }
    ];
    
    legendItems.forEach((item, idx) => {
      const x = centerX - 150 + idx * 80;
      
      // Draw color box
      ctx.fillStyle = item.color;
      ctx.fillRect(x, legendY, 10, 10);
      
      // Draw label
      ctx.fillStyle = '#333';
      ctx.font = '12px Arial';
      ctx.fillText(item.label, x + 15, legendY + 10);
    });
  };
  
  // Handle view mode change
  const handleViewModeChange = (event: SelectChangeEvent) => {
    setViewMode(event.target.value);
  };
  
  // Handle depth change
  const handleDepthChange = (event: SelectChangeEvent) => {
    setDepth(Number(event.target.value));
  };
  
  // Draw the graph when parameters change
  useEffect(() => {
    drawCallGraph();
  }, [viewMode, depth]);
  
  return (
    <Card elevation={3}>
      <CardContent>
        <Typography variant="h6" gutterBottom>Call Graph Visualization</Typography>
        
        {/* Controls */}
        <Grid container spacing={3} sx={{ mb: 4 }}>
          <Grid item xs={12} sm={4}>
            <FormControl fullWidth variant="outlined" size="small">
              <InputLabel id="view-mode-label">View Mode</InputLabel>
              <Select
                labelId="view-mode-label"
                value={viewMode}
                onChange={handleViewModeChange}
                label="View Mode"
              >
                <MenuItem value="split">Side by Side</MenuItem>
                <MenuItem value="diff">Difference View</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={4}>
            <FormControl fullWidth variant="outlined" size="small">
              <InputLabel id="depth-label">Depth</InputLabel>
              <Select
                labelId="depth-label"
                value={String(depth)}
                onChange={handleDepthChange}
                label="Depth"
              >
                <MenuItem value="1">1 Level</MenuItem>
                <MenuItem value="2">2 Levels</MenuItem>
                <MenuItem value="3">3 Levels</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={12} sm={4}>
            <Stack direction="row" spacing={1}>
              <Chip
                label={`${selectedComparison?.call_graph_similarity ? 
                  (selectedComparison.call_graph_similarity * 100).toFixed(1) : 0}% Similar`}
                color="primary"
              />
              <Button size="small" variant="outlined">Export Graph</Button>
            </Stack>
          </Grid>
        </Grid>
        
        <Divider sx={{ mb: 2 }} />
        
        {/* Canvas for visualization */}
        <Paper 
          elevation={0} 
          sx={{ 
            bgcolor: 'background.default',
            p: 2,
            borderRadius: 1,
            overflow: 'hidden'
          }}
        >
          <canvas 
            ref={canvasRef}
            width={800}
            height={400}
            style={{ 
              width: '100%', 
              height: 'auto',
              maxHeight: '400px'
            }}
          />
        </Paper>
        
        <Typography variant="body2" color="text.secondary" sx={{ mt: 2, textAlign: 'center' }}>
          Note: This is a simplified visualization. In a production environment, this would use an
          interactive graph visualization library.
        </Typography>
      </CardContent>
    </Card>
  );
};

export default CallGraphVisualization;