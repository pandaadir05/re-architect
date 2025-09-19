import React, { useEffect, useRef } from 'react';
import { ForceGraph2D } from 'react-force-graph';
import { Box, Paper, Typography, useTheme, CircularProgress } from '@mui/material';
import { Function } from '../../services/api';
import { useAppDispatch, useAppSelector } from '../../redux/hooks';
import { setFunctionCallGraph } from '../../redux/slices/visualizationSlice';

interface CallGraphNode {
  id: string;
  name: string;
  val: number;
  color?: string;
}

interface CallGraphLink {
  source: string;
  target: string;
  value: number;
}

interface CallGraphData {
  nodes: CallGraphNode[];
  links: CallGraphLink[];
}

interface FunctionCallGraphProps {
  functions: Record<string, Function>;
  selectedFunction?: string;
  onNodeClick?: (functionId: string) => void;
  width?: number;
  height?: number;
}

/**
 * Component to visualize function call graph using force-directed graph
 */
const FunctionCallGraph: React.FC<FunctionCallGraphProps> = ({
  functions,
  selectedFunction,
  onNodeClick,
  width = 800,
  height = 600,
}) => {
  const theme = useTheme();
  const graphRef = useRef<any>();

  // Process data for the graph
  const processGraphData = (): CallGraphData => {
    const nodes: CallGraphNode[] = [];
    const links: CallGraphLink[] = [];
    const nodeSet = new Set<string>();

    // First pass: collect all nodes
    Object.entries(functions).forEach(([id, func]) => {
      nodeSet.add(id);

      if (func.calls) {
        func.calls.forEach((callId) => {
          if (functions[callId]) {
            nodeSet.add(callId);
          }
        });
      }
    });

    // Create nodes
    nodeSet.forEach((id) => {
      const func = functions[id];
      if (func) {
        nodes.push({
          id,
          name: func.name || `func_${id}`,
          val: func.size / 50 || 1, // Node size based on function size
          color: 
            id === selectedFunction 
              ? theme.palette.primary.main 
              : func.vulnerabilities?.length 
                ? theme.palette.error.main 
                : theme.palette.grey[600]
        });
      }
    });

    // Create links
    Object.entries(functions).forEach(([id, func]) => {
      if (func.calls) {
        func.calls.forEach((callId) => {
          if (functions[callId]) {
            links.push({
              source: id,
              target: callId,
              value: 1,
            });
          }
        });
      }
    });

    return { nodes, links };
  };

  const graphData = processGraphData();

  useEffect(() => {
    // Focus on selected function
    if (selectedFunction && graphRef.current) {
      const node = graphData.nodes.find(node => node.id === selectedFunction);
      if (node) {
        graphRef.current.centerAt(0, 0, 1000);
        setTimeout(() => {
          graphRef.current.zoomToFit(400);
        }, 500);
      }
    }
  }, [selectedFunction, graphData.nodes]);

  return (
    <Paper elevation={2} sx={{ p: 2, height: height, width: width }}>
      <Typography variant="h6" gutterBottom>
        Function Call Graph
      </Typography>
      <Box sx={{ height: 'calc(100% - 40px)', width: '100%' }}>
        {graphData.nodes.length > 0 ? (
          <ForceGraph2D
            ref={graphRef}
            graphData={graphData}
            nodeLabel={(node: any) => node.name}
            nodeRelSize={6}
            nodeVal={(node: any) => node.val}
            nodeColor={(node: any) => node.color}
            linkDirectionalParticles={2}
            linkDirectionalParticleWidth={2}
            linkWidth={1}
            onNodeClick={(node: any) => {
              if (onNodeClick) {
                onNodeClick(node.id);
              }
            }}
            cooldownTicks={100}
            onEngineStop={() => graphRef.current?.zoomToFit(400)}
          />
        ) : (
          <Box display="flex" justifyContent="center" alignItems="center" height="100%">
            <Typography variant="body1" color="textSecondary">
              No function call data available
            </Typography>
          </Box>
        )}
      </Box>
    </Paper>
  );
};

export default FunctionCallGraph;