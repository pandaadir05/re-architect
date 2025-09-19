import React from 'react';
import { Box, Paper, Typography } from '@mui/material';

interface CodeViewerProps {
  code: string;
  language?: string;
  title?: string;
  maxHeight?: number | string;
}

/**
 * CodeViewer component for displaying formatted code blocks
 * Note: In a real implementation, this would use a syntax highlighter like Prism or Monaco Editor
 */
const CodeViewer: React.FC<CodeViewerProps> = ({
  code,
  language = 'c',
  title,
  maxHeight = 500
}) => {
  return (
    <Paper elevation={2} sx={{ overflow: 'hidden' }}>
      {title && (
        <Box px={2} py={1} bgcolor="grey.100" borderBottom={1} borderColor="divider">
          <Typography variant="subtitle2">{title}</Typography>
        </Box>
      )}
      <Box
        component="pre"
        sx={{
          m: 0,
          p: 2,
          overflow: 'auto',
          maxHeight,
          fontSize: '0.875rem',
          fontFamily: 'monospace',
          whiteSpace: 'pre-wrap',
          backgroundColor: 'grey.50'
        }}
      >
        <Box component="code" data-language={language}>
          {code}
        </Box>
      </Box>
    </Paper>
  );
};

export default CodeViewer;
