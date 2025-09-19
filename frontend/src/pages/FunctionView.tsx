import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import {
  Box,
  Typography,
  Paper,
  Tabs,
  Tab,
  Divider,
  Card,
  CardContent,
  Chip,
  Grid,
} from '@mui/material';
import { Editor } from '@monaco-editor/react';

interface FunctionData {
  id: string;
  name: string;
  decompiled: string;
  summary: string;
  complexity: 'Low' | 'Medium' | 'High';
  parameters: {
    name: string;
    type: string;
    description: string;
  }[];
  returnValue: {
    type: string;
    description: string;
  };
  callers: string[];
  callees: string[];
  potentialVulnerabilities: string[];
}

// Sample function data
const sampleFunction: FunctionData = {
  id: 'func-1',
  name: 'process_buffer',
  decompiled: `int process_buffer(char *buffer, size_t size) {
  if (buffer == NULL) {
    return -1;
  }
  
  if (size > MAX_BUFFER_SIZE) {
    size = MAX_BUFFER_SIZE;
  }
  
  int result = 0;
  for (size_t i = 0; i < size; i++) {
    if (buffer[i] == 0) {
      break;
    }
    result += (int)buffer[i];
  }
  
  return result;
}`,
  summary: 'Processes a character buffer by summing the ASCII values of characters until a null terminator is found or the specified size is reached. Returns -1 if the buffer is NULL.',
  complexity: 'Low',
  parameters: [
    {
      name: 'buffer',
      type: 'char*',
      description: 'Pointer to the character buffer to process',
    },
    {
      name: 'size',
      type: 'size_t',
      description: 'Maximum number of bytes to process',
    },
  ],
  returnValue: {
    type: 'int',
    description: 'The sum of character values or -1 if buffer is NULL',
  },
  callers: ['main', 'handle_request'],
  callees: [],
  potentialVulnerabilities: [],
};

// Function View component
const FunctionView: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [functionData, setFunctionData] = useState<FunctionData | null>(null);
  const [activeTab, setActiveTab] = useState(0);

  // Fetch function data when component mounts
  useEffect(() => {
    // In a real app, we would fetch data from an API
    setFunctionData(sampleFunction);
  }, [id]);

  const handleTabChange = (event: React.SyntheticEvent, newValue: number) => {
    setActiveTab(newValue);
  };

  if (!functionData) {
    return (
      <Box sx={{ pt: 4, display: 'flex', justifyContent: 'center' }}>
        <Typography variant="h6">Loading function data...</Typography>
      </Box>
    );
  }

  return (
    <Box sx={{ pt: 2, pb: 6 }}>
      <Typography variant="h4" gutterBottom>
        Function: {functionData.name}
      </Typography>

      <Paper sx={{ mb: 4 }}>
        <Tabs 
          value={activeTab} 
          onChange={handleTabChange} 
          indicatorColor="primary"
          textColor="primary"
          variant="scrollable"
          scrollButtons="auto"
        >
          <Tab label="Summary" />
          <Tab label="Code" />
          <Tab label="References" />
          <Tab label="Test Harness" />
        </Tabs>
      </Paper>

      {/* Summary Tab */}
      {activeTab === 0 && (
        <Grid container spacing={3}>
          <Grid item xs={12}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Function Summary
                </Typography>
                <Typography variant="body1" paragraph>
                  {functionData.summary}
                </Typography>

                <Box sx={{ mb: 2 }}>
                  <Chip 
                    label={`Complexity: ${functionData.complexity}`} 
                    color={
                      functionData.complexity === 'Low' ? 'success' :
                      functionData.complexity === 'Medium' ? 'warning' : 'error'
                    }
                    sx={{ mr: 1 }}
                  />
                </Box>
                
                <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                  Parameters
                </Typography>
                <Box component="dl">
                  {functionData.parameters.map((param) => (
                    <React.Fragment key={param.name}>
                      <Typography component="dt" variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                        {param.name}: <Typography component="span" variant="body2" sx={{ color: 'text.secondary' }}>{param.type}</Typography>
                      </Typography>
                      <Typography component="dd" variant="body2" sx={{ mb: 1 }}>
                        {param.description}
                      </Typography>
                    </React.Fragment>
                  ))}
                </Box>

                <Typography variant="h6" gutterBottom sx={{ mt: 3 }}>
                  Return Value
                </Typography>
                <Box component="dl">
                  <Typography component="dt" variant="subtitle1" sx={{ fontWeight: 'bold' }}>
                    <Typography component="span" variant="body2" sx={{ color: 'text.secondary' }}>{functionData.returnValue.type}</Typography>
                  </Typography>
                  <Typography component="dd" variant="body2" sx={{ mb: 1 }}>
                    {functionData.returnValue.description}
                  </Typography>
                </Box>
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Code Tab */}
      {activeTab === 1 && (
        <Paper sx={{ height: 500 }}>
          <Editor
            height="500px"
            defaultLanguage="c"
            value={functionData.decompiled}
            options={{
              readOnly: true,
              minimap: { enabled: true },
              scrollBeyondLastLine: false,
              fontFamily: "'Fira Code', 'Courier New', monospace",
              fontSize: 14,
            }}
          />
        </Paper>
      )}

      {/* References Tab */}
      {activeTab === 2 && (
        <Grid container spacing={3}>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Called By
                </Typography>
                {functionData.callers.length > 0 ? (
                  <ul>
                    {functionData.callers.map((caller) => (
                      <li key={caller}>
                        <Typography variant="body1">
                          {caller}
                        </Typography>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No caller functions found
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
          <Grid item xs={12} md={6}>
            <Card>
              <CardContent>
                <Typography variant="h6" gutterBottom>
                  Calls
                </Typography>
                {functionData.callees.length > 0 ? (
                  <ul>
                    {functionData.callees.map((callee) => (
                      <li key={callee}>
                        <Typography variant="body1">
                          {callee}
                        </Typography>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <Typography variant="body2" color="text.secondary">
                    No called functions found
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        </Grid>
      )}

      {/* Test Harness Tab */}
      {activeTab === 3 && (
        <Paper sx={{ height: 500, p: 2 }}>
          <Typography variant="body1" paragraph>
            Generated test harness for {functionData.name}:
          </Typography>

          <Editor
            height="400px"
            defaultLanguage="c"
            value={`#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function prototype
int process_buffer(char *buffer, size_t size);

// Test cases
void test_normal_usage() {
    char buffer[] = "Hello, World!";
    int result = process_buffer(buffer, strlen(buffer));
    printf("Test normal usage: %d\\n", result);
    // Expected result: Sum of ASCII values of "Hello, World!"
}

void test_null_buffer() {
    int result = process_buffer(NULL, 10);
    printf("Test null buffer: %d\\n", result);
    // Expected result: -1
}

void test_empty_buffer() {
    char buffer[] = "";
    int result = process_buffer(buffer, 0);
    printf("Test empty buffer: %d\\n", result);
    // Expected result: 0
}

int main() {
    printf("Running tests for process_buffer\\n");
    printf("---------------------------------\\n");
    
    test_normal_usage();
    test_null_buffer();
    test_empty_buffer();
    
    return 0;
}
`}
            options={{
              readOnly: true,
              minimap: { enabled: true },
              scrollBeyondLastLine: false,
            }}
          />
        </Paper>
      )}
    </Box>
  );
};

export default FunctionView;
