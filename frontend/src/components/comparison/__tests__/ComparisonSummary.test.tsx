import { render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import configureStore from 'redux-mock-store';
import ComparisonSummary from '../ComparisonSummary';
import { ComparisonResult, FunctionChange, StructureChange } from '../types';

// Create a mock store
const mockStore = configureStore([]);

describe('ComparisonSummary Component', () => {
  // Sample comparison data for testing
  const mockComparison: ComparisonResult = {
    id: 'comp-123',
    name: 'Test Comparison',
    description: 'A test comparison between binaries',
    base_project_id: 'proj-1',
    base_version_id: 'ver-1',
    target_project_id: 'proj-2',
    target_version_id: 'ver-2',
    created_at: '2025-09-10T12:00:00Z',
    updated_at: '2025-09-10T12:30:00Z',
    overall_similarity: 0.85,
    function_similarity: 0.80,
    structure_similarity: 0.90,
    call_graph_similarity: 0.85,
    tags: ['test', 'comparison'],
  };

  // Sample function changes
  const mockFunctionChanges: FunctionChange[] = [
    {
      id: 'func-1',
      function_name: 'main',
      base_address: '0x1000',
      target_address: '0x1000',
      change_type: 'UNCHANGED',
      similarity: 1.0,
    },
    {
      id: 'func-2',
      function_name: 'initialize',
      base_address: '0x1100',
      target_address: '0x1100',
      change_type: 'MODIFIED',
      similarity: 0.75,
    },
    {
      id: 'func-3',
      function_name: 'process_data',
      base_address: '0x1200',
      target_address: null,
      change_type: 'REMOVED',
    },
    {
      id: 'func-4',
      function_name: 'new_feature',
      base_address: null,
      target_address: '0x1300',
      change_type: 'ADDED',
    }
  ];

  // Sample structure changes
  const mockStructureChanges: StructureChange[] = [
    {
      id: 'struct-1',
      structure_name: 'UserData',
      change_type: 'UNCHANGED',
      similarity: 1.0,
    },
    {
      id: 'struct-2',
      structure_name: 'ConfigOptions',
      change_type: 'MODIFIED',
      similarity: 0.80,
      field_changes: [
        { field_name: 'timeout', change_type: 'MODIFIED', base_type: 'uint16', target_type: 'uint32' }
      ]
    },
    {
      id: 'struct-3',
      structure_name: 'OldFeature',
      change_type: 'REMOVED',
    }
  ];

  test('renders comparison summary with correct data', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        metricChanges: [],
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <ComparisonSummary comparisonId="comp-123" />
      </Provider>
    );

    // Check if summary title is rendered
    expect(screen.getByText('Test Comparison')).toBeInTheDocument();
    
    // Check if description is rendered
    expect(screen.getByText('A test comparison between binaries')).toBeInTheDocument();
    
    // Check if similarity scores are displayed
    expect(screen.getByText('85%')).toBeInTheDocument(); // Overall similarity
    expect(screen.getByText('80%')).toBeInTheDocument(); // Function similarity
    expect(screen.getByText('90%')).toBeInTheDocument(); // Structure similarity
    
    // Check if function change counts are displayed
    expect(screen.getByText('1 Added')).toBeInTheDocument();
    expect(screen.getByText('1 Removed')).toBeInTheDocument();
    expect(screen.getByText('1 Modified')).toBeInTheDocument();
    
    // Check if tags are displayed
    expect(screen.getByText('test')).toBeInTheDocument();
    expect(screen.getByText('comparison')).toBeInTheDocument();
  });

  test('shows empty state when comparison not found', () => {
    // Create store with empty data
    const store = mockStore({
      comparison: {
        comparisons: [],
        functionChanges: [],
        structureChanges: [],
        metricChanges: [],
      },
    });

    // Render component with store and non-existent ID
    render(
      <Provider store={store}>
        <ComparisonSummary comparisonId="non-existent-id" />
      </Provider>
    );

    // Check if empty state message is displayed
    expect(screen.getByText('No comparison selected')).toBeInTheDocument();
  });
});