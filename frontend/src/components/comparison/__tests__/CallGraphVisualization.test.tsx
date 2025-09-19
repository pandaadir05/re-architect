import { fireEvent, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import configureStore from 'redux-mock-store';
import CallGraphVisualization from '../CallGraphVisualization';
import { ComparisonResult } from '../types';

// Create a mock store
const mockStore = configureStore([]);

// Mock the canvas drawing methods since they're not available in JSDOM
HTMLCanvasElement.prototype.getContext = jest.fn(() => ({
  clearRect: jest.fn(),
  beginPath: jest.fn(),
  moveTo: jest.fn(),
  lineTo: jest.fn(),
  arc: jest.fn(),
  fill: jest.fn(),
  stroke: jest.fn(),
  fillText: jest.fn(),
  fillRect: jest.fn(),
  strokeStyle: '',
  fillStyle: '',
  font: '',
}));

describe('CallGraphVisualization Component', () => {
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
    overall_similarity: 0.85,
    function_similarity: 0.80,
    structure_similarity: 0.90,
    call_graph_similarity: 0.75,
  };

  test('renders call graph visualization with correct data', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        comparisons: [mockComparison],
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <CallGraphVisualization comparisonId="comp-123" />
      </Provider>
    );

    // Check if title is rendered
    expect(screen.getByText('Call Graph Visualization')).toBeInTheDocument();
    
    // Check if view mode selector is rendered
    expect(screen.getByText('View Mode')).toBeInTheDocument();
    expect(screen.getByText('Side by Side')).toBeInTheDocument();
    
    // Check if depth selector is rendered
    expect(screen.getByText('Depth')).toBeInTheDocument();
    
    // Check if similarity percentage is displayed
    expect(screen.getByText('75.0% Similar')).toBeInTheDocument();
    
    // Check if export button is rendered
    expect(screen.getByText('Export Graph')).toBeInTheDocument();
    
    // Check if canvas is rendered
    const canvas = screen.getByRole('img');
    expect(canvas).toBeInTheDocument();
    expect(canvas.tagName.toLowerCase()).toBe('canvas');
  });

  test('changes view mode when dropdown is changed', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        comparisons: [mockComparison],
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <CallGraphVisualization comparisonId="comp-123" />
      </Provider>
    );

    // Find the view mode select
    const viewModeSelect = screen.getByLabelText('View Mode');
    
    // Change the view mode to "Difference View"
    fireEvent.change(viewModeSelect, { target: { value: 'diff' } });
    
    // Check if the select value has changed
    expect(viewModeSelect.value).toBe('diff');
  });

  test('changes depth when dropdown is changed', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        comparisons: [mockComparison],
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <CallGraphVisualization comparisonId="comp-123" />
      </Provider>
    );

    // Find the depth select
    const depthSelect = screen.getByLabelText('Depth');
    
    // Change the depth to 3
    fireEvent.change(depthSelect, { target: { value: '3' } });
    
    // Check if the select value has changed
    expect(depthSelect.value).toBe('3');
  });
});