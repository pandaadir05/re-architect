import { fireEvent, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import { BrowserRouter } from 'react-router-dom';
import configureStore from 'redux-mock-store';
import ComparisonView from '../ComparisonView';
import { ComparisonResult, FunctionChange, StructureChange } from '../types';

// Create a mock store
const mockStore = configureStore([]);

// Mock the canvas element for CallGraphVisualization
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

// Mock the child components
jest.mock('../ComparisonSummary', () => ({
  __esModule: true,
  default: ({ comparisonId }) => <div data-testid="comparison-summary">{comparisonId}</div>,
}));

jest.mock('../FunctionChangesTable', () => ({
  __esModule: true,
  default: ({ comparisonId, onViewFunction, searchQuery }) => (
    <div data-testid="function-changes-table">
      <p>ComparisonId: {comparisonId}</p>
      <p>SearchQuery: {searchQuery}</p>
      <button onClick={() => onViewFunction('func-1')}>View Function</button>
    </div>
  ),
}));

jest.mock('../StructureChangesTable', () => ({
  __esModule: true,
  default: ({ comparisonId, onViewStructure, searchQuery }) => (
    <div data-testid="structure-changes-table">
      <p>ComparisonId: {comparisonId}</p>
      <p>SearchQuery: {searchQuery}</p>
      <button onClick={() => onViewStructure('struct-1')}>View Structure</button>
    </div>
  ),
}));

jest.mock('../FunctionDiffViewer', () => ({
  __esModule: true,
  default: ({ comparisonId, functionId, onBack }) => (
    <div data-testid="function-diff-viewer">
      <p>ComparisonId: {comparisonId}</p>
      <p>FunctionId: {functionId}</p>
      <button onClick={onBack}>Back</button>
    </div>
  ),
}));

jest.mock('../StructureDiffViewer', () => ({
  __esModule: true,
  default: ({ comparisonId, structureId, onBack }) => (
    <div data-testid="structure-diff-viewer">
      <p>ComparisonId: {comparisonId}</p>
      <p>StructureId: {structureId}</p>
      <button onClick={onBack}>Back</button>
    </div>
  ),
}));

jest.mock('../CallGraphVisualization', () => ({
  __esModule: true,
  default: ({ comparisonId }) => <div data-testid="call-graph-visualization">{comparisonId}</div>,
}));

jest.mock('../ProjectSelector', () => ({
  __esModule: true,
  default: () => <div data-testid="project-selector">Project Selector</div>,
}));

describe('ComparisonView Component', () => {
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

  // Sample functions and structures
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
  ];

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
    },
  ];

  // Create mock dispatch function
  const mockDispatch = jest.fn();

  beforeEach(() => {
    // Reset mock function before each test
    mockDispatch.mockReset();
  });

  test('renders project selector when no comparison is selected', () => {
    // Create store with no selected comparison
    const store = mockStore({
      comparison: {
        selectedComparisonId: null,
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        loading: false,
        error: null,
      },
    });

    // Mock useDispatch
    store.dispatch = mockDispatch;

    // Render component with store
    render(
      <Provider store={store}>
        <BrowserRouter>
          <ComparisonView />
        </BrowserRouter>
      </Provider>
    );

    // Check if project selector is rendered
    expect(screen.getByTestId('project-selector')).toBeInTheDocument();
  });

  test('renders comparison summary when a comparison is selected', () => {
    // Create store with selected comparison
    const store = mockStore({
      comparison: {
        selectedComparisonId: 'comp-123',
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        loading: false,
        error: null,
      },
    });

    // Mock useDispatch
    store.dispatch = mockDispatch;

    // Render component with store
    render(
      <Provider store={store}>
        <BrowserRouter>
          <ComparisonView />
        </BrowserRouter>
      </Provider>
    );

    // Check if comparison summary is rendered
    expect(screen.getByTestId('comparison-summary')).toBeInTheDocument();
    
    // Check if tab navigation is rendered
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Functions')).toBeInTheDocument();
    expect(screen.getByText('Structures')).toBeInTheDocument();
    expect(screen.getByText('Call Graph')).toBeInTheDocument();
  });

  test('switches tabs when clicked', () => {
    // Create store with selected comparison
    const store = mockStore({
      comparison: {
        selectedComparisonId: 'comp-123',
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        loading: false,
        error: null,
      },
    });

    // Mock useDispatch
    store.dispatch = mockDispatch;

    // Render component with store
    render(
      <Provider store={store}>
        <BrowserRouter>
          <ComparisonView />
        </BrowserRouter>
      </Provider>
    );

    // Check if comparison summary is initially rendered
    expect(screen.getByTestId('comparison-summary')).toBeInTheDocument();
    
    // Click on Functions tab
    fireEvent.click(screen.getByText('Functions'));
    
    // Check if function changes table is now rendered
    expect(screen.getByTestId('function-changes-table')).toBeInTheDocument();
    
    // Click on Structures tab
    fireEvent.click(screen.getByText('Structures'));
    
    // Check if structure changes table is now rendered
    expect(screen.getByTestId('structure-changes-table')).toBeInTheDocument();
    
    // Click on Call Graph tab
    fireEvent.click(screen.getByText('Call Graph'));
    
    // Check if call graph visualization is now rendered
    expect(screen.getByTestId('call-graph-visualization')).toBeInTheDocument();
  });

  test('shows function diff viewer when function is selected', () => {
    // Create store with selected comparison
    const store = mockStore({
      comparison: {
        selectedComparisonId: 'comp-123',
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        loading: false,
        error: null,
      },
    });

    // Mock useDispatch
    store.dispatch = mockDispatch;

    // Render component with store
    render(
      <Provider store={store}>
        <BrowserRouter>
          <ComparisonView />
        </BrowserRouter>
      </Provider>
    );
    
    // Click on Functions tab
    fireEvent.click(screen.getByText('Functions'));
    
    // Click on "View Function" button
    fireEvent.click(screen.getByText('View Function'));
    
    // Check if function diff viewer is now rendered
    expect(screen.getByTestId('function-diff-viewer')).toBeInTheDocument();
    expect(screen.getByText('FunctionId: func-1')).toBeInTheDocument();
    
    // Click on "Back" button
    fireEvent.click(screen.getByText('Back'));
    
    // Check if function changes table is shown again
    expect(screen.getByTestId('function-changes-table')).toBeInTheDocument();
  });

  test('shows structure diff viewer when structure is selected', () => {
    // Create store with selected comparison
    const store = mockStore({
      comparison: {
        selectedComparisonId: 'comp-123',
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        loading: false,
        error: null,
      },
    });

    // Mock useDispatch
    store.dispatch = mockDispatch;

    // Render component with store
    render(
      <Provider store={store}>
        <BrowserRouter>
          <ComparisonView />
        </BrowserRouter>
      </Provider>
    );
    
    // Click on Structures tab
    fireEvent.click(screen.getByText('Structures'));
    
    // Click on "View Structure" button
    fireEvent.click(screen.getByText('View Structure'));
    
    // Check if structure diff viewer is now rendered
    expect(screen.getByTestId('structure-diff-viewer')).toBeInTheDocument();
    expect(screen.getByText('StructureId: struct-1')).toBeInTheDocument();
    
    // Click on "Back" button
    fireEvent.click(screen.getByText('Back'));
    
    // Check if structure changes table is shown again
    expect(screen.getByTestId('structure-changes-table')).toBeInTheDocument();
  });

  test('filters functions when search query is entered', () => {
    // Create store with selected comparison
    const store = mockStore({
      comparison: {
        selectedComparisonId: 'comp-123',
        comparisons: [mockComparison],
        functionChanges: mockFunctionChanges,
        structureChanges: mockStructureChanges,
        loading: false,
        error: null,
      },
    });

    // Mock useDispatch
    store.dispatch = mockDispatch;

    // Render component with store
    render(
      <Provider store={store}>
        <BrowserRouter>
          <ComparisonView />
        </BrowserRouter>
      </Provider>
    );
    
    // Click on Functions tab
    fireEvent.click(screen.getByText('Functions'));
    
    // Find search input and enter a search query
    const searchInput = screen.getByPlaceholderText('Search functions...');
    fireEvent.change(searchInput, { target: { value: 'main' } });
    
    // Check if the search query is passed to the table component
    expect(screen.getByText('SearchQuery: main')).toBeInTheDocument();
  });
});