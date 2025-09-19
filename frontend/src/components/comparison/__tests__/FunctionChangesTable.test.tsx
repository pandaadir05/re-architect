import { fireEvent, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import configureStore from 'redux-mock-store';
import FunctionChangesTable from '../FunctionChangesTable';
import { FunctionChange } from '../types';

// Create a mock store
const mockStore = configureStore([]);

describe('FunctionChangesTable Component', () => {
  // Sample function changes for testing
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
      target_address: undefined,
      change_type: 'REMOVED',
    },
    {
      id: 'func-4',
      function_name: 'new_feature',
      base_address: undefined,
      target_address: '0x1300',
      change_type: 'ADDED',
    }
  ];

  // Mock function for onViewFunction callback
  const mockOnViewFunction = jest.fn();

  beforeEach(() => {
    // Reset mock function before each test
    mockOnViewFunction.mockReset();
  });

  test('renders function changes table with correct data', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <FunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Check if table headers are rendered
    expect(screen.getByText('Function Name')).toBeInTheDocument();
    expect(screen.getByText('Base Address')).toBeInTheDocument();
    expect(screen.getByText('Target Address')).toBeInTheDocument();
    expect(screen.getByText('Similarity')).toBeInTheDocument();
    
    // Check if function data is displayed
    expect(screen.getByText('main')).toBeInTheDocument();
    expect(screen.getByText('initialize')).toBeInTheDocument();
    expect(screen.getByText('process_data')).toBeInTheDocument();
    expect(screen.getByText('new_feature')).toBeInTheDocument();
    
    // Check if addresses are displayed
    expect(screen.getByText('0x1000')).toBeInTheDocument();
    expect(screen.getByText('0x1100')).toBeInTheDocument();
    expect(screen.getByText('0x1200')).toBeInTheDocument();
    expect(screen.getByText('0x1300')).toBeInTheDocument();
    
    // Check if similarity scores are displayed
    expect(screen.getByText('100.0%')).toBeInTheDocument();
    expect(screen.getByText('75.0%')).toBeInTheDocument();
  });

  test('calls onViewFunction when view button is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <FunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Get all view buttons (should be one for each function)
    const viewButtons = screen.getAllByRole('button');
    
    // Click the first view button (for 'main' function)
    fireEvent.click(viewButtons[0]);
    
    // Check if onViewFunction was called with the correct function ID
    expect(mockOnViewFunction).toHaveBeenCalledWith('func-1');
  });

  test('filters functions based on search query', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store and search query
    const { rerender } = render(
      <Provider store={store}>
        <FunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
          searchQuery=""
        />
      </Provider>
    );

    // Initially all functions should be visible
    expect(screen.getByText('main')).toBeInTheDocument();
    expect(screen.getByText('initialize')).toBeInTheDocument();
    expect(screen.getByText('process_data')).toBeInTheDocument();
    expect(screen.getByText('new_feature')).toBeInTheDocument();

    // Re-render with a search query
    rerender(
      <Provider store={store}>
        <FunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
          searchQuery="init"
        />
      </Provider>
    );

    // Only 'initialize' should be visible
    expect(screen.queryByText('main')).not.toBeInTheDocument();
    expect(screen.getByText('initialize')).toBeInTheDocument();
    expect(screen.queryByText('process_data')).not.toBeInTheDocument();
    expect(screen.queryByText('new_feature')).not.toBeInTheDocument();
  });

  test('shows empty state when no functions match', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store and search query that won't match any functions
    render(
      <Provider store={store}>
        <FunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
          searchQuery="nonexistent"
        />
      </Provider>
    );

    // Check if empty state message is displayed
    expect(screen.getByText('No function changes found')).toBeInTheDocument();
  });
});