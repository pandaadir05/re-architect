import { fireEvent, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import configureStore from 'redux-mock-store';
import EnhancedFunctionChangesTable from '../EnhancedFunctionChangesTable';
import { FunctionChange } from '../types';

// Create a mock store
const mockStore = configureStore([]);

// Mock Material UI components that might be problematic in tests
jest.mock('@mui/material/Popover', () => {
  return ({ children, open }) => (open ? <div data-testid="mock-popover">{children}</div> : null);
});

describe('EnhancedFunctionChangesTable Component', () => {
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

  test('renders enhanced function changes table with correct data', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedFunctionChangesTable 
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

    // Check if statistics chips are displayed
    expect(screen.getByText('UNCHANGED: 1')).toBeInTheDocument();
    expect(screen.getByText('MODIFIED: 1')).toBeInTheDocument();
    expect(screen.getByText('REMOVED: 1')).toBeInTheDocument();
    expect(screen.getByText('ADDED: 1')).toBeInTheDocument();
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
        <EnhancedFunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Find view buttons by their tooltip
    const viewButtons = screen.getAllByTitle('View Function Details');
    
    // Click the first view button
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
        <EnhancedFunctionChangesTable 
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
        <EnhancedFunctionChangesTable 
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
        <EnhancedFunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
          searchQuery="nonexistent"
        />
      </Provider>
    );

    // Check if empty state message is displayed
    expect(screen.getByText('No function changes found')).toBeInTheDocument();
  });
  
  test('sorts functions when column header is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedFunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Find Function Name column header and click it to sort
    const functionNameHeader = screen.getByText('Function Name');
    fireEvent.click(functionNameHeader);
    
    // Check if sorting indicator is active
    const sortLabel = functionNameHeader.closest('th')?.querySelector('.MuiTableSortLabel-active');
    expect(sortLabel).not.toBeNull();
  });
  
  test('opens filter popover when filter button is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedFunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Find and click the filter button
    const filterButton = screen.getByTitle('Filter functions');
    fireEvent.click(filterButton);
    
    // Check if filter popover is displayed
    expect(screen.getByTestId('mock-popover')).toBeInTheDocument();
    expect(screen.getByText('Change Type')).toBeInTheDocument();
    expect(screen.getByText('Similarity')).toBeInTheDocument();
  });
  
  test('filters functions by change type when type chips are clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedFunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Find and click the ADDED type chip
    const addedChip = screen.getByText('ADDED: 1');
    fireEvent.click(addedChip);
    
    // Only the ADDED function should be visible
    expect(screen.queryByText('main')).not.toBeInTheDocument();
    expect(screen.queryByText('initialize')).not.toBeInTheDocument();
    expect(screen.queryByText('process_data')).not.toBeInTheDocument();
    expect(screen.getByText('new_feature')).toBeInTheDocument();
    
    // Check if the filtered indicator is displayed
    expect(screen.getByText('Filtered')).toBeInTheDocument();
  });
  
  test('clears filters when clear button is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        functionChanges: mockFunctionChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedFunctionChangesTable 
          comparisonId="comp-123" 
          onViewFunction={mockOnViewFunction}
        />
      </Provider>
    );

    // Apply a filter first
    const addedChip = screen.getByText('ADDED: 1');
    fireEvent.click(addedChip);
    
    // Check that filter is applied
    expect(screen.queryByText('main')).not.toBeInTheDocument();
    
    // Find and click the filtered chip to clear filters
    const filteredChip = screen.getByText('Filtered');
    fireEvent.click(filteredChip);
    
    // All functions should be visible again
    expect(screen.getByText('main')).toBeInTheDocument();
    expect(screen.getByText('initialize')).toBeInTheDocument();
    expect(screen.getByText('process_data')).toBeInTheDocument();
    expect(screen.getByText('new_feature')).toBeInTheDocument();
  });
});