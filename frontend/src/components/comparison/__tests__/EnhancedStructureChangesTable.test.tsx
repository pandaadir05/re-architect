import { fireEvent, render, screen } from '@testing-library/react';
import { Provider } from 'react-redux';
import configureStore from 'redux-mock-store';
import EnhancedStructureChangesTable from '../EnhancedStructureChangesTable';
import { StructureChange } from '../types';

// Create a mock store
const mockStore = configureStore([]);

// Mock Material UI components that might be problematic in tests
jest.mock('@mui/material/Popover', () => {
  return ({ children, open }: { children: React.ReactNode, open: boolean }) => (
    open ? <div data-testid="mock-popover">{children}</div> : null
  );
});

// Mock Collapse component
jest.mock('@mui/material/Collapse', () => {
  return ({ children, in: open }: { children: React.ReactNode, in: boolean }) => (
    open ? <div data-testid="mock-collapse">{children}</div> : null
  );
});

describe('EnhancedStructureChangesTable Component', () => {
  // Sample structure changes for testing
  const mockStructureChanges: StructureChange[] = [
    {
      id: 'struct-1',
      structure_name: 'Point',
      change_type: 'UNCHANGED',
      similarity: 1.0,
      field_changes: [
        {
          field_name: 'x',
          base_type: 'int32_t',
          target_type: 'int32_t',
          change_type: 'UNCHANGED'
        },
        {
          field_name: 'y',
          base_type: 'int32_t',
          target_type: 'int32_t',
          change_type: 'UNCHANGED'
        }
      ]
    },
    {
      id: 'struct-2',
      structure_name: 'Rectangle',
      change_type: 'MODIFIED',
      similarity: 0.8,
      field_changes: [
        {
          field_name: 'width',
          base_type: 'int32_t',
          target_type: 'float',
          change_type: 'MODIFIED'
        },
        {
          field_name: 'height',
          base_type: 'int32_t',
          target_type: 'float',
          change_type: 'MODIFIED'
        }
      ]
    },
    {
      id: 'struct-3',
      structure_name: 'OldStruct',
      change_type: 'REMOVED',
      field_changes: []
    },
    {
      id: 'struct-4',
      structure_name: 'NewStruct',
      change_type: 'ADDED',
      field_changes: [
        {
          field_name: 'data',
          base_type: null,
          target_type: 'char*',
          change_type: 'ADDED'
        }
      ]
    }
  ];

  // Mock function for onViewStructure callback
  const mockOnViewStructure = jest.fn();

  beforeEach(() => {
    // Reset mock function before each test
    mockOnViewStructure.mockReset();
  });

  test('renders enhanced structure changes table with correct data', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        structureChanges: mockStructureChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
        />
      </Provider>
    );

    // Check if table headers are rendered
    expect(screen.getByText('Structure Name')).toBeInTheDocument();
    expect(screen.getByText('Similarity')).toBeInTheDocument();
    
    // Check if structure data is displayed
    expect(screen.getByText('Point')).toBeInTheDocument();
    expect(screen.getByText('Rectangle')).toBeInTheDocument();
    expect(screen.getByText('OldStruct')).toBeInTheDocument();
    expect(screen.getByText('NewStruct')).toBeInTheDocument();
    
    // Check if similarity scores are displayed
    expect(screen.getByText('100.0%')).toBeInTheDocument();
    expect(screen.getByText('80.0%')).toBeInTheDocument();

    // Check if statistics chips are displayed
    expect(screen.getByText('UNCHANGED: 1')).toBeInTheDocument();
    expect(screen.getByText('MODIFIED: 1')).toBeInTheDocument();
    expect(screen.getByText('REMOVED: 1')).toBeInTheDocument();
    expect(screen.getByText('ADDED: 1')).toBeInTheDocument();
  });

  test('calls onViewStructure when view button is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        structureChanges: mockStructureChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
        />
      </Provider>
    );

    // Find view buttons
    const viewButtons = screen.getAllByTitle('View Structure Details');
    
    // Click the first view button (for structures without field changes)
    fireEvent.click(viewButtons[0]);
    
    // Check if onViewStructure was called with the correct structure ID
    expect(mockOnViewStructure).toHaveBeenCalled();
  });

  test('expands field changes when expand button is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        structureChanges: mockStructureChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
        />
      </Provider>
    );
    
    // Find expand buttons (first row should have one)
    const expandButtons = screen.getAllByTestId('KeyboardArrowDownIcon');
    
    // Click to expand
    fireEvent.click(expandButtons[0]);
    
    // Field changes should be visible (collapse mock should render)
    expect(screen.getByTestId('mock-collapse')).toBeInTheDocument();
    expect(screen.getByText('Field Changes')).toBeInTheDocument();
  });

  test('filters structures based on search query', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        structureChanges: mockStructureChanges,
      },
    });

    // Render component with store and search query
    const { rerender } = render(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
          searchQuery=""
        />
      </Provider>
    );

    // Initially all structures should be visible
    expect(screen.getByText('Point')).toBeInTheDocument();
    expect(screen.getByText('Rectangle')).toBeInTheDocument();
    expect(screen.getByText('OldStruct')).toBeInTheDocument();
    expect(screen.getByText('NewStruct')).toBeInTheDocument();

    // Re-render with a search query
    rerender(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
          searchQuery="Rect"
        />
      </Provider>
    );

    // Only 'Rectangle' should be visible
    expect(screen.queryByText('Point')).not.toBeInTheDocument();
    expect(screen.getByText('Rectangle')).toBeInTheDocument();
    expect(screen.queryByText('OldStruct')).not.toBeInTheDocument();
    expect(screen.queryByText('NewStruct')).not.toBeInTheDocument();
  });

  test('sorts structures when column header is clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        structureChanges: mockStructureChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
        />
      </Provider>
    );

    // Find Structure Name column header and click it to sort
    const nameHeader = screen.getByText('Structure Name');
    fireEvent.click(nameHeader);
    
    // Check if sorting indicator is active
    const sortLabel = nameHeader.closest('th')?.querySelector('.MuiTableSortLabel-active');
    expect(sortLabel).not.toBeNull();
  });
  
  test('filters structures by change type when type chips are clicked', () => {
    // Create store with mock data
    const store = mockStore({
      comparison: {
        structureChanges: mockStructureChanges,
      },
    });

    // Render component with store
    render(
      <Provider store={store}>
        <EnhancedStructureChangesTable 
          comparisonId="comp-123" 
          onViewStructure={mockOnViewStructure}
        />
      </Provider>
    );

    // Find and click the ADDED type chip
    const addedChip = screen.getByText('ADDED: 1');
    fireEvent.click(addedChip);
    
    // Only the ADDED structure should be visible
    expect(screen.queryByText('Point')).not.toBeInTheDocument();
    expect(screen.queryByText('Rectangle')).not.toBeInTheDocument();
    expect(screen.queryByText('OldStruct')).not.toBeInTheDocument();
    expect(screen.getByText('NewStruct')).toBeInTheDocument();
    
    // Check if the filtered indicator is displayed
    expect(screen.getByText('Filtered')).toBeInTheDocument();
  });
});