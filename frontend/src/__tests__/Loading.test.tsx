import { render, screen } from '@testing-library/react';
import Loading from '../components/common/Loading';

describe('Loading Component', () => {
  test('renders loading spinner with default message', () => {
    render(<Loading />);
    
    // Check for loading message
    expect(screen.getByText('Loading...')).toBeInTheDocument();
  });

  test('renders loading spinner with custom message', () => {
    const customMessage = 'Processing binary...';
    render(<Loading message={customMessage} />);
    
    // Check for custom message
    expect(screen.getByText(customMessage)).toBeInTheDocument();
  });
});
