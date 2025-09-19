import React, { useEffect } from 'react';
import ComparisonView from '../components/comparison/ComparisonView';
import { useAppDispatch } from '../redux/hooks';
import { fetchComparisons, fetchProjects } from '../redux/slices/comparisonSlice';

/**
 * Binary Comparison Page Component
 * This is the main page for the binary comparison feature
 */
const BinaryComparisonPage: React.FC = () => {
  const dispatch = useAppDispatch();
  
  // Load projects and comparisons on component mount
  useEffect(() => {
    dispatch(fetchProjects());
    dispatch(fetchComparisons());
  }, [dispatch]);

  return <ComparisonView />;
};

export default BinaryComparisonPage;