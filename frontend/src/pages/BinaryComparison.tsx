import React, { useEffect } from 'react';
import { useAppDispatch, useAppSelector } from '../redux/hooks';
import { fetchProjects, fetchComparisons } from '../redux/slices/comparisonSlice';
import ComparisonView from '../components/comparison/ComparisonView';

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