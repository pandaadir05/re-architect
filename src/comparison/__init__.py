"""Binary comparison package for RE-ARCHITECT.

This package contains modules for comparing binary analysis results
between different versions of a program.
"""

from src.comparison.models import AnalysisProject, ComparisonResult
from src.comparison.comparator import BinaryComparator
from src.comparison.store import ComparisonStore
from src.comparison.analyzer import (
    BinaryComparisonAnalyzer,
    BinaryDiff,
    FunctionDiff,
    StructureDiff
)

__all__ = [
    'AnalysisProject', 
    'ComparisonResult', 
    'BinaryComparator',
    'ComparisonStore',
    'BinaryComparisonAnalyzer',
    'BinaryDiff',
    'FunctionDiff',
    'StructureDiff'
]