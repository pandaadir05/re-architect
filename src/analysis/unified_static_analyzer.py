"""
Unified static analyzer that can work with both binary data and decompiled code.

This module provides a single interface for static analysis that automatically
chooses the best approach based on available data and capabilities.
"""

import logging
from typing import Optional, Union
from pathlib import Path

from src.core.config import Config
from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import DecompiledCode
from src.analysis.static_analyzer import StaticAnalyzer, StaticAnalysisResults as LegacyResults
from src.analysis.enhanced_static_analyzer import EnhancedStaticAnalyzer, StaticAnalysisResults as EnhancedResults

logger = logging.getLogger("re-architect.analysis.unified")

class UnifiedStaticAnalyzer:
    """
    Unified static analyzer that can analyze both binary data and decompiled code.
    
    This analyzer automatically selects the best analysis approach:
    - If binary data is available and Capstone is installed: Enhanced binary-level analysis
    - If only decompiled code is available: Legacy decompiled code analysis
    - If both are available: Enhanced analysis with legacy as fallback
    """
    
    def __init__(self, config: Config):
        """
        Initialize the unified static analyzer.
        
        Args:
            config: Configuration object
        """
        self.config = config
        
        # Initialize both analyzers
        self.legacy_analyzer = StaticAnalyzer(config)
        self.enhanced_analyzer = EnhancedStaticAnalyzer(config)
        
        # Check capabilities
        self.enhanced_available = self._check_enhanced_capabilities()
        
    def analyze(
        self,
        binary_info: Optional[BinaryInfo] = None,
        decompiled_code: Optional[DecompiledCode] = None
    ) -> Union[EnhancedResults, LegacyResults]:
        """
        Perform static analysis using the best available method.
        
        Args:
            binary_info: Optional binary information for enhanced analysis
            decompiled_code: Optional decompiled code for legacy analysis
            
        Returns:
            Analysis results from the selected analyzer
            
        Raises:
            ValueError: If no valid input is provided
        """
        if not binary_info and not decompiled_code:
            raise ValueError("Either binary_info or decompiled_code must be provided")
        
        # Prefer enhanced analysis if available and binary info is provided
        if self.enhanced_available and binary_info:
            logger.info("Using enhanced binary-level static analysis")
            try:
                return self.enhanced_analyzer.analyze_binary(binary_info)
            except Exception as e:
                logger.warning(f"Enhanced analysis failed: {e}")
                if decompiled_code:
                    logger.info("Falling back to legacy decompiled code analysis")
                    return self.legacy_analyzer.analyze(decompiled_code)
                else:
                    raise
        
        # Use legacy analysis if enhanced is not available or failed
        if decompiled_code:
            logger.info("Using legacy decompiled code static analysis")
            return self.legacy_analyzer.analyze(decompiled_code)
        
        # If we get here, we have binary info but enhanced analysis is not available
        logger.warning("Enhanced analysis not available and no decompiled code provided")
        raise ValueError("Cannot perform analysis without enhanced capabilities or decompiled code")
    
    def analyze_binary(self, binary_info: BinaryInfo) -> EnhancedResults:
        """
        Perform enhanced binary-level static analysis.
        
        Args:
            binary_info: Binary information to analyze
            
        Returns:
            Enhanced analysis results
            
        Raises:
            RuntimeError: If enhanced analysis is not available
        """
        if not self.enhanced_available:
            raise RuntimeError("Enhanced binary analysis not available - missing dependencies")
        
        logger.info("Performing enhanced binary-level static analysis")
        return self.enhanced_analyzer.analyze_binary(binary_info)
    
    def analyze_decompiled(self, decompiled_code: DecompiledCode) -> LegacyResults:
        """
        Perform legacy decompiled code static analysis.
        
        Args:
            decompiled_code: Decompiled code to analyze
            
        Returns:
            Legacy analysis results
        """
        logger.info("Performing legacy decompiled code static analysis")
        return self.legacy_analyzer.analyze(decompiled_code)
    
    def _check_enhanced_capabilities(self) -> bool:
        """
        Check if enhanced binary analysis is available.
        
        Returns:
            True if enhanced analysis dependencies are available
        """
        try:
            import capstone
            return True
        except ImportError:
            logger.warning("Enhanced static analysis not available - Capstone not installed")
            return False
    
    def get_analysis_info(self) -> dict:
        """
        Get information about available analysis capabilities.
        
        Returns:
            Dictionary with capability information
        """
        return {
            "enhanced_available": self.enhanced_available,
            "legacy_available": True,
            "preferred_method": "enhanced" if self.enhanced_available else "legacy",
            "capstone_available": self.enhanced_available
        }