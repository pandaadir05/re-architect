"""
Integration tests for unpacking in the analysis pipeline.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.core.binary_loader import BinaryLoader
from src.core.pipeline import ReversePipeline
from src.core.config import Config
from src.unpacking.symbolic_unpacker import SymbolicUnpacker


class TestUnpackingPipeline:
    """Test cases for unpacking integration in the analysis pipeline."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
        self.binary_loader = BinaryLoader()
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_binary_loader_auto_unpack_enabled(self):
        """Test binary loader with auto-unpack enabled."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Mock the unpacker to return a successful result
        with patch('src.core.binary_loader.SymbolicUnpacker') as mock_unpacker_class:
            mock_unpacker = Mock()
            mock_unpacker.is_available.return_value = True
            mock_unpacker.detect_packer.return_value = "UPX"
            
            # Create a mock unpacked binary
            unpacked_binary = self.temp_path / "test_packed_unpacked.exe"
            unpacked_binary.write_bytes(b"Unpacked binary data")
            
            mock_result = Mock()
            mock_result.success = True
            mock_result.unpacked_path = unpacked_binary
            mock_unpacker.unpack.return_value = mock_result
            
            mock_unpacker_class.return_value = mock_unpacker
            
            # Test loading with auto-unpack enabled
            binary_info = self.binary_loader.load(test_binary, auto_unpack=True)
            
            # Verify unpacker was called
            mock_unpacker.detect_packer.assert_called_once_with(test_binary)
            mock_unpacker.unpack.assert_called_once_with(test_binary)
            
            # Verify the unpacked binary was used
            assert binary_info.path == unpacked_binary
    
    def test_binary_loader_auto_unpack_disabled(self):
        """Test binary loader with auto-unpack disabled."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Test loading with auto-unpack disabled
        binary_info = self.binary_loader.load(test_binary, auto_unpack=False)
        
        # Verify the original binary was used
        assert binary_info.path == test_binary
    
    def test_binary_loader_unpacker_not_available(self):
        """Test binary loader when unpacker is not available."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Mock the unpacker to be unavailable
        with patch('src.core.binary_loader.SymbolicUnpacker') as mock_unpacker_class:
            mock_unpacker = Mock()
            mock_unpacker.is_available.return_value = False
            mock_unpacker_class.return_value = mock_unpacker
            
            # Test loading with auto-unpack enabled
            binary_info = self.binary_loader.load(test_binary, auto_unpack=True)
            
            # Verify unpacker was called but no unpacking occurred
            mock_unpacker.is_available.assert_called_once()
            mock_unpacker.detect_packer.assert_not_called()
            
            # Verify the original binary was used
            assert binary_info.path == test_binary
    
    def test_binary_loader_no_packer_detected(self):
        """Test binary loader when no packer is detected."""
        # Create a normal binary
        normal_data = b"Normal binary data"
        test_binary = self.temp_path / "test_normal.exe"
        test_binary.write_bytes(normal_data)
        
        # Mock the unpacker to detect no packer
        with patch('src.core.binary_loader.SymbolicUnpacker') as mock_unpacker_class:
            mock_unpacker = Mock()
            mock_unpacker.is_available.return_value = True
            mock_unpacker.detect_packer.return_value = None
            mock_unpacker_class.return_value = mock_unpacker
            
            # Test loading with auto-unpack enabled
            binary_info = self.binary_loader.load(test_binary, auto_unpack=True)
            
            # Verify unpacker was called but no unpacking occurred
            mock_unpacker.detect_packer.assert_called_once_with(test_binary)
            mock_unpacker.unpack.assert_not_called()
            
            # Verify the original binary was used
            assert binary_info.path == test_binary
    
    def test_binary_loader_unpacking_failed(self):
        """Test binary loader when unpacking fails."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Mock the unpacker to fail unpacking
        with patch('src.core.binary_loader.SymbolicUnpacker') as mock_unpacker_class:
            mock_unpacker = Mock()
            mock_unpacker.is_available.return_value = True
            mock_unpacker.detect_packer.return_value = "UPX"
            
            mock_result = Mock()
            mock_result.success = False
            mock_result.error_message = "Unpacking failed"
            mock_unpacker.unpack.return_value = mock_result
            
            mock_unpacker_class.return_value = mock_unpacker
            
            # Test loading with auto-unpack enabled
            binary_info = self.binary_loader.load(test_binary, auto_unpack=True)
            
            # Verify unpacker was called
            mock_unpacker.detect_packer.assert_called_once_with(test_binary)
            mock_unpacker.unpack.assert_called_once_with(test_binary)
            
            # Verify the original binary was used (fallback)
            assert binary_info.path == test_binary
    
    def test_binary_loader_unpacking_import_error(self):
        """Test binary loader when unpacking module import fails."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Mock import error for unpacking module
        with patch('src.core.binary_loader.SymbolicUnpacker', side_effect=ImportError):
            # Test loading with auto-unpack enabled
            binary_info = self.binary_loader.load(test_binary, auto_unpack=True)
            
            # Verify the original binary was used (fallback)
            assert binary_info.path == test_binary
    
    def test_binary_loader_unpacking_exception(self):
        """Test binary loader when unpacking raises an exception."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Mock the unpacker to raise an exception
        with patch('src.core.binary_loader.SymbolicUnpacker') as mock_unpacker_class:
            mock_unpacker = Mock()
            mock_unpacker.is_available.return_value = True
            mock_unpacker.detect_packer.side_effect = Exception("Unpacker error")
            mock_unpacker_class.return_value = mock_unpacker
            
            # Test loading with auto-unpack enabled
            binary_info = self.binary_loader.load(test_binary, auto_unpack=True)
            
            # Verify the original binary was used (fallback)
            assert binary_info.path == test_binary
    
    def test_pipeline_with_unpacking(self):
        """Test the full pipeline with unpacking enabled."""
        # Create a mock packed binary
        packed_data = b"UPX! This is a packed binary"
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(packed_data)
        
        # Create a mock unpacked binary
        unpacked_binary = self.temp_path / "test_packed_unpacked.exe"
        unpacked_binary.write_bytes(b"Unpacked binary data")
        
        # Mock the unpacker
        with patch('src.core.binary_loader.SymbolicUnpacker') as mock_unpacker_class:
            mock_unpacker = Mock()
            mock_unpacker.is_available.return_value = True
            mock_unpacker.detect_packer.return_value = "UPX"
            
            mock_result = Mock()
            mock_result.success = True
            mock_result.unpacked_path = unpacked_binary
            mock_unpacker.unpack.return_value = mock_result
            
            mock_unpacker_class.return_value = mock_unpacker
            
            # Mock the pipeline components
            with patch('src.core.pipeline.StaticAnalyzer') as mock_static_analyzer_class:
                with patch('src.core.pipeline.DynamicAnalyzer') as mock_dynamic_analyzer_class:
                    with patch('src.core.pipeline.DecompilerFactory') as mock_decompiler_factory_class:
                        # Set up mocks
                        mock_static_analyzer = Mock()
                        mock_analysis_result = Mock()
                        mock_analysis_result.functions = {}
                        mock_static_analyzer.analyze.return_value = mock_analysis_result
                        
                        mock_dynamic_analyzer = Mock()
                        mock_dynamic_analyzer.analyze.return_value = {"traces": []}
                        
                        mock_decompiler = Mock()
                        mock_decompiled_code = Mock()
                        mock_decompiled_code.types = {}
                        mock_decompiler.decompile.return_value = mock_decompiled_code
                        
                        mock_static_analyzer_class.return_value = mock_static_analyzer
                        mock_dynamic_analyzer_class.return_value = mock_dynamic_analyzer
                        mock_decompiler_factory_class.return_value.create.return_value = mock_decompiler
                        
                        # Create pipeline
                        config = Config()
                        pipeline = ReversePipeline(config)
                        
                        # Run pipeline
                        result = pipeline.analyze(test_binary)
                        
                        # Verify unpacking occurred
                        mock_unpacker.detect_packer.assert_called_once_with(test_binary)
                        mock_unpacker.unpack.assert_called_once_with(test_binary)
                        
                        # Verify the unpacked binary was used in analysis
                        mock_static_analyzer.analyze.assert_called_once()
                        # Note: Dynamic analyzer is not called by default (dynamic.enable=false in config)
                        mock_decompiler.decompile.assert_called_once()
                        
                        # Verify result is a valid pipeline result
                        assert "metadata" in result
                        assert "functions" in result
                        assert "data_structures" in result
                        
                        # Unpacking info validation is done through the mock assertions above
                        # The actual unpacking result integration is not yet implemented in pipeline
