"""
Unit tests for the symbolic unpacker module.
"""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.unpacking.symbolic_unpacker import SymbolicUnpacker, UnpackingResult


class TestSymbolicUnpacker:
    """Test cases for SymbolicUnpacker."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.unpacker = SymbolicUnpacker()
        self.temp_dir = tempfile.mkdtemp()
        self.temp_path = Path(self.temp_dir)
    
    def teardown_method(self):
        """Clean up test fixtures."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_init_default_config(self):
        """Test unpacker initialization with default config."""
        unpacker = SymbolicUnpacker()
        assert unpacker.max_execution_steps == 10000
        assert unpacker.timeout_seconds == 300
        assert unpacker.memory_dump_threshold == 1024 * 1024
    
    def test_init_custom_config(self):
        """Test unpacker initialization with custom config."""
        config = {
            "unpacking.max_execution_steps": 5000,
            "unpacking.timeout_seconds": 150,
            "unpacking.memory_dump_threshold": 512 * 1024
        }
        unpacker = SymbolicUnpacker(config)
        assert unpacker.max_execution_steps == 5000
        assert unpacker.timeout_seconds == 150
        assert unpacker.memory_dump_threshold == 512 * 1024
    
    def test_detect_packer_upx(self):
        """Test UPX packer detection."""
        # Create a mock UPX-packed binary
        upx_data = b"UPX! This is a test binary"
        test_binary = self.temp_path / "test_upx.exe"
        test_binary.write_bytes(upx_data)
        
        packer = self.unpacker.detect_packer(test_binary)
        assert packer == "UPX"
    
    def test_detect_packer_pecompact(self):
        """Test PECompact packer detection."""
        pecompact_data = b"PECompact packed binary data"
        test_binary = self.temp_path / "test_pecompact.exe"
        test_binary.write_bytes(pecompact_data)
        
        packer = self.unpacker.detect_packer(test_binary)
        assert packer == "PECompact"
    
    def test_detect_packer_aspack(self):
        """Test ASPack packer detection."""
        aspack_data = b"aPLib compressed data with ASPack"
        test_binary = self.temp_path / "test_aspack.exe"
        test_binary.write_bytes(aspack_data)
        
        packer = self.unpacker.detect_packer(test_binary)
        assert packer == "ASPack"
    
    def test_detect_packer_unknown(self):
        """Test detection of unknown packed binary."""
        # High entropy data that looks packed
        high_entropy_data = bytes(range(256)) * 10  # High entropy
        test_binary = self.temp_path / "test_unknown.exe"
        test_binary.write_bytes(high_entropy_data)
        
        packer = self.unpacker.detect_packer(test_binary)
        assert packer == "Unknown"
    
    def test_detect_packer_not_packed(self):
        """Test detection of non-packed binary."""
        # Low entropy data that looks like normal code
        normal_data = b"Hello, World!" * 100
        test_binary = self.temp_path / "test_normal.exe"
        test_binary.write_bytes(normal_data)
        
        packer = self.unpacker.detect_packer(test_binary)
        assert packer is None
    
    def test_detect_packer_file_not_found(self):
        """Test packer detection with non-existent file."""
        non_existent = self.temp_path / "does_not_exist.exe"
        packer = self.unpacker.detect_packer(non_existent)
        assert packer is None
    
    def test_calculate_entropy(self):
        """Test entropy calculation."""
        # Test with uniform distribution (high entropy)
        uniform_data = bytes(range(256))
        entropy = self.unpacker._calculate_entropy(uniform_data)
        assert entropy > 7.0
        
        # Test with repeated data (low entropy)
        repeated_data = b"A" * 1000
        entropy = self.unpacker._calculate_entropy(repeated_data)
        assert entropy < 1.0
        
        # Test with empty data
        entropy = self.unpacker._calculate_entropy(b"")
        assert entropy == 0.0
    
    def test_is_likely_packed_high_entropy(self):
        """Test packed binary detection with high entropy."""
        high_entropy_data = bytes(range(256)) * 10
        assert self.unpacker._is_likely_packed(high_entropy_data)
    
    def test_is_likely_packed_low_entropy(self):
        """Test packed binary detection with low entropy."""
        low_entropy_data = b"A" * 1000
        assert not self.unpacker._is_likely_packed(low_entropy_data)
    
    def test_is_likely_packed_suspicious_patterns(self):
        """Test packed binary detection with suspicious patterns."""
        suspicious_data = b"Normal data with .upx section" + b"A" * 1000  # Make it large enough
        assert self.unpacker._is_likely_packed(suspicious_data)
    
    def test_is_likely_packed_too_small(self):
        """Test packed binary detection with very small file."""
        small_data = b"Hi"
        assert not self.unpacker._is_likely_packed(small_data)
    
    @patch('src.unpacking.symbolic_unpacker.ANGR_AVAILABLE', False)
    def test_unpack_angr_unavailable(self):
        """Test unpacking when Angr is not available."""
        # Create test binary
        test_binary = self.temp_path / "test_packed.exe"
        test_binary.write_bytes(b"UPX! packed data")
        
        result = self.unpacker.unpack(test_binary)
        
        assert not result.success
        assert "Angr not available" in result.error_message
    
    def test_unpack_no_packer_detected(self):
        """Test unpacking when no packer is detected."""
        test_binary = self.temp_path / "test_normal.exe"
        test_binary.write_bytes(b"Normal binary data")
        
        result = self.unpacker.unpack(test_binary)
        
        assert not result.success
        assert result.error_message == "No packer detected"
    
    def test_unpack_angr_not_available(self):
        """Test unpacking when Angr is not available."""
        with patch('src.unpacking.symbolic_unpacker.ANGR_AVAILABLE', False):
            test_binary = self.temp_path / "test_packed.exe"
            test_binary.write_bytes(b"UPX! packed data")
            
            result = self.unpacker.unpack(test_binary)
            
            assert not result.success
            assert "Angr not available" in result.error_message
    
    def test_unpack_extraction_failed(self):
        """Test unpacking when extraction fails."""
        with patch('src.unpacking.symbolic_unpacker.angr'):
            with patch('src.unpacking.symbolic_unpacker.ANGR_AVAILABLE', True):
                with patch.object(self.unpacker, '_extract_unpacked_binary', return_value=None):
                    test_binary = self.temp_path / "test_packed.exe"
                    test_binary.write_bytes(b"UPX! packed data")
                    
                    result = self.unpacker.unpack(test_binary)
                    
                    assert not result.success
                    assert "Failed to extract unpacked binary" in result.error_message
    
    def test_is_available_with_angr(self):
        """Test availability check when Angr is available."""
        with patch('src.unpacking.symbolic_unpacker.ANGR_AVAILABLE', True):
            assert self.unpacker.is_available()
    
    def test_is_available_without_angr(self):
        """Test availability check when Angr is not available."""
        with patch('src.unpacking.symbolic_unpacker.ANGR_AVAILABLE', False):
            assert not self.unpacker.is_available()
    
    def test_get_unpacker_info(self):
        """Test unpacker info retrieval."""
        info = self.unpacker.get_unpacker_info()
        
        assert info["name"] == "SymbolicUnpacker"
        assert "available" in info
        assert info["max_execution_steps"] == 10000
        assert info["timeout_seconds"] == 300
        assert "supported_packers" in info
        assert "UPX" in info["supported_packers"]
    
    def test_unpacking_result_initialization(self):
        """Test UnpackingResult initialization."""
        result = UnpackingResult(success=True)
        
        assert result.success
        assert result.unpacked_path is None
        assert result.original_path is None
        assert result.packer_detected is None
        assert result.unpacking_method is None
        assert result.execution_steps == 0
        assert result.memory_dumps == []
        assert result.error_message is None
        assert result.metadata == {}
    
    def test_unpacking_result_with_data(self):
        """Test UnpackingResult with data."""
        memory_dumps = [(0x1000, 1024, b"data")]
        metadata = {"test": "value"}
        
        result = UnpackingResult(
            success=True,
            unpacked_path=Path("/tmp/unpacked.exe"),
            original_path=Path("/tmp/packed.exe"),
            packer_detected="UPX",
            unpacking_method="symbolic_execution",
            execution_steps=1000,
            memory_dumps=memory_dumps,
            metadata=metadata
        )
        
        assert result.success
        assert result.unpacked_path == Path("/tmp/unpacked.exe")
        assert result.original_path == Path("/tmp/packed.exe")
        assert result.packer_detected == "UPX"
        assert result.unpacking_method == "symbolic_execution"
        assert result.execution_steps == 1000
        assert result.memory_dumps == memory_dumps
        assert result.metadata == metadata
