import pytest
import os
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.binary_loader import BinaryLoader


class TestBinaryLoader:
    def test_binary_loader_initialization(self):
        loader = BinaryLoader()
        assert loader is not None

    def test_supported_formats(self):
        loader = BinaryLoader()
        assert hasattr(loader, 'supported_formats')
        assert isinstance(loader.supported_formats, list)
        assert len(loader.supported_formats) > 0
        
    @pytest.mark.parametrize("format_name", ["elf", "pe", "macho"])
    def test_format_support(self, format_name):
        loader = BinaryLoader()
        assert format_name in loader.supported_formats


class TestDecompilerFactory:
    @pytest.fixture
    def decompiler_factory(self):
        from src.decompilers.decompiler_factory import DecompilerFactory
        return DecompilerFactory()

    def test_factory_initialization(self, decompiler_factory):
        assert decompiler_factory is not None

    def test_get_decompiler(self, decompiler_factory):
        from src.decompilers.ghidra_decompiler import GhidraDecompiler
        decompiler = decompiler_factory.get_decompiler("ghidra")
        assert decompiler is not None
        assert isinstance(decompiler, GhidraDecompiler)

    def test_invalid_decompiler(self, decompiler_factory):
        with pytest.raises(ValueError):
            decompiler_factory.get_decompiler("invalid_decompiler_name")
