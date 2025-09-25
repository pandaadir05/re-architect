import os
import sys
import tempfile
from pathlib import Path

import pytest

# Add the src directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.core.pipeline import ReversePipeline
from src.core.config import Config


class TestPipelineDynamicDisabled:
    @pytest.fixture
    def temp_config_file(self):
        config_content = """
        decompiler:
          default: ghidra
          ghidra:
            path: null
            headless: true
            timeout: 60
        analysis:
          static:
            function_analysis_depth: basic
          dynamic:
            enable: false
        llm:
          enable: false
        output:
          detail_level: basic
          formats: [json]
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml') as f:
            f.write(config_content)
            config_path = f.name
        yield config_path
        os.unlink(config_path)

    @pytest.fixture
    def mock_binary_path(self):
        with tempfile.NamedTemporaryFile(delete=False, mode='wb', suffix='.bin') as f:
            f.write(b'\x7fELF\x02\x01\x01')
            binary_path = f.name
        yield binary_path
        os.unlink(binary_path)

    @pytest.fixture
    def pipeline(self, temp_config_file, monkeypatch):
        import src.decompilers.ghidra_decompiler
        monkeypatch.setattr(src.decompilers.ghidra_decompiler.GhidraDecompiler,
                            'decompile',
                            lambda self, binary_info: type('D', (), {
                                'functions': {0x1000: 'int main() { return 0; }'},
                                'function_names': {0x1000: 'main'},
                                'function_metadata': {0x1000: {}}
                            })())
        config = Config(temp_config_file)
        return ReversePipeline(config)

    def test_pipeline_runs_with_dynamic_disabled(self, pipeline, mock_binary_path, monkeypatch):
        import src.analysis.static_analyzer
        class MockAnalysisResults:
            def __init__(self):
                self.functions = {'main': {'name': 'main', 'code': 'int main() { return 0; }'}}
        monkeypatch.setattr(src.analysis.static_analyzer.StaticAnalyzer,
                            'analyze',
                            lambda self, decompiled: MockAnalysisResults())
        import src.analysis.data_structure_analyzer
        monkeypatch.setattr(src.analysis.data_structure_analyzer.DataStructureAnalyzer,
                            'analyze',
                            lambda self, decompiled, static_analysis: {})
        monkeypatch.setattr(ReversePipeline, '_save_results', lambda self: None)
        results = pipeline.analyze(mock_binary_path)
        assert 'functions' in results
        assert 'data_structures' in results
