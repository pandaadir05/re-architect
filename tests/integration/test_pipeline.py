import os
import pytest
import tempfile
import sys
from pathlib import Path

# Add the src directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import necessary components for integration testing
from src.core.pipeline import REPipeline
from src.core.config import Config


class TestPipelineIntegration:
    @pytest.fixture
    def temp_config_file(self):
        # Create a temporary config file for testing
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
          enable: true
          provider: mock
          model: mock-model
        output:
          detail_level: basic
          formats: [json]
        """
        with tempfile.NamedTemporaryFile(delete=False, mode='w', suffix='.yaml') as f:
            f.write(config_content)
            config_path = f.name
            
        yield config_path
        
        # Clean up the temporary file
        os.unlink(config_path)
    
    @pytest.fixture
    def mock_binary_path(self):
        # Create a temporary binary-like file for testing
        with tempfile.NamedTemporaryFile(delete=False, mode='wb', suffix='.bin') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00')
            binary_path = f.name
            
        yield binary_path
        
        # Clean up the temporary file
        os.unlink(binary_path)
        
    @pytest.fixture
    def pipeline(self, temp_config_file, monkeypatch):
        # Mock external dependencies
        import src.decompilers.ghidra_decompiler
        monkeypatch.setattr(src.decompilers.ghidra_decompiler.GhidraDecompiler, 
                           'decompile', 
                           lambda self, binary_path: {'functions': {'main': 'int main() { return 0; }'}})
        
        # Create pipeline with config
        config = Config(temp_config_file)
        pipeline = REPipeline(config)
        return pipeline
    
    def test_pipeline_initialization(self, pipeline):
        assert pipeline is not None
        assert pipeline.config is not None
        
    def test_pipeline_analysis(self, pipeline, mock_binary_path, monkeypatch):
        # Mock the analysis components to avoid actual execution
        # Create a class with the expected properties to mock StaticAnalyzer's return value
        class MockAnalysisResults:
            def __init__(self):
                self.functions = {'main': {'name': 'main', 'code': 'int main() { return 0; }'}}
        
        # Mock the analyze method to return our mock object
        import src.analysis.static_analyzer
        monkeypatch.setattr(src.analysis.static_analyzer.StaticAnalyzer,
                           'analyze',
                           lambda self, decompiled: MockAnalysisResults())
                           
        # Mock the data structure analyzer
        import src.analysis.data_structure_analyzer
        monkeypatch.setattr(src.analysis.data_structure_analyzer.DataStructureAnalyzer,
                           'analyze',
                           lambda self, decompiled, static_analysis: {})
                           
        # Mock BinaryLoader load method to return a simple dict
        import src.core.binary_loader
        
        class MockBinaryInfo:
            def __init__(self):
                self.path = mock_binary_path
                self.architecture = "x86_64"
                self.compiler = "gcc"
                self.entry_point = 0x1000
        
        monkeypatch.setattr(src.core.binary_loader.BinaryLoader,
                           'load',
                           lambda self, path: MockBinaryInfo())
                           
        # Mock _save_results to do nothing
        monkeypatch.setattr(src.core.pipeline.REPipeline,
                          '_save_results',
                          lambda self: None)
                           
        import src.llm.function_summarizer
        monkeypatch.setattr(src.llm.function_summarizer.FunctionSummarizer,
                           'summarize_function',
                           lambda self, function_code: 'This function returns zero.')
                           
        # Run the pipeline
        results = pipeline.analyze(mock_binary_path)
        
        # Check results
        assert results is not None
        assert 'functions' in results
        assert 'data_structures' in results
        # More assertions based on expected pipeline output
