import pytest
import os
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add the src directory to the Python path
sys.path.append(str(Path(__file__).parent.parent.parent))

from src.llm.function_summarizer import FunctionSummarizer


class TestFunctionSummarizer:
    @pytest.fixture
    def config(self):
        return {
            "provider": "openai",
            "model": "gpt-4-turbo",
            "max_tokens": 8192,
            "temperature": 0.2,
            "cache_dir": "./cache/llm"
        }
        
    @pytest.fixture
    def summarizer(self, config):
        return FunctionSummarizer(config)
        
    def test_summarizer_initialization(self, summarizer):
        assert summarizer is not None
        assert summarizer.provider == "openai"
        assert summarizer.model == "gpt-4-turbo"
        
    def test_cache_management(self, summarizer):
        # Create mock function for testing
        test_function = """
        int calculate_factorial(int n) {
            if (n <= 1) {
                return 1;
            }
            return n * calculate_factorial(n - 1);
        }
        """
        
        # First call should not use cache
        with patch.object(summarizer, '_call_llm_api') as mock_api:
            mock_api.return_value = "Calculates the factorial of a number recursively."
            result1 = summarizer.summarize_function(test_function)
            assert mock_api.called
            
        # Second call with same function should use cache
        with patch.object(summarizer, '_call_llm_api') as mock_api:
            mock_api.return_value = "Different summary"  # Should not be used
            result2 = summarizer.summarize_function(test_function)
            assert not mock_api.called
            assert result1 == result2
            
    @patch('src.llm.function_summarizer.FunctionSummarizer._call_openai_api')
    def test_provider_selection(self, mock_openai_api, config):
        mock_openai_api.return_value = "OpenAI summary"
        
        # Test OpenAI
        summarizer = FunctionSummarizer(config)
        result = summarizer.summarize_function("void test() {}")
        assert result == "OpenAI summary"
        assert mock_openai_api.called
        
        # Test Anthropic
        with patch('src.llm.function_summarizer.FunctionSummarizer._call_anthropic_api') as mock_anthropic_api:
            mock_anthropic_api.return_value = "Anthropic summary"
            config["provider"] = "anthropic"
            summarizer = FunctionSummarizer(config)
            result = summarizer.summarize_function("void test() {}")
            assert result == "Anthropic summary"
            assert mock_anthropic_api.called
