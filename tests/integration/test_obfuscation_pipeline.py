from pathlib import Path
from unittest.mock import patch, Mock

from src.core.pipeline import ReversePipeline
from src.core.config import Config


@patch('src.core.pipeline.ObfuscationOptimizer')
def test_pipeline_reports_obfuscation_optimization(mock_opt_class, tmp_path):
    # Prepare a dummy binary file
    binary = tmp_path / 'dummy.bin'
    binary.write_bytes(b'not a real binary')

    # Mock optimizer to return a deterministic report
    mock_opt = Mock()
    mock_opt.is_available.return_value = True
    mock_report = Mock()
    mock_report.iterations = 2
    mock_report.changes_applied = 10
    mock_report.passes_run = ["junk_code_removal", "opaque_predicate_solving"]
    mock_report.details = {"per_iteration": [{}, {}]}
    mock_opt.optimize.return_value = mock_report
    mock_opt_class.return_value = mock_opt

    config = Config()
    pipeline = ReversePipeline(config)
    result = pipeline.analyze(binary)

    assert "obfuscation_optimization" in result
    info = result["obfuscation_optimization"]
    assert info["iterations"] == 2
    assert info["changes_applied"] == 10
    assert info["passes_run"] == ["junk_code_removal", "opaque_predicate_solving"]


