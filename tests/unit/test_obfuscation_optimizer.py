import tempfile
from pathlib import Path
from unittest.mock import patch, Mock

from src.optimization.optimizer import ObfuscationOptimizer, OptimizationReport


def test_optimizer_availability():
    opt = ObfuscationOptimizer()
    assert isinstance(opt.is_available(), bool)


@patch('src.optimization.optimizer.angr')
def test_optimizer_runs_iterations(mock_angr):
    # Mock angr project, cfg, state
    mock_project = Mock()
    mock_cfg = Mock()
    mock_cfg.graph.nodes.return_value = []
    mock_project.analyses.CFGFast.return_value = mock_cfg
    mock_state = Mock()
    mock_project.factory.entry_state.return_value = mock_state
    mock_angr.Project.return_value = mock_project

    opt = ObfuscationOptimizer(max_iterations=3)
    report = opt.optimize(Path('dummy'))

    assert isinstance(report, OptimizationReport)
    assert report.iterations >= 1
    assert isinstance(report.changes_applied, int)
    assert isinstance(report.passes_run, list)


@patch('src.optimization.optimizer.angr')
def test_optimizer_converges(mock_angr):
    # Configure passes to produce zero changes (graph has no nodes)
    mock_project = Mock()
    mock_cfg = Mock()
    mock_cfg.graph.nodes.return_value = []
    mock_project.analyses.CFGFast.return_value = mock_cfg
    mock_state = Mock()
    mock_project.factory.entry_state.return_value = mock_state
    mock_angr.Project.return_value = mock_project

    opt = ObfuscationOptimizer(max_iterations=5)
    report = opt.optimize(Path('dummy'))
    assert report.iterations == 1


