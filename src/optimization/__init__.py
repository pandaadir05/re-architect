"""
Obfuscation optimization subsystem.

Provides iterative passes to clean junk code, resolve opaque predicates,
reduce mixed boolean arithmetic, and detect VM-based virtualization handlers.

Backed by Angr for symbolic reasoning and CFG reconstruction.
"""

from .optimizer import ObfuscationOptimizer, OptimizationReport

__all__ = ["ObfuscationOptimizer", "OptimizationReport"]


