"""
Unpacking module for RE-Architect.

This module handles unpacking of packed binaries using symbolic execution
with Angr. It can detect common packers and automatically unpack binaries
to enable static analysis.
"""

from .symbolic_unpacker import SymbolicUnpacker, UnpackingResult

__all__ = ["SymbolicUnpacker", "UnpackingResult"]
