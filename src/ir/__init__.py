"""
Intermediate Representation (IR) framework for RE-Architect.

This package defines a two-level IR inspired by Valgrind's VEX and
Ghidra's P-Code models:

- Ground-Level IR: A low-level, architecture-agnostic representation that
  preserves the semantics of machine instructions using explicit, verbose
  operation names and explicit side effects.

- Sky-Level IR: A higher-level, language-like abstraction that captures
  control flow and data flow in constructs resembling C/C++ for improved
  readability and analysis while retaining links back to the ground level.

All IR component names intentionally use descriptive and verbose names
to enable self-documenting structures during debugging and analysis.
"""

from .ir_core import (
    # Core IR classes
    IntermediateRepresentationProgram,
    IntermediateRepresentationFunction,
    IntermediateRepresentationBasicBlock,
    GroundLevelInstruction,
    GroundLevelOperand,
    EnterpriseAbstractSyntaxTreeNode,
    EnterpriseFunctionAbstractSyntaxTree,
    # Enums and supporting classes
    IRIntegerSignedness,
    IRScalarElementType,
    IRVectorShape,
    IRRoundingMode,
    IRMemoryOrdering,
    IRAddressingForm,
    IRMemoryAddressExpression,
    IROperationCategory,
)

__all__ = [
    # Core IR classes
    "IntermediateRepresentationProgram",
    "IntermediateRepresentationFunction", 
    "IntermediateRepresentationBasicBlock",
    "GroundLevelInstruction",
    "GroundLevelOperand",
    "EnterpriseAbstractSyntaxTreeNode",
    "EnterpriseFunctionAbstractSyntaxTree",
    # Enums and supporting classes
    "IRIntegerSignedness",
    "IRScalarElementType", 
    "IRVectorShape",
    "IRRoundingMode",
    "IRMemoryOrdering",
    "IRAddressingForm",
    "IRMemoryAddressExpression",
    "IROperationCategory",
]


