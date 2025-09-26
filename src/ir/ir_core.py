"""
Core Intermediate Representation (IR) data structures.

This module defines the core classes for a two-level IR used by
the internal decompiler:

- Ground-Level IR captures semantics of machine instructions as explicit
  operations with fully named side-effects.

- Sky-Level IR constructs an abstract syntax tree (AST) with C/C++-like
  control and data structures while maintaining back-references to the
  underlying ground-level instructions for traceability.

All names are intentionally verbose and self-descriptive.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union


class IRIntegerSignedness(Enum):
    SIGNED = "signed"
    UNSIGNED = "unsigned"


class IRScalarElementType(Enum):
    INTEGER = "integer"
    FLOAT_IEEE754 = "float_ieee754"
    BIT = "bit"
    BCD = "bcd"


class IRVectorShape(Enum):
    SCALAR = "scalar"
    VECTOR = "vector"  # use element_count and element_width for shape


class IRRoundingMode(Enum):
    NEAREST_EVEN = "nearest_even"
    TOWARD_ZERO = "toward_zero"
    TOWARD_POSITIVE = "toward_positive"
    TOWARD_NEGATIVE = "toward_negative"
    CURRENT_ENVIRONMENT = "current_environment"


class IRMemoryOrdering(Enum):
    NONE = "none"
    ACQUIRE = "acquire"
    RELEASE = "release"
    ACQ_REL = "acq_rel"
    SEQ_CST = "seq_cst"


class IRAddressingForm(Enum):
    REGISTER_DIRECT = "register_direct"
    IMMEDIATE = "immediate"
    MEMORY_EFFECTIVE_ADDRESS = "memory_effective_address"  # base+index*scale+disp with optional segment


@dataclass
class IRMemoryAddressExpression:
    """Explicit x86 effective address structure with segment overrides."""
    segment_register_name: Optional[str]
    base_register_name: Optional[str]
    index_register_name: Optional[str]
    index_scale_factor: int
    displacement_value: int


@dataclass
class GroundLevelOperand:
    """A single operand in the ground-level IR with explicit type and value.

    This structure supports x86 addressing (segment overrides, SIB) and vector
    element typing to cover AVX/AVX-512 and x87 usages.
    """
    operand_role_name: str  # e.g., "source_register", "destination_memory"
    addressing_form: IRAddressingForm
    operand_value_representation: Union[str, int, IRMemoryAddressExpression]
    operand_bit_width: Optional[int] = None
    operand_integer_signedness: Optional[IRIntegerSignedness] = None
    scalar_element_type: Optional[IRScalarElementType] = None
    vector_shape: IRVectorShape = IRVectorShape.SCALAR
    vector_element_bit_width: Optional[int] = None
    vector_element_count: Optional[int] = None


class IROperationCategory(Enum):
    """High-level categories that cover the entire x86/x64 ISA surface."""
    ARITHMETIC_INTEGER = "arithmetic_integer"          # add, sub, adc, sbb, mul, imul, div, idiv, neg, inc, dec
    BIT_MANIPULATION = "bit_manipulation"              # and, or, xor, not, bt/bts/btr/btc, bsf, bsr, popcnt, pdep, pext, lzcnt, tzcnt
    SHIFT_ROTATE = "shift_rotate"                      # shl, shr, sal, sar, rol, ror, rcl, rcr, shld, shrd
    COMPARE_TEST = "compare_test"                      # cmp, test, cmpsx/mmx/sse compares, setcc, cmovcc
    CONTROL_FLOW = "control_flow"                      # jcc, jmp, call, ret, loop*, sysenter/sysexit, int/iret, xbegin/xend/xabort
    MEMORY_MOVE = "memory_move"                        # mov*, cmov*, xchg, xadd, movsx/movzx, lea, string ops (movs, cmps, stos, lods, scas)
    MEMORY_FENCE_CACHE = "memory_fence_cache"          # mfence, lfence, sfence, clflush*, wbinvd, invlpg
    FLAGS_MANAGEMENT = "flags_management"              # lahf, sahf, pushf, popf, stc, clc, cmc, std, cld
    SYSTEM = "system"                                  # cpuid, rdtsc, rdtscp, rdmsr, wrmsr, xgetbv, xsetbv, cli, sti, hlt
    CRYPTO = "crypto"                                  # AES*, PCLMULQDQ, SHA*
    SSE_AVX_SCALAR = "sse_avx_scalar"                  # scalar float ops
    SSE_AVX_VECTOR = "sse_avx_vector"                  # packed float/integer ops incl. AVX/AVX2/AVX-512 (blend, permute, shuffle)
    SSE_AVX_DATA_MOVEMENT = "sse_avx_data_movement"    # movd, movq, movaps, movups, vmovdqa*, broadcasts, masks, compress/expand
    SSE_AVX_CONVERSION = "sse_avx_conversion"          # cvt* conversions between types and sizes
    SSE_AVX_MISC = "sse_avx_misc"                      # testps, ptest, crc32, etc.
    X87_STACK_FLOATING = "x87_stack_floating"          # fld, fstp, fadd, fsub, fmul, fdiv, fcom*, fxch, finit, fsave/frstor
    ATOMIC_SYNCHRONIZATION = "atomic_synchronization"  # lock-prefixed operations, xchg-based atomics


@dataclass
class GroundLevelInstruction:
    """A ground-level IR instruction with explicit operation semantics covering x86/x64.

    Rather than enumerating every opcode, we provide a parameterized operation
    model with:
    - operation_semantic_name: verbose operation (e.g., "arithmetic_add_unsigned")
    - operation_category: category enum to simplify analysis
    - vector and floating metadata for AVX/AVX-512 and x87
    - flag effects and reads/writes sets
    - prefix semantics (lock, rep/repe/repne, segment override already in addressing)
    - memory ordering semantics for fences and atomics
    """
    originating_address: int
    operation_semantic_name: str
    operation_category: IROperationCategory
    operands: List[GroundLevelOperand] = field(default_factory=list)
    side_effect_descriptions: List[str] = field(default_factory=list)
    comment_explanations: List[str] = field(default_factory=list)

    # Vector and FP metadata (for SSE/AVX/AVX-512/x87)
    vector_shape: IRVectorShape = IRVectorShape.SCALAR
    vector_element_type: Optional[IRScalarElementType] = None
    vector_element_bit_width: Optional[int] = None
    vector_element_count: Optional[int] = None
    predicate_mask_register_name: Optional[str] = None  # e.g., k0-k7 for AVX-512
    predicate_mask_is_merging: Optional[bool] = None    # AVX-512 merging vs zeroing
    rounding_mode: Optional[IRRoundingMode] = None     # EVEX/legacy rounding control
    floating_exception_behavior: Optional[str] = None  # "suppress_all", "default", etc.

    # x87 stack oriented metadata
    x87_stack_effect_description: Optional[str] = None  # e.g., "push", "pop", "exchange_top", "no_change"

    # Flags and atomic semantics
    reads_flags: List[str] = field(default_factory=list)
    writes_flags: List[str] = field(default_factory=list)
    memory_ordering: IRMemoryOrdering = IRMemoryOrdering.NONE
    lock_prefix_applied: bool = False
    repeat_prefix: Optional[str] = None  # None | "rep" | "repe" | "repne"


@dataclass
class IntermediateRepresentationBasicBlock:
    """A basic block grouping ground-level instructions with explicit edges."""
    basic_block_start_address: int
    basic_block_end_address: int
    ground_level_instructions: List[GroundLevelInstruction] = field(default_factory=list)
    successor_block_addresses: List[int] = field(default_factory=list)
    predecessor_block_addresses: List[int] = field(default_factory=list)


@dataclass
class IntermediateRepresentationFunction:
    """A function containing basic blocks and optional sky-level AST."""
    function_start_address: int
    function_symbolic_name: str
    function_return_type_description: str = "unknown"
    function_parameter_descriptions: List[str] = field(default_factory=list)
    basic_blocks: List[IntermediateRepresentationBasicBlock] = field(default_factory=list)
    sky_level_function_ast: Optional["SkyLevelFunctionAbstractSyntaxTree"] = None


@dataclass
class IntermediateRepresentationProgram:
    """IR container for a complete program with function mapping."""
    functions_by_address: Dict[int, IntermediateRepresentationFunction] = field(default_factory=dict)
    program_strings_by_address: Dict[int, str] = field(default_factory=dict)
    program_types_by_name: Dict[str, str] = field(default_factory=dict)


# Sky-Level IR types

@dataclass
class SkyLevelAbstractSyntaxTreeNode:
    """A node in the sky-level AST representing a high-level construct.

    node_kind_name examples: "function_definition", "if_statement",
    "while_loop", "variable_declaration", "return_statement",
    "binary_expression", "call_expression".
    """
    node_kind_name: str
    node_properties: Dict[str, Any] = field(default_factory=dict)
    child_nodes: List["SkyLevelAbstractSyntaxTreeNode"] = field(default_factory=list)
    source_ground_level_addresses: List[int] = field(default_factory=list)


@dataclass
class SkyLevelFunctionAbstractSyntaxTree:
    """A sky-level AST for a function, similar to a simplified C/C++ AST."""
    function_name: str
    return_type_description: str
    parameter_descriptions: List[str]
    root_node: SkyLevelAbstractSyntaxTreeNode


