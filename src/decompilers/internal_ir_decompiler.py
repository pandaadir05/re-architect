"""
Internal IR Decompiler for RE-Architect.

This decompiler produces a two-level Intermediate Representation (IR):

1) Ground-Level IR: a low-level, architecture-agnostic encoding of machine
   instruction semantics with explicit, verbose operation names and explicit
   side effects.

2) Sky-Level IR: a higher-level abstraction rendering control flow and data
   flow in structures resembling C/C++ (function definitions, statements,
   expressions), while preserving traceability to the ground level.

The design takes inspiration from Valgrind's VEX and Ghidra's P-Code. All
IR names are deliberately verbose and self-describing.
"""

import logging
from typing import Dict, Optional, List

from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode
from src.ir import (
    IntermediateRepresentationProgram,
    IntermediateRepresentationFunction,
    IntermediateRepresentationBasicBlock,
    GroundLevelInstruction,
    GroundLevelOperand,
    IRAddressingForm,
    IRIntegerSignedness,
    IRScalarElementType,
    IRVectorShape,
    IRRoundingMode,
    IRMemoryOrdering,
    IRMemoryAddressExpression,
    IROperationCategory,
    SkyLevelAbstractSyntaxTreeNode,
    SkyLevelFunctionAbstractSyntaxTree,
)

logger = logging.getLogger("re-architect.decompilers.internal_ir")


class InternalIRDecompiler(BaseDecompiler):
    """Decompiler that emits the custom two-level IR and a C-like rendering."""

    def __init__(self):
        super().__init__()
        self.name = "InternalIRDecompiler"

    def is_available(self) -> bool:
        # Always available as it is internal
        return True

    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        """Decompile the binary into IR, and also produce a C-like rendering per function.

        The return type is still DecompiledCode for compatibility with the
        existing pipeline. We store the IR in special fields on the instance
        for downstream components that are IR-aware.
        """
        logger.info(f"Decompiling {binary_info.path} using Internal IR decompiler")

        # Construct IR program container and lift using Capstone if available
        ir_program = self._lift_program(binary_info)

        # Bridge to existing interface: create DecompiledCode where function bodies
        # are the "sky-level" C-like renderings. We will also attach the IR to
        # the object for IR-aware consumers.
        decompiled = DecompiledCode(binary_info)
        for addr, ir_func in ir_program.functions_by_address.items():
            c_like = self._render_sky_level_function_as_c(ir_func)
            metadata = {
                "ir_available": True,
                "ground_instruction_count": sum(len(bb.ground_level_instructions) for bb in ir_func.basic_blocks),
                "sky_ast": True,
            }
            decompiled.add_function(addr, c_like, ir_func.function_symbolic_name, metadata)

        # Attach IR program so that other components can access it
        setattr(decompiled, "internal_ir_program", ir_program)
        return decompiled

    def _render_sky_level_function_as_c(self, ir_func: IntermediateRepresentationFunction) -> str:
        """Render a minimal C-like representation from the sky-level AST.

        This renderer is intentionally simple and conservative; it ensures
        human-readable output even if the sky-level AST is rudimentary.
        """
        ret_type = ir_func.function_return_type_description or "int"
        name = ir_func.function_symbolic_name
        params = ", ".join(ir_func.function_parameter_descriptions) if ir_func.function_parameter_descriptions else "void"
        body_lines = ["// Auto-generated C-like representation from Sky-Level IR"]

        ast = ir_func.sky_level_function_ast
        if ast and ast.root_node:
            for node in ast.root_node.child_nodes:
                if node.node_kind_name == "return_statement":
                    expr = node.node_properties.get("return_expression", 0)
                    body_lines.append(f"return {expr};")
        else:
            body_lines.append("// No AST available; returning 0 as placeholder")
            body_lines.append("return 0;")

        body = "\n    ".join(body_lines)
        return f"{ret_type} {name}({params})\n{{\n    {body}\n}}\n"

    def get_decompiler_info(self) -> Dict:
        return {
            "name": self.name,
            "available": True,
            "version": "0.1-internal-ir",
            "ir_levels": ["ground", "sky"],
        }

    # --- Lifting implementation ---
    def _lift_program(self, binary_info: BinaryInfo) -> IntermediateRepresentationProgram:
        """Lift binary code into IR. Currently focuses on entry point function.

        This implementation uses Capstone to disassemble a bounded number of
        instructions from the entry point, translates each instruction into our
        ground-level IR, and builds a single basic block for a proof of concept.
        """
        ir_program = IntermediateRepresentationProgram()
        if not binary_info.entry_point:
            return ir_program
        try:
            import capstone
        except ImportError:
            # Fallback: synthesize a trivial function if disassembly is unavailable
            func_addr = binary_info.entry_point
            function_name = f"function_at_0x{func_addr:x}"
            basic_block = IntermediateRepresentationBasicBlock(
                basic_block_start_address=func_addr,
                basic_block_end_address=func_addr,
                ground_level_instructions=[
                    GroundLevelInstruction(
                        originating_address=func_addr,
                        operation_semantic_name="control_flow_return",
                        operation_category=IROperationCategory.CONTROL_FLOW,
                    )
                ],
            )
            ir_function = IntermediateRepresentationFunction(
                function_start_address=func_addr,
                function_symbolic_name=function_name,
                function_return_type_description="int",
                function_parameter_descriptions=[],
                basic_blocks=[basic_block],
            )
            ir_function.sky_level_function_ast = self._build_minimal_sky_ast(function_name, 0, [func_addr])
            ir_program.functions_by_address[func_addr] = ir_function
            return ir_program

        # Setup Capstone for the architecture
        md = self._create_capstone(binary_info)
        if md is None:
            return ir_program

        # Read binary bytes
        try:
            with open(binary_info.path, 'rb') as f:
                binary_bytes = f.read()
        except Exception:
            return ir_program

        # Compute section containing entry point if possible
        entry = binary_info.entry_point
        section_bytes, section_base = self._get_section_bytes_containing_address(binary_bytes, binary_info, entry)
        if section_bytes is None:
            return ir_program

        # Disassemble a limited window from the entry point
        max_instructions = 256
        ir_instructions: List[GroundLevelInstruction] = []
        end_address = entry
        try:
            for insn in md.disasm(section_bytes[entry - section_base:], entry, count=max_instructions):
                ir_instr = self._translate_insn_to_ir(md, insn)
                ir_instructions.append(ir_instr)
                end_address = insn.address
                # Stop at RET to keep it simple for PoC
                if insn.mnemonic.lower().startswith('ret'):
                    break
        except Exception as e:
            logger.debug(f"Disassembly error during IR lift: {e}")

        # Build function and basic block
        function_name = f"function_at_0x{entry:x}"
        basic_block = IntermediateRepresentationBasicBlock(
            basic_block_start_address=entry,
            basic_block_end_address=end_address,
            ground_level_instructions=ir_instructions,
        )
        ir_function = IntermediateRepresentationFunction(
            function_start_address=entry,
            function_symbolic_name=function_name,
            function_return_type_description="int",
            function_parameter_descriptions=[],
            basic_blocks=[basic_block],
        )

        # Build naïve sky-level AST (recognize simple "return 0" pattern)
        return_value = 0
        return_addresses = [i.originating_address for i in ir_instructions[-1:]] if ir_instructions else [entry]
        ir_function.sky_level_function_ast = self._build_minimal_sky_ast(function_name, return_value, return_addresses)

        ir_program.functions_by_address[entry] = ir_function
        return ir_program

    def _create_capstone(self, binary_info: BinaryInfo):
        try:
            import capstone
        except ImportError:
            return None
        arch = getattr(binary_info.architecture, 'value', str(binary_info.architecture)).lower()
        try:
            if arch == 'x86_64' or arch == 'x86-64':
                return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif arch == 'x86':
                return capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif arch == 'arm64':
                return capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            elif arch == 'arm':
                return capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            else:
                return None
        except Exception:
            return None

    def _get_section_bytes_containing_address(self, binary_bytes: bytes, binary_info: BinaryInfo, address: int):
        for _name, info in binary_info.sections.items():
            vaddr = info.get('virtual_address', 0)
            size = info.get('size', 0)
            offset = info.get('offset', 0)
            if vaddr <= address < vaddr + size and offset + size <= len(binary_bytes):
                return binary_bytes[offset:offset + size], vaddr
        return None, 0

    def _build_minimal_sky_ast(self, function_name: str, return_value: int, source_addrs: List[int]) -> SkyLevelFunctionAbstractSyntaxTree:
        return_stmt = SkyLevelAbstractSyntaxTreeNode(
            node_kind_name="return_statement",
            node_properties={"return_expression": return_value},
            source_ground_level_addresses=source_addrs,
        )
        root = SkyLevelAbstractSyntaxTreeNode(
            node_kind_name="function_definition",
            node_properties={},
            child_nodes=[return_stmt],
            source_ground_level_addresses=source_addrs,
        )
        return SkyLevelFunctionAbstractSyntaxTree(
            function_name=function_name,
            return_type_description="int",
            parameter_descriptions=[],
            root_node=root,
        )

    def _translate_insn_to_ir(self, md, insn) -> GroundLevelInstruction:
        """Translate a Capstone instruction to GroundLevelInstruction.

        This covers x86/x64 including vector and x87 mnemonics at a category level.
        """
        mnem = insn.mnemonic.lower()
        opcat, sem_name = self._map_mnemonic_to_category_and_semantics(mnem)

        # Prefixes
        lock = False
        repeat = None
        try:
            # Capstone exposes x86 prefixes as a list of ints
            if getattr(insn, 'prefix', None):
                pf = [p for p in insn.prefix if p]
                if 0xF0 in pf:
                    lock = True
                if 0xF3 in pf:
                    repeat = 'repe'
                if 0xF2 in pf:
                    repeat = 'repne'
        except Exception:
            pass

        # Operands
        operands: List[GroundLevelOperand] = []
        try:
            x86 = insn.operands
            for idx, op in enumerate(x86):
                role = self._infer_operand_role(mnem, idx)
                if op.type == md.x86.OP_REG:
                    reg_name = md.reg_name(op.reg)
                    operands.append(GroundLevelOperand(
                        operand_role_name=role,
                        addressing_form=IRAddressingForm.REGISTER_DIRECT,
                        operand_value_representation=reg_name,
                    ))
                elif op.type == md.x86.OP_IMM:
                    operands.append(GroundLevelOperand(
                        operand_role_name=role,
                        addressing_form=IRAddressingForm.IMMEDIATE,
                        operand_value_representation=int(op.imm),
                    ))
                elif op.type == md.x86.OP_MEM:
                    mem = op.mem
                    addr_expr = IRMemoryAddressExpression(
                        segment_register_name=(md.reg_name(mem.segment) if mem.segment != 0 else None),
                        base_register_name=(md.reg_name(mem.base) if mem.base != 0 else None),
                        index_register_name=(md.reg_name(mem.index) if mem.index != 0 else None),
                        index_scale_factor=int(mem.scale) if getattr(mem, 'scale', 0) else 0,
                        displacement_value=int(mem.disp) if getattr(mem, 'disp', 0) else 0,
                    )
                    operands.append(GroundLevelOperand(
                        operand_role_name=role,
                        addressing_form=IRAddressingForm.MEMORY_EFFECTIVE_ADDRESS,
                        operand_value_representation=addr_expr,
                    ))
        except Exception:
            pass

        # Vector hints based on register names
        vec_shape = IRVectorShape.SCALAR
        vec_etype = None
        vec_ebits = None
        vec_ecount = None
        if any(isinstance(o.operand_value_representation, str) and o.operand_value_representation.startswith(('xmm', 'ymm', 'zmm')) for o in operands):
            vec_shape = IRVectorShape.VECTOR
            # Heuristic: assume 32-bit float elements for *ps, 64-bit for *pd, else integer 32
            if mnem.endswith('ps'):
                vec_etype = IRScalarElementType.FLOAT_IEEE754
                vec_ebits = 32
            elif mnem.endswith('pd'):
                vec_etype = IRScalarElementType.FLOAT_IEEE754
                vec_ebits = 64
            else:
                vec_etype = IRScalarElementType.INTEGER
                vec_ebits = 32

        instr = GroundLevelInstruction(
            originating_address=insn.address,
            operation_semantic_name=sem_name,
            operation_category=opcat,
            operands=operands,
            vector_shape=vec_shape,
            vector_element_type=vec_etype,
            vector_element_bit_width=vec_ebits,
            vector_element_count=vec_ecount,
            lock_prefix_applied=lock,
            repeat_prefix=repeat,
        )

        # Flags effects (heuristic for common ALU ops)
        if opcat == IROperationCategory.ARITHMETIC_INTEGER or opcat == IROperationCategory.COMPARE_TEST:
            instr.writes_flags = ["CF", "ZF", "SF", "OF", "AF", "PF"]

        # Memory ordering fences
        if mnem in ("mfence", "sfence", "lfence"):
            instr.memory_ordering = IRMemoryOrdering.SEQ_CST if mnem == 'mfence' else (
                IRMemoryOrdering.RELEASE if mnem == 'sfence' else IRMemoryOrdering.ACQUIRE
            )

        # x87 stack effect hints
        if mnem.startswith('f') and any(isinstance(o.operand_value_representation, str) and o.operand_value_representation.startswith('st') for o in operands):
            instr.operation_category = IROperationCategory.X87_STACK_FLOATING
            if mnem.startswith('fld'):
                instr.x87_stack_effect_description = 'push'
            elif mnem.startswith('fstp'):
                instr.x87_stack_effect_description = 'pop'
            elif mnem.startswith('fxch'):
                instr.x87_stack_effect_description = 'exchange_top'

        return instr

    def _map_mnemonic_to_category_and_semantics(self, mnem: str):
        # Common integer arithmetic
        if mnem in ("add", "adc"):
            return IROperationCategory.ARITHMETIC_INTEGER, "arithmetic_add_unsigned"
        if mnem in ("sub", "sbb"):
            return IROperationCategory.ARITHMETIC_INTEGER, "arithmetic_subtract_unsigned"
        if mnem in ("mul", "imul"):
            return IROperationCategory.ARITHMETIC_INTEGER, "arithmetic_multiply"
        if mnem in ("div", "idiv"):
            return IROperationCategory.ARITHMETIC_INTEGER, "arithmetic_divide"
        if mnem in ("inc",):
            return IROperationCategory.ARITHMETIC_INTEGER, "arithmetic_increment"
        if mnem in ("dec",):
            return IROperationCategory.ARITHMETIC_INTEGER, "arithmetic_decrement"

        # Bitwise, shifts, rotates
        if mnem in ("and", "or", "xor", "not"):
            return IROperationCategory.BIT_MANIPULATION, f"bitwise_{mnem}"
        if mnem in ("shl", "sal"):
            return IROperationCategory.SHIFT_ROTATE, "shift_left_arithmetic"
        if mnem == "shr":
            return IROperationCategory.SHIFT_ROTATE, "shift_right_logical"
        if mnem == "sar":
            return IROperationCategory.SHIFT_ROTATE, "shift_right_arithmetic"
        if mnem in ("rol", "ror", "rcl", "rcr"):
            return IROperationCategory.SHIFT_ROTATE, f"rotate_{mnem}"

        # Compare/test
        if mnem == "cmp":
            return IROperationCategory.COMPARE_TEST, "compare_subtract_sets_flags"
        if mnem == "test":
            return IROperationCategory.COMPARE_TEST, "compare_test_and_sets_flags"

        # Control flow
        if mnem.startswith('j'):
            return IROperationCategory.CONTROL_FLOW, ("control_flow_branch_conditional" if mnem != 'jmp' else "control_flow_jump_unconditional")
        if mnem == "jmp":
            return IROperationCategory.CONTROL_FLOW, "control_flow_jump_unconditional"
        if mnem == "call":
            return IROperationCategory.CONTROL_FLOW, "control_flow_call"
        if mnem.startswith("ret"):
            return IROperationCategory.CONTROL_FLOW, "control_flow_return"

        # Moves and LEA
        if mnem.startswith('mov'):
            return IROperationCategory.MEMORY_MOVE, "memory_move_transfer"
        if mnem == 'lea':
            return IROperationCategory.MEMORY_MOVE, "address_calculation_lea"

        # Fences
        if mnem in ("mfence", "sfence", "lfence"):
            return IROperationCategory.MEMORY_FENCE_CACHE, f"memory_{mnem}"

        # SSE/AVX: heuristic based on leading 'v' or xmm/ymm/zmm usage
        if mnem.startswith('v'):
            if mnem.startswith('vmov'):
                return IROperationCategory.SSE_AVX_DATA_MOVEMENT, "vector_data_move"
            if any(s in mnem for s in ("add", "sub", "mul", "div", "and", "or", "xor")):
                return IROperationCategory.SSE_AVX_VECTOR, "vector_arithmetic_operation"
            return IROperationCategory.SSE_AVX_MISC, "vector_misc_operation"

        if mnem.startswith('f'):
            return IROperationCategory.X87_STACK_FLOATING, "x87_floating_operation"

        # Default catch-all
        return IROperationCategory.SYSTEM, f"system_or_unclassified_{mnem}"

    def _infer_operand_role(self, mnem: str, index: int) -> str:
        # Simple heuristic: many x86 ops are dest, src1, src2 order
        if index == 0:
            return "destination_operand"
        elif index == 1:
            return "source_operand_primary"
        else:
            return f"source_operand_{index}"


