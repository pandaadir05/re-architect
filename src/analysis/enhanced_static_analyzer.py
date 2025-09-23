"""
Enhanced static analyzer module for RE-Architect.

This module performs static analysis on binary data using Capstone disassembler
to extract function information, control flow, and dependencies.
"""

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from pathlib import Path

try:
    import capstone
    CAPSTONE_AVAILABLE = True
except ImportError:
    CAPSTONE_AVAILABLE = False

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

from src.core.config import Config
from src.core.binary_loader import BinaryInfo, BinaryFormat
from src.core.binary_loader import Architecture  # Import separately to avoid issues
from src.decompilers.base_decompiler import DecompiledCode

logger = logging.getLogger("re-architect.analysis.static")

@dataclass
class Instruction:
    """Represents a disassembled instruction."""
    address: int
    mnemonic: str
    op_str: str
    size: int
    bytes: bytes
    is_call: bool = False
    is_jump: bool = False
    is_return: bool = False
    target_address: Optional[int] = None

@dataclass 
class BasicBlock:
    """Represents a basic block in the control flow."""
    start_address: int
    end_address: int
    instructions: List[Instruction] = field(default_factory=list)
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)
    
    @property
    def size(self) -> int:
        """Get the size of this basic block."""
        return len(self.instructions)

@dataclass
class FunctionInfo:
    """Information about a function extracted from static analysis."""
    address: int
    name: str
    size: int
    instructions: List[Instruction] = field(default_factory=list)
    basic_blocks: List[BasicBlock] = field(default_factory=list)
    calls: List[int] = field(default_factory=list)  # Addresses of functions called
    called_by: List[int] = field(default_factory=list)  # Addresses of functions that call this
    parameters: List[str] = field(default_factory=list)
    return_type: str = "unknown"
    complexity: float = 0.0
    is_library: bool = False
    has_loops: bool = False
    has_switch: bool = False
    entry_point: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "address": self.address,
            "name": self.name,
            "size": self.size,
            "instruction_count": len(self.instructions),
            "basic_block_count": len(self.basic_blocks),
            "calls": self.calls,
            "called_by": self.called_by,
            "parameters": self.parameters,
            "return_type": self.return_type,
            "complexity": self.complexity,
            "is_library": self.is_library,
            "has_loops": self.has_loops,
            "has_switch": self.has_switch,
            "entry_point": self.entry_point
        }

@dataclass
class StaticAnalysisResults:
    """Results from static analysis of binary code."""
    functions: Dict[int, FunctionInfo]
    call_graph: Dict[int, Set[int]]
    reverse_call_graph: Dict[int, Set[int]]
    strings: List[Tuple[int, str]] = field(default_factory=list)
    
    @property
    def function_count(self) -> int:
        """Get the number of analyzed functions."""
        return len(self.functions)

class EnhancedStaticAnalyzer:
    """
    Enhanced static analyzer for RE-Architect.
    
    This class performs static analysis on binary data using Capstone disassembler
    to extract function information, detect patterns, and build a call graph.
    """
    
    def __init__(self, config: Config):
        """
        Initialize the static analyzer.
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.depth = self.config.get("analysis.static.function_analysis_depth", "medium")
        
        if not CAPSTONE_AVAILABLE:
            logger.warning("Capstone not available. Static analysis will be limited.")
        
        self._disassembler = None
        self._architecture = None
        self._mode = None
    
    def analyze(self, decompiled_code: DecompiledCode) -> StaticAnalysisResults:
        """
        Analyze decompiled code (legacy interface for compatibility).
        
        Args:
            decompiled_code: Decompiled code to analyze
            
        Returns:
            StaticAnalysisResults object containing analysis results
        """
        logger.info("Using legacy static analysis (no binary data)")
        
        # Create empty results for compatibility
        return StaticAnalysisResults(
            functions={},
            call_graph={},
            reverse_call_graph={}
        )
    
    def analyze_binary(self, binary_info: BinaryInfo) -> StaticAnalysisResults:
        """
        Analyze binary data using Capstone disassembler.
        
        Args:
            binary_info: Binary information from BinaryLoader
            
        Returns:
            StaticAnalysisResults object containing analysis results
        """
        logger.info(f"Starting enhanced static analysis of {binary_info.path}")
        
        if not CAPSTONE_AVAILABLE:
            logger.error("Capstone not available for static analysis")
            return StaticAnalysisResults(functions={}, call_graph={}, reverse_call_graph={})
        
        # Initialize disassembler for this architecture
        self._setup_disassembler(binary_info.architecture, binary_info.bit_width)
        
        if not self._disassembler:
            logger.error("Failed to initialize disassembler")
            return StaticAnalysisResults(functions={}, call_graph={}, reverse_call_graph={})
        
        # Read binary data
        binary_data = self._read_binary_data(binary_info.path)
        if not binary_data:
            return StaticAnalysisResults(functions={}, call_graph={}, reverse_call_graph={})
        
        # Find executable sections
        executable_sections = self._find_executable_sections(binary_info)
        
        # Extract strings
        strings = self._extract_strings(binary_data)
        
        # Analyze functions
        functions = {}
        
        # Start with known symbols (functions)
        function_addresses = self._get_function_addresses(binary_info)
        
        # If no symbols, try to identify functions heuristically
        if not function_addresses:
            function_addresses = self._identify_functions_heuristic(binary_data, executable_sections)
        
        # Analyze each function
        for addr in function_addresses:
            try:
                func_info = self._analyze_function(binary_data, addr, binary_info)
                if func_info:
                    functions[addr] = func_info
            except Exception as e:
                logger.warning(f"Failed to analyze function at 0x{addr:08x}: {e}")
        
        # Build call graphs
        call_graph, reverse_call_graph = self._build_call_graphs(functions)
        
        logger.info(f"Static analysis completed: {len(functions)} functions analyzed")
        
        return StaticAnalysisResults(
            functions=functions,
            call_graph=call_graph,
            reverse_call_graph=reverse_call_graph,
            strings=strings
        )
    
    def _setup_disassembler(self, architecture: Architecture, bit_width: int):
        """Setup Capstone disassembler for the given architecture."""
        try:
            logger.info(f"Setting up disassembler for {architecture} ({bit_width}-bit)")
            
            # Compare by value to avoid enum identity issues
            if architecture.value == "x86":
                logger.info("Detected X86 architecture - setting up 32-bit mode")
                if bit_width == 64:
                    self._disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
                else:
                    self._disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            elif architecture.value == "x86_64":
                logger.info("Detected X86_64 architecture - setting up 64-bit mode")
                self._disassembler = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            elif architecture.value == "arm":
                logger.info("Detected ARM architecture")
                self._disassembler = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
            elif architecture.value == "arm64":
                logger.info("Detected ARM64 architecture")
                self._disassembler = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
            else:
                logger.warning(f"Unsupported architecture for disassembly: {architecture}")
                return
            
            # Enable detailed instruction information
            self._disassembler.detail = True
            self._architecture = architecture
            logger.info(f"Disassembler setup successful for {architecture}")
            
        except Exception as e:
            logger.error(f"Failed to setup disassembler: {e}")
            import traceback
            logger.error(traceback.format_exc())
            self._disassembler = None
    
    def _read_binary_data(self, binary_path: Path) -> Optional[bytes]:
        """Read binary file data."""
        try:
            with open(binary_path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Failed to read binary data: {e}")
            return None
    
    def _find_executable_sections(self, binary_info: BinaryInfo) -> List[Tuple[int, int, bytes]]:
        """Find executable sections in the binary."""
        executable_sections = []
        
        # Look for executable sections
        for section_name, section_info in binary_info.sections.items():
            # Common executable section names
            if (section_name.startswith('.text') or 
                section_name.startswith('.code') or
                'exec' in section_name.lower()):
                
                addr = section_info.get('virtual_address', 0)
                size = section_info.get('size', 0)
                offset = section_info.get('offset', 0)
                
                if addr > 0 and size > 0:
                    executable_sections.append((addr, size, offset))
        
        return executable_sections
    
    def _extract_strings(self, binary_data: bytes) -> List[Tuple[int, str]]:
        """Extract strings from binary data."""
        strings = []
        
        # Simple string extraction (printable ASCII strings >= 4 chars)
        current_string = ""
        start_offset = 0
        
        for i, byte in enumerate(binary_data):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current_string:
                    start_offset = i
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:
                    strings.append((start_offset, current_string))
                current_string = ""
        
        # Don't forget the last string
        if len(current_string) >= 4:
            strings.append((start_offset, current_string))
        
        return strings
    
    def _get_function_addresses(self, binary_info: BinaryInfo) -> List[int]:
        """Get function addresses from symbols."""
        function_addresses = []
        
        for symbol_name, symbol_info in binary_info.symbols.items():
            # Look for function symbols
            if (symbol_info.get('type') in ['static', 'dynamic'] and
                not symbol_name.startswith('.') and
                symbol_info.get('value', 0) > 0):
                function_addresses.append(symbol_info['value'])
        
        # Add entry point if available
        if binary_info.entry_point > 0:
            function_addresses.append(binary_info.entry_point)
        
        return sorted(set(function_addresses))
    
    def _identify_functions_heuristic(self, binary_data: bytes, executable_sections: List[Tuple[int, int, int]]) -> List[int]:
        """Identify function start addresses using heuristics."""
        function_addresses = []
        
        # This is a simplified heuristic - in practice, this would be much more sophisticated
        # Look for common function prologue patterns
        
        if (self._architecture and 
            (self._architecture.value == "x86" or self._architecture.value == "x86_64")):
            # Common x86/x64 function prologues
            prologues = [
                b'\x55\x8b\xec',        # push ebp; mov ebp, esp
                b'\x55\x48\x89\xe5',    # push rbp; mov rbp, rsp (x64)
                b'\x48\x83\xec',        # sub rsp, imm (x64)
                b'\x83\xec',            # sub esp, imm (x86)
            ]
            
            for addr, size, offset in executable_sections:
                if offset + size > len(binary_data):
                    continue
                
                section_data = binary_data[offset:offset + size]
                for i in range(len(section_data) - 8):
                    for prologue in prologues:
                        if section_data[i:i + len(prologue)] == prologue:
                            function_addresses.append(addr + i)
        
        return sorted(set(function_addresses))
    
    def _analyze_function(self, binary_data: bytes, address: int, binary_info: BinaryInfo) -> Optional[FunctionInfo]:
        """Analyze a single function starting at the given address."""
        
        # Find the section containing this address
        section_data, section_offset = self._get_section_data(binary_data, address, binary_info)
        if not section_data:
            return None
        
        # Calculate offset within section
        data_offset = address - section_offset
        if data_offset < 0 or data_offset >= len(section_data):
            return None
        
        # Disassemble instructions
        instructions = []
        max_instructions = 1000  # Prevent infinite loops
        current_offset = data_offset
        
        try:
            for insn in self._disassembler.disasm(section_data[data_offset:], address, max_instructions):
                instruction = Instruction(
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    size=insn.size,
                    bytes=insn.bytes,
                    is_call='call' in insn.mnemonic.lower(),
                    is_jump=insn.group(capstone.CS_GRP_JUMP) if hasattr(insn, 'group') else False,
                    is_return=insn.group(capstone.CS_GRP_RET) if hasattr(insn, 'group') else 'ret' in insn.mnemonic.lower()
                )
                
                instructions.append(instruction)
                
                # Stop at return instruction (simple heuristic)
                if instruction.is_return:
                    break
                
                # Stop if we hit another known function start (simple heuristic)
                if len(instructions) > 1 and insn.address in binary_info.symbols:
                    break
        
        except Exception as e:
            logger.warning(f"Disassembly failed for function at 0x{address:08x}: {e}")
            return None
        
        if not instructions:
            return None
        
        # Find function name
        func_name = f"func_{address:08x}"
        for symbol_name, symbol_info in binary_info.symbols.items():
            if symbol_info.get('value') == address:
                func_name = symbol_name
                break
        
        # Calculate function size
        func_size = instructions[-1].address - address + instructions[-1].size
        
        # Extract function calls
        calls = []
        for insn in instructions:
            if insn.is_call and insn.target_address:
                calls.append(insn.target_address)
        
        # Create basic blocks (simplified)
        basic_blocks = self._create_basic_blocks(instructions)
        
        # Calculate complexity (simplified McCabe complexity)
        complexity = self._calculate_complexity(instructions, basic_blocks)
        
        # Detect loops and switches (simplified)
        has_loops = self._detect_loops(instructions)
        has_switch = self._detect_switch(instructions)
        
        return FunctionInfo(
            address=address,
            name=func_name,
            size=func_size,
            instructions=instructions,
            basic_blocks=basic_blocks,
            calls=calls,
            complexity=complexity,
            has_loops=has_loops,
            has_switch=has_switch,
            entry_point=(address == binary_info.entry_point)
        )
    
    def _get_section_data(self, binary_data: bytes, address: int, binary_info: BinaryInfo) -> Tuple[Optional[bytes], int]:
        """Get section data containing the given address."""
        for section_name, section_info in binary_info.sections.items():
            vaddr = section_info.get('virtual_address', 0)
            size = section_info.get('size', 0)
            offset = section_info.get('offset', 0)
            
            if vaddr <= address < vaddr + size:
                # Found the section
                if offset + size > len(binary_data):
                    return None, 0
                return binary_data[offset:offset + size], vaddr
        
        return None, 0
    
    def _create_basic_blocks(self, instructions: List[Instruction]) -> List[BasicBlock]:
        """Create basic blocks from instructions (simplified)."""
        if not instructions:
            return []
        
        # For now, create one basic block per function (simplified)
        # In a full implementation, this would properly split on jumps/calls
        block = BasicBlock(
            start_address=instructions[0].address,
            end_address=instructions[-1].address,
            instructions=instructions
        )
        
        return [block]
    
    def _calculate_complexity(self, instructions: List[Instruction], basic_blocks: List[BasicBlock]) -> float:
        """Calculate cyclomatic complexity (simplified)."""
        # Simplified: count decision points (jumps, calls)
        decision_points = sum(1 for insn in instructions if insn.is_jump or insn.is_call)
        return float(decision_points + 1)
    
    def _detect_loops(self, instructions: List[Instruction]) -> bool:
        """Detect if function contains loops (simplified)."""
        # Look for backward jumps (simplified heuristic)
        for insn in instructions:
            if insn.is_jump and insn.target_address and insn.target_address < insn.address:
                return True
        return False
    
    def _detect_switch(self, instructions: List[Instruction]) -> bool:
        """Detect if function contains switch statements (simplified)."""
        # Look for jump tables or multiple jumps (simplified heuristic)
        jump_count = sum(1 for insn in instructions if insn.is_jump)
        return jump_count > 3
    
    def _build_call_graphs(self, functions: Dict[int, FunctionInfo]) -> Tuple[Dict[int, Set[int]], Dict[int, Set[int]]]:
        """Build call graph and reverse call graph."""
        call_graph = {}
        reverse_call_graph = {}
        
        for addr, func_info in functions.items():
            call_graph[addr] = set(func_info.calls)
            
            # Build reverse call graph
            for called_addr in func_info.calls:
                if called_addr not in reverse_call_graph:
                    reverse_call_graph[called_addr] = set()
                reverse_call_graph[called_addr].add(addr)
        
        return call_graph, reverse_call_graph


# Alias for backwards compatibility
StaticAnalyzer = EnhancedStaticAnalyzer