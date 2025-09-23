"""
Binary loader module for RE-Architect.

This module handles loading and initial analysis of binary files.
"""

import logging
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple, Union

try:
    import lief
    LIEF_AVAILABLE = True
except ImportError:
    LIEF_AVAILABLE = False

logger = logging.getLogger("re-architect.binary_loader")

class Architecture(Enum):
    """Supported binary architectures."""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    PPC = "powerpc"
    PPC64 = "powerpc64"
    UNKNOWN = "unknown"

class BinaryFormat(Enum):
    """Supported binary file formats."""
    ELF = "elf"
    PE = "pe"
    MACHO = "macho"
    RAW = "raw"
    UNKNOWN = "unknown"

class CompilerType(Enum):
    """Detected compiler types."""
    GCC = "gcc"
    CLANG = "clang"
    MSVC = "msvc"
    GO = "go"
    RUST = "rust"
    UNKNOWN = "unknown"

@dataclass
class BinaryInfo:
    """Information about a loaded binary file."""
    path: Path
    format: BinaryFormat
    architecture: Architecture
    bit_width: int
    endianness: str  # "little" or "big"
    entry_point: int
    sections: Dict[str, Dict]
    symbols: Dict[str, Dict]
    compiler: CompilerType
    stripped: bool
    is_library: bool
    imports: Dict[str, List[str]]
    exports: List[str]
    
    def __str__(self) -> str:
        """String representation of binary information."""
        return (
            f"BinaryInfo(path={self.path}, "
            f"format={self.format.value}, "
            f"architecture={self.architecture.value}, "
            f"bit_width={self.bit_width}, "
            f"endianness={self.endianness}, "
            f"compiler={self.compiler.value}, "
            f"stripped={self.stripped})"
        )

class BinaryLoader:
    """
    Binary loader for RE-Architect.
    
    This class handles loading and initial analysis of binary files.
    """
    
    def __init__(self):
        """Initialize the binary loader."""
        # Check for available tools
        self._check_tools()
        
        # Define supported binary formats
        self.supported_formats = ["elf", "pe", "macho"]
        
        # Check LIEF availability
        if not LIEF_AVAILABLE:
            logger.warning("LIEF not available. Some features may be limited.")
    
    def _check_tools(self) -> None:
        """Check for available binary analysis tools."""
        self.available_tools = {
            "file": self._check_command("file --version"),
            "objdump": self._check_command("objdump --version"),
            "readelf": self._check_command("readelf --version"),
            "nm": self._check_command("nm --version"),
            "strings": self._check_command("strings --version"),
            "ldd": self._check_command("ldd --version"),
            "lief": LIEF_AVAILABLE,
        }
        
        logger.debug(f"Available tools: {[k for k, v in self.available_tools.items() if v]}")
    
    def _check_command(self, command: str) -> bool:
        """
        Check if a command is available.
        
        Args:
            command: Command to check
            
        Returns:
            True if the command is available, False otherwise
        """
        try:
            subprocess.run(
                command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False
            )
            return True
        except (subprocess.SubprocessError, FileNotFoundError):
            return False
    
    def load(self, binary_path: Union[str, Path]) -> BinaryInfo:
        """
        Load and analyze a binary file.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            BinaryInfo object containing information about the binary
            
        Raises:
            FileNotFoundError: If the binary file doesn't exist
            ValueError: If the binary format is not supported
        """
        binary_path = Path(binary_path)
        
        # Check if file exists
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary file not found: {binary_path}")
        
        logger.info(f"Loading binary: {binary_path}")
        
        # Use LIEF if available for better analysis
        if LIEF_AVAILABLE:
            return self._load_with_lief(binary_path)
        else:
            return self._load_with_fallback(binary_path)
    
    def _load_with_lief(self, binary_path: Path) -> BinaryInfo:
        """
        Load and analyze a binary file using LIEF.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            BinaryInfo object containing information about the binary
        """
        try:
            # Parse the binary with LIEF
            binary = lief.parse(str(binary_path))
            if binary is None:
                logger.warning("LIEF failed to parse binary, falling back to basic analysis")
                return self._load_with_fallback(binary_path)
            
            # Determine format
            binary_format = self._lief_determine_format(binary)
            
            # Get architecture info
            architecture, bit_width, endianness = self._lief_get_architecture(binary)
            
            # Get entry point
            entry_point = binary.entrypoint if hasattr(binary, 'entrypoint') else 0
            
            # Get sections
            sections = self._lief_get_sections(binary)
            
            # Get symbols
            symbols = self._lief_get_symbols(binary)
            
            # Detect compiler
            compiler = self._lief_detect_compiler(binary, sections)
            
            # Check if stripped
            stripped = len(symbols) == 0 or all(not sym.get('name', '') for sym in symbols.values())
            
            # Check if library
            is_library = self._lief_is_library(binary)
            
            # Get imports and exports
            imports = self._lief_get_imports(binary)
            exports = self._lief_get_exports(binary)
            
            return BinaryInfo(
                path=binary_path,
                format=binary_format,
                architecture=architecture,
                bit_width=bit_width,
                endianness=endianness,
                entry_point=entry_point,
                sections=sections,
                symbols=symbols,
                compiler=compiler,
                stripped=stripped,
                is_library=is_library,
                imports=imports,
                exports=exports
            )
            
        except Exception as e:
            logger.error(f"Error using LIEF to parse {binary_path}: {e}")
            logger.info("Falling back to basic analysis")
            return self._load_with_fallback(binary_path)
    
    def _load_with_fallback(self, binary_path: Path) -> BinaryInfo:
        """
        Load and analyze a binary file using basic analysis.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            BinaryInfo object containing information about the binary
        """
        # Get basic file information
        file_info = self._get_file_info(binary_path)
        
        # Determine binary format
        binary_format = self._determine_format(file_info)
        
        # Determine architecture
        architecture, bit_width, endianness = self._determine_architecture(file_info)
        
        # Get entry point (basic implementation)
        entry_point = 0
        
        # Get sections (basic implementation)
        sections = {}
        
        # Get symbols (basic implementation)
        symbols = {}
        
        # Detect compiler (basic implementation)
        compiler = CompilerType.UNKNOWN
        
        # Check if stripped (basic implementation)
        stripped = True
        
        # Check if library (basic implementation)
        is_library = False
        
        # Get imports and exports (basic implementation)
        imports = {}
        exports = []
        
        return BinaryInfo(
            path=binary_path,
            format=binary_format,
            architecture=architecture,
            bit_width=bit_width,
            endianness=endianness,
            entry_point=entry_point,
            sections=sections,
            symbols=symbols,
            compiler=compiler,
            stripped=stripped,
            is_library=is_library,
            imports=imports,
            exports=exports
        )
    
    def _get_file_info(self, binary_path: Path) -> str:
        """
        Get basic file information using the 'file' command.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Output of the 'file' command
        """
        if not self.available_tools.get("file", False):
            logger.warning("'file' command not available, falling back to basic analysis")
            return ""
        
        try:
            result = subprocess.run(
                ["file", str(binary_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=True,
                text=True
            )
            return result.stdout.strip()
        except subprocess.SubprocessError as e:
            logger.warning(f"Error running 'file' command: {e}")
            return ""
    
    def _determine_format(self, file_info: str) -> BinaryFormat:
        """
        Determine the binary format based on file information.
        
        Args:
            file_info: Output of the 'file' command
            
        Returns:
            Detected binary format
        """
        file_info_lower = file_info.lower()
        
        if "elf" in file_info_lower:
            return BinaryFormat.ELF
        elif "pe" in file_info_lower or "executable for ms windows" in file_info_lower:
            return BinaryFormat.PE
        elif "mach-o" in file_info_lower:
            return BinaryFormat.MACHO
        else:
            return BinaryFormat.UNKNOWN
    
    def _determine_architecture(self, file_info: str) -> Tuple[Architecture, int, str]:
        """
        Determine the architecture, bit width, and endianness based on file information.
        
        Args:
            file_info: Output of the 'file' command
            
        Returns:
            Tuple of (architecture, bit_width, endianness)
        """
        file_info_lower = file_info.lower()
        
        # Determine architecture
        if "x86-64" in file_info_lower or "x86_64" in file_info_lower:
            architecture = Architecture.X86_64
            bit_width = 64
        elif "i386" in file_info_lower or "80386" in file_info_lower:
            architecture = Architecture.X86
            bit_width = 32
        elif "arm64" in file_info_lower or "aarch64" in file_info_lower:
            architecture = Architecture.ARM64
            bit_width = 64
        elif "arm" in file_info_lower:
            architecture = Architecture.ARM
            bit_width = 32
        else:
            architecture = Architecture.UNKNOWN
            bit_width = 32
        
        # Determine endianness
        if "msb" in file_info_lower or "big-endian" in file_info_lower:
            endianness = "big"
        else:
            endianness = "little"
        
        return architecture, bit_width, endianness
    
    # LIEF-specific helper methods
    def _lief_determine_format(self, binary) -> BinaryFormat:
        """Determine binary format using LIEF."""
        if hasattr(binary, 'format'):
            if binary.format == lief.Binary.FORMATS.ELF:
                return BinaryFormat.ELF
            elif binary.format == lief.Binary.FORMATS.PE:
                return BinaryFormat.PE
            elif binary.format == lief.Binary.FORMATS.MACHO:
                return BinaryFormat.MACHO
        return BinaryFormat.UNKNOWN
    
    def _lief_get_architecture(self, binary) -> Tuple[Architecture, int, str]:
        """Get architecture information using LIEF."""
        architecture = Architecture.UNKNOWN
        bit_width = 32
        endianness = "little"
        
        if hasattr(binary, 'header'):
            header = binary.header
            
            # ELF specific
            if binary.format == lief.Binary.FORMATS.ELF:
                machine = header.machine_type if hasattr(header, 'machine_type') else None
                try:
                    if machine == lief.ELF.ARCH.x86_64:
                        architecture = Architecture.X86_64
                        bit_width = 64
                    elif machine == lief.ELF.ARCH.i386:
                        architecture = Architecture.X86
                        bit_width = 32
                    elif machine == lief.ELF.ARCH.ARM:
                        architecture = Architecture.ARM
                        bit_width = 32
                    elif machine == lief.ELF.ARCH.AARCH64:
                        architecture = Architecture.ARM64
                        bit_width = 64
                    
                    # Get endianness
                    endianness = "little" if header.identity_data == lief.ELF.ELF_DATA.LSB else "big"
                except AttributeError:
                    # Fallback for different LIEF versions
                    pass
            
            # PE specific
            elif binary.format == lief.Binary.FORMATS.PE:
                machine = header.machine if hasattr(header, 'machine') else None
                try:
                    # Handle different LIEF API versions
                    if hasattr(lief.PE, 'MACHINE_TYPES'):
                        machine_types = lief.PE.MACHINE_TYPES
                    else:
                        # Fallback for newer LIEF versions
                        machine_types = lief.PE.MACHINE_TYPE
                    
                    if hasattr(machine_types, 'AMD64') and machine == machine_types.AMD64:
                        architecture = Architecture.X86_64
                        bit_width = 64
                    elif hasattr(machine_types, 'I386') and machine == machine_types.I386:
                        architecture = Architecture.X86
                        bit_width = 32
                    elif hasattr(machine_types, 'ARM64') and machine == machine_types.ARM64:
                        architecture = Architecture.ARM64
                        bit_width = 64
                except AttributeError:
                    # Fallback - try to determine from binary class
                    if hasattr(binary, 'optional_header') and hasattr(binary.optional_header, 'magic'):
                        magic = binary.optional_header.magic
                        if magic == 0x20b:  # PE32+
                            architecture = Architecture.X86_64
                            bit_width = 64
                        elif magic == 0x10b:  # PE32
                            architecture = Architecture.X86
                            bit_width = 32
            
            # Mach-O specific
            elif binary.format == lief.Binary.FORMATS.MACHO:
                cpu_type = header.cpu_type if hasattr(header, 'cpu_type') else None
                try:
                    if hasattr(lief.MachO, 'CPU_TYPES'):
                        cpu_types = lief.MachO.CPU_TYPES
                    else:
                        cpu_types = lief.MachO.CPU_TYPE
                    
                    if hasattr(cpu_types, 'x86_64') and cpu_type == cpu_types.x86_64:
                        architecture = Architecture.X86_64
                        bit_width = 64
                    elif hasattr(cpu_types, 'x86') and cpu_type == cpu_types.x86:
                        architecture = Architecture.X86
                        bit_width = 32
                    elif hasattr(cpu_types, 'ARM64') and cpu_type == cpu_types.ARM64:
                        architecture = Architecture.ARM64
                        bit_width = 64
                    elif hasattr(cpu_types, 'ARM') and cpu_type == cpu_types.ARM:
                        architecture = Architecture.ARM
                        bit_width = 32
                except AttributeError:
                    pass
        
        return architecture, bit_width, endianness
    
    def _lief_get_sections(self, binary) -> Dict[str, Dict]:
        """Get section information using LIEF."""
        sections = {}
        
        if hasattr(binary, 'sections'):
            for idx, section in enumerate(binary.sections):
                section_info = {
                    "name": section.name if hasattr(section, 'name') else f"section_{idx}",
                    "virtual_address": section.virtual_address if hasattr(section, 'virtual_address') else 0,
                    "size": section.size if hasattr(section, 'size') else 0,
                    "offset": section.offset if hasattr(section, 'offset') else 0,
                    "entropy": section.entropy if hasattr(section, 'entropy') else 0.0,
                }
                
                # Add format-specific information
                if binary.format == lief.Binary.FORMATS.ELF and hasattr(section, 'type'):
                    section_info["type"] = str(section.type)
                    section_info["flags"] = section.flags if hasattr(section, 'flags') else 0
                elif binary.format == lief.Binary.FORMATS.PE and hasattr(section, 'characteristics'):
                    section_info["characteristics"] = section.characteristics
                
                sections[section_info["name"]] = section_info
        
        return sections
    
    def _lief_get_symbols(self, binary) -> Dict[str, Dict]:
        """Get symbol information using LIEF."""
        symbols = {}
        
        # Get static symbols
        if hasattr(binary, 'symbols'):
            for symbol in binary.symbols:
                if hasattr(symbol, 'name') and symbol.name:
                    symbol_info = {
                        "name": symbol.name,
                        "value": symbol.value if hasattr(symbol, 'value') else 0,
                        "size": symbol.size if hasattr(symbol, 'size') else 0,
                        "type": "static"
                    }
                    
                    # Add format-specific info
                    if binary.format == lief.Binary.FORMATS.ELF:
                        if hasattr(symbol, 'type'):
                            symbol_info["symbol_type"] = str(symbol.type)
                        if hasattr(symbol, 'binding'):
                            symbol_info["binding"] = str(symbol.binding)
                    
                    symbols[symbol.name] = symbol_info
        
        # Get dynamic symbols for ELF
        if binary.format == lief.Binary.FORMATS.ELF and hasattr(binary, 'dynamic_symbols'):
            for symbol in binary.dynamic_symbols:
                if hasattr(symbol, 'name') and symbol.name:
                    symbol_info = {
                        "name": symbol.name,
                        "value": symbol.value if hasattr(symbol, 'value') else 0,
                        "size": symbol.size if hasattr(symbol, 'size') else 0,
                        "type": "dynamic"
                    }
                    symbols[symbol.name] = symbol_info
        
        return symbols
    
    def _lief_detect_compiler(self, binary, sections: Dict) -> CompilerType:
        """Detect compiler using LIEF analysis."""
        # Look for compiler-specific sections or strings
        if ".gcc_except_table" in sections or ".eh_frame" in sections:
            return CompilerType.GCC
        
        if binary.format == lief.Binary.FORMATS.PE:
            # Check for MSVC-specific sections
            if ".rdata" in sections and ".pdata" in sections:
                return CompilerType.MSVC
        
        # Look for Go-specific patterns
        if ".gopclntab" in sections or ".go.buildinfo" in sections:
            return CompilerType.GO
        
        # Look for Rust-specific patterns
        rust_sections = [".text.startup", ".rustc"]
        if any(section in sections for section in rust_sections):
            return CompilerType.RUST
        
        return CompilerType.UNKNOWN
    
    def _lief_is_library(self, binary) -> bool:
        """Check if binary is a library using LIEF."""
        try:
            if binary.format == lief.Binary.FORMATS.ELF:
                return hasattr(binary, 'header') and hasattr(binary.header, 'file_type') and \
                       str(binary.header.file_type).endswith('DYNAMIC')
            elif binary.format == lief.Binary.FORMATS.PE:
                return hasattr(binary, 'header') and hasattr(binary.header, 'characteristics') and \
                       (binary.header.characteristics & 0x2000) != 0  # IMAGE_FILE_DLL
            elif binary.format == lief.Binary.FORMATS.MACHO:
                return hasattr(binary, 'header') and hasattr(binary.header, 'file_type') and \
                       str(binary.header.file_type).endswith('DYLIB')
        except AttributeError:
            pass
        return False
    
    def _lief_get_imports(self, binary) -> Dict[str, List[str]]:
        """Get import information using LIEF."""
        imports = {}
        
        if hasattr(binary, 'imports'):
            for imported_library in binary.imports:
                library_name = imported_library.name if hasattr(imported_library, 'name') else "unknown"
                import_list = []
                
                if hasattr(imported_library, 'entries'):
                    for entry in imported_library.entries:
                        if hasattr(entry, 'name') and entry.name:
                            import_list.append(entry.name)
                
                if import_list:
                    imports[library_name] = import_list
        
        return imports
    
    def _lief_get_exports(self, binary) -> List[str]:
        """Get export information using LIEF."""
        exports = []
        
        if hasattr(binary, 'exported_functions'):
            for export in binary.exported_functions:
                if hasattr(export, 'name') and export.name:
                    exports.append(export.name)
        
        return exports