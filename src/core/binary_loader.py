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
    
    def _check_tools(self) -> None:
        """Check for available binary analysis tools."""
        self.available_tools = {
            "file": self._check_command("file --version"),
            "objdump": self._check_command("objdump --version"),
            "readelf": self._check_command("readelf --version"),
            "nm": self._check_command("nm --version"),
            "strings": self._check_command("strings --version"),
            "ldd": self._check_command("ldd --version"),
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
        
        # Get basic file information
        file_info = self._get_file_info(binary_path)
        
        # Determine binary format
        binary_format = self._determine_format(file_info)
        
        # Determine architecture
        architecture, bit_width, endianness = self._determine_architecture(file_info)
        
        # Get entry point
        entry_point = self._get_entry_point(binary_path, binary_format)
        
        # Get sections
        sections = self._get_sections(binary_path, binary_format)
        
        # Get symbols
        symbols = self._get_symbols(binary_path, binary_format)
        
        # Detect compiler
        compiler = self._detect_compiler(binary_path, file_info, sections)
        
        # Check if stripped
        stripped = self._is_stripped(binary_path, symbols)
        
        # Check if library
        is_library = self._is_library(binary_path, binary_format, file_info)
        
        # Get imports and exports
        imports = self._get_imports(binary_path, binary_format)
        exports = self._get_exports(binary_path, binary_format)
        
        binary_info = BinaryInfo(
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
        
        logger.info(f"Binary loaded: {binary_info}")
        return binary_info
    
    def _get_file_info(self, binary_path: Path) -> str:
        """
        Get basic file information using the 'file' command.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Output of the 'file' command
        """
        if not self.available_tools["file"]:
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
            # Try to determine based on file extension or content
            return BinaryFormat.UNKNOWN
    
    def _determine_architecture(self, file_info: str) -> Tuple[Architecture, int, str]:
        """
        Determine the architecture, bit width, and endianness based on file information.
        
        Args:
            file_info: Output of the 'file' command
            
        Returns:
            Tuple containing architecture, bit width, and endianness
        """
        file_info_lower = file_info.lower()
        
        # Default values
        architecture = Architecture.UNKNOWN
        bit_width = 0
        endianness = "unknown"
        
        # Detect architecture
        if "x86-64" in file_info_lower or "x86_64" in file_info_lower or "amd64" in file_info_lower:
            architecture = Architecture.X86_64
            bit_width = 64
        elif "x86" in file_info_lower or "i386" in file_info_lower or "i686" in file_info_lower:
            architecture = Architecture.X86
            bit_width = 32
        elif "aarch64" in file_info_lower or "arm64" in file_info_lower:
            architecture = Architecture.ARM64
            bit_width = 64
        elif "arm" in file_info_lower:
            architecture = Architecture.ARM
            bit_width = 32
        elif "mips64" in file_info_lower:
            architecture = Architecture.MIPS64
            bit_width = 64
        elif "mips" in file_info_lower:
            architecture = Architecture.MIPS
            bit_width = 32
        elif "powerpc64" in file_info_lower or "ppc64" in file_info_lower:
            architecture = Architecture.PPC64
            bit_width = 64
        elif "powerpc" in file_info_lower or "ppc" in file_info_lower:
            architecture = Architecture.PPC
            bit_width = 32
        
        # Detect endianness
        if "lsb" in file_info_lower or "little endian" in file_info_lower:
            endianness = "little"
        elif "msb" in file_info_lower or "big endian" in file_info_lower:
            endianness = "big"
        
        return architecture, bit_width, endianness
    
    def _get_entry_point(self, binary_path: Path, binary_format: BinaryFormat) -> int:
        """
        Get the entry point of the binary.
        
        Args:
            binary_path: Path to the binary file
            binary_format: Format of the binary
            
        Returns:
            Entry point address as an integer
        """
        entry_point = 0
        
        if binary_format == BinaryFormat.ELF and self.available_tools["readelf"]:
            try:
                result = subprocess.run(
                    ["readelf", "-h", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                
                for line in result.stdout.splitlines():
                    if "Entry point address:" in line:
                        entry_hex = line.split(":")[1].strip()
                        entry_point = int(entry_hex, 16)
                        break
            except (subprocess.SubprocessError, ValueError) as e:
                logger.warning(f"Error getting entry point: {e}")
        
        # TODO: Implement for other binary formats
        
        return entry_point
    
    def _get_sections(self, binary_path: Path, binary_format: BinaryFormat) -> Dict[str, Dict]:
        """
        Get sections from the binary.
        
        Args:
            binary_path: Path to the binary file
            binary_format: Format of the binary
            
        Returns:
            Dictionary mapping section names to section information
        """
        sections = {}
        
        if binary_format == BinaryFormat.ELF and self.available_tools["readelf"]:
            try:
                result = subprocess.run(
                    ["readelf", "-S", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                
                # Parse the readelf output
                in_section_headers = False
                for line in result.stdout.splitlines():
                    line = line.strip()
                    
                    if "Section Headers:" in line:
                        in_section_headers = True
                        continue
                    
                    if in_section_headers and line and line[0] == "[":
                        parts = line.split()
                        if len(parts) >= 7:
                            try:
                                # Extract section index
                                section_idx = int(parts[0].strip("[]"))
                                
                                # Extract section name
                                section_name = parts[1]
                                
                                # Extract section size
                                section_size = int(parts[4], 16)
                                
                                # Extract section address
                                section_addr = int(parts[3], 16)
                                
                                sections[section_name] = {
                                    "index": section_idx,
                                    "address": section_addr,
                                    "size": section_size
                                }
                            except (IndexError, ValueError) as e:
                                logger.debug(f"Error parsing section line '{line}': {e}")
            except subprocess.SubprocessError as e:
                logger.warning(f"Error getting sections: {e}")
        
        # TODO: Implement for other binary formats
        
        return sections
    
    def _get_symbols(self, binary_path: Path, binary_format: BinaryFormat) -> Dict[str, Dict]:
        """
        Get symbols from the binary.
        
        Args:
            binary_path: Path to the binary file
            binary_format: Format of the binary
            
        Returns:
            Dictionary mapping symbol names to symbol information
        """
        symbols = {}
        
        if binary_format == BinaryFormat.ELF and self.available_tools["nm"]:
            try:
                result = subprocess.run(
                    ["nm", "-n", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,  # Don't fail on stripped binaries
                    text=True
                )
                
                for line in result.stdout.splitlines():
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            try:
                                addr = int(parts[0], 16)
                                symbol_type = parts[1]
                                name = parts[2]
                                
                                symbols[name] = {
                                    "address": addr,
                                    "type": symbol_type
                                }
                            except (IndexError, ValueError) as e:
                                logger.debug(f"Error parsing symbol line '{line}': {e}")
            except subprocess.SubprocessError as e:
                logger.warning(f"Error getting symbols: {e}")
        
        # TODO: Implement for other binary formats
        
        return symbols
    
    def _detect_compiler(
        self,
        binary_path: Path,
        file_info: str,
        sections: Dict[str, Dict]
    ) -> CompilerType:
        """
        Detect the compiler used to build the binary.
        
        Args:
            binary_path: Path to the binary file
            file_info: Output of the 'file' command
            sections: Dictionary of section information
            
        Returns:
            Detected compiler type
        """
        file_info_lower = file_info.lower()
        
        # Check for common compiler signatures in the file info
        if "gcc" in file_info_lower:
            return CompilerType.GCC
        elif "clang" in file_info_lower:
            return CompilerType.CLANG
        elif "microsoft" in file_info_lower:
            return CompilerType.MSVC
        elif "go" in file_info_lower:
            return CompilerType.GO
        elif "rust" in file_info_lower:
            return CompilerType.RUST
        
        # Look for specific sections or strings
        if self.available_tools["strings"]:
            try:
                result = subprocess.run(
                    ["strings", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                
                output = result.stdout.lower()
                
                if "gcc" in output and "gcc_" in output:
                    return CompilerType.GCC
                elif "clang" in output:
                    return CompilerType.CLANG
                elif "microsoft" in output and "msvc" in output:
                    return CompilerType.MSVC
                elif "go build id" in output:
                    return CompilerType.GO
                elif "rust" in output and "rustc" in output:
                    return CompilerType.RUST
            except subprocess.SubprocessError:
                pass
        
        return CompilerType.UNKNOWN
    
    def _is_stripped(self, binary_path: Path, symbols: Dict[str, Dict]) -> bool:
        """
        Check if the binary is stripped.
        
        Args:
            binary_path: Path to the binary file
            symbols: Dictionary of symbol information
            
        Returns:
            True if the binary is stripped, False otherwise
        """
        # A binary is considered stripped if it has very few symbols
        # or if most symbols are system/library symbols
        
        # Quick check: if there are no symbols, it's definitely stripped
        if not symbols:
            return True
        
        # Count function symbols (usually type 'T' or 't')
        function_symbols = sum(1 for info in symbols.values() if info.get("type") in ["T", "t"])
        
        # If there are more than a few function symbols, it's probably not stripped
        return function_symbols < 5
    
    def _is_library(
        self,
        binary_path: Path,
        binary_format: BinaryFormat,
        file_info: str
    ) -> bool:
        """
        Check if the binary is a library.
        
        Args:
            binary_path: Path to the binary file
            binary_format: Format of the binary
            file_info: Output of the 'file' command
            
        Returns:
            True if the binary is a library, False otherwise
        """
        file_info_lower = file_info.lower()
        
        # Check file extension
        suffix = binary_path.suffix.lower()
        
        if suffix in [".so", ".dll", ".dylib"]:
            return True
        
        # Check file info
        if "shared" in file_info_lower and "library" in file_info_lower:
            return True
        
        # For ELF files, check if it's an executable or a shared object
        if binary_format == BinaryFormat.ELF and self.available_tools["readelf"]:
            try:
                result = subprocess.run(
                    ["readelf", "-h", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True,
                    text=True
                )
                
                for line in result.stdout.splitlines():
                    if "Type:" in line:
                        if "DYN" in line or "EXEC" in line:
                            return "DYN" in line and "EXEC" not in line
            except subprocess.SubprocessError:
                pass
        
        return False
    
    def _get_imports(self, binary_path: Path, binary_format: BinaryFormat) -> Dict[str, List[str]]:
        """
        Get imported symbols from the binary.
        
        Args:
            binary_path: Path to the binary file
            binary_format: Format of the binary
            
        Returns:
            Dictionary mapping library names to lists of imported symbols
        """
        imports = {}
        
        if binary_format == BinaryFormat.ELF and self.available_tools["readelf"]:
            try:
                result = subprocess.run(
                    ["readelf", "-d", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    text=True
                )
                
                # Extract shared library dependencies
                for line in result.stdout.splitlines():
                    if "NEEDED" in line and "Shared library:" in line:
                        lib_name = line.split("[")[1].split("]")[0]
                        imports[lib_name] = []
                
                # Now try to get the actual imported symbols
                if self.available_tools["nm"]:
                    result = subprocess.run(
                        ["nm", "-D", "--undefined-only", str(binary_path)],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        check=False,
                        text=True
                    )
                    
                    # Group imports by library (this is an approximation)
                    for line in result.stdout.splitlines():
                        if line.strip():
                            parts = line.split()
                            if len(parts) >= 2:
                                symbol = parts[-1]
                                
                                # For simplicity, add to "unknown" library
                                if "unknown" not in imports:
                                    imports["unknown"] = []
                                imports["unknown"].append(symbol)
            except subprocess.SubprocessError as e:
                logger.warning(f"Error getting imports: {e}")
        
        # TODO: Implement for other binary formats
        
        return imports
    
    def _get_exports(self, binary_path: Path, binary_format: BinaryFormat) -> List[str]:
        """
        Get exported symbols from the binary.
        
        Args:
            binary_path: Path to the binary file
            binary_format: Format of the binary
            
        Returns:
            List of exported symbol names
        """
        exports = []
        
        if binary_format == BinaryFormat.ELF and self.available_tools["nm"]:
            try:
                result = subprocess.run(
                    ["nm", "-D", "--defined-only", str(binary_path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=False,
                    text=True
                )
                
                for line in result.stdout.splitlines():
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3 and parts[1] in ["T", "t"]:
                            exports.append(parts[2])
            except subprocess.SubprocessError as e:
                logger.warning(f"Error getting exports: {e}")
        
        # TODO: Implement for other binary formats
        
        return exports
