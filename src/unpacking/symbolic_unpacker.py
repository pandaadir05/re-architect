"""
Symbolic execution unpacker for RE-Architect.

This module uses Angr to symbolically execute packed binaries and extract
the unpacked payload. It can detect common packers and automatically
unpack binaries to enable static analysis.
"""

import logging
import tempfile
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass

logger = logging.getLogger("re-architect.unpacking.symbolic")

@dataclass
class UnpackingResult:
    """Result from symbolic unpacking."""
    success: bool
    unpacked_path: Optional[Path] = None
    original_path: Optional[Path] = None
    packer_detected: Optional[str] = None
    unpacking_method: Optional[str] = None
    execution_steps: int = 0
    memory_dumps: List[Tuple[int, int, bytes]] = None  # (address, size, data)
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.memory_dumps is None:
            self.memory_dumps = []
        if self.metadata is None:
            self.metadata = {}


class SymbolicUnpacker:
    """
    Symbolic execution unpacker using Angr.
    
    This class can detect common packers and automatically unpack binaries
    using symbolic execution to find the unpacked payload in memory.
    """
    
    def __init__(self, config: Optional[Dict] = None):
        """
        Initialize the symbolic unpacker.
        
        Args:
            config: Configuration dictionary for unpacking parameters
        """
        self.config = config or {}
        self.max_execution_steps = self.config.get("unpacking.max_execution_steps", 10000)
        self.timeout_seconds = self.config.get("unpacking.timeout_seconds", 300)
        self.memory_dump_threshold = self.config.get("unpacking.memory_dump_threshold", 1024 * 1024)  # 1MB
        
        # Common packer signatures
        self.packer_signatures = {
            "UPX": [b"UPX!", b"$Info: This file is packed with the UPX"],
            "PECompact": [b"PECompact"],
            "ASPack": [b"aPLib", b"ASPack"],
            "FSG": [b"FSG!"],
            "Mew": [b"Mew11"],
            "Themida": [b"Themida"],
            "VMProtect": [b"VMProtect"],
            "Armadillo": [b"Armadillo"],
            "Enigma": [b"Enigma"],
        }
    
    def detect_packer(self, binary_path: Path) -> Optional[str]:
        """
        Detect if a binary is packed and identify the packer.
        
        Args:
            binary_path: Path to the binary file
            
        Returns:
            Name of detected packer or None if not packed
        """
        try:
            with open(binary_path, 'rb') as f:
                data = f.read()
            
            for packer_name, signatures in self.packer_signatures.items():
                for signature in signatures:
                    if signature in data:
                        logger.info(f"Detected packer: {packer_name}")
                        return packer_name
            
            # Additional heuristics for packed binaries
            if self._is_likely_packed(data):
                return "Unknown"
                
            return None
            
        except Exception as e:
            logger.error(f"Error detecting packer: {e}")
            return None
    
    def _is_likely_packed(self, data: bytes) -> bool:
        """
        Heuristic check for packed binaries.
        
        Args:
            data: Binary data to analyze
            
        Returns:
            True if binary appears to be packed
        """
        # Check for common packed binary characteristics
        if len(data) < 1024:  # Too small to be meaningful
            return False
            
        # High entropy (compressed/encrypted data)
        entropy = self._calculate_entropy(data)
        if entropy > 7.5:  # Very high entropy suggests packed data
            return True
            
        # Check for suspicious section characteristics
        # This is a simplified check - in practice, you'd parse PE/ELF headers
        suspicious_patterns = [
            b".upx", b".packed", b".encrypted", b".compressed",
            b"UPX", b"aPLib", b"FSG", b"Mew"
        ]
        
        for pattern in suspicious_patterns:
            if pattern in data:
                return True
                
        return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if not data:
            return 0.0
            
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in byte_counts:
            if count > 0:
                probability = count / data_len
                entropy -= probability * (probability.bit_length() - 1)
                
        return entropy
    
    def unpack(self, binary_path: Path, output_path: Optional[Path] = None) -> UnpackingResult:
        """
        Unpack a binary using symbolic execution.
        
        Args:
            binary_path: Path to the packed binary
            output_path: Optional path for unpacked binary output
            
        Returns:
            UnpackingResult with unpacking status and results
        """
        logger.info(f"Starting symbolic unpacking of {binary_path}")
        
        # Detect packer
        packer = self.detect_packer(binary_path)
        if not packer:
            return UnpackingResult(
                success=False,
                original_path=binary_path,
                error_message="No packer detected"
            )
        
        try:
            # Try to import Angr
            import angr
            import claripy
        except ImportError:
            return UnpackingResult(
                success=False,
                original_path=binary_path,
                error_message="Angr not available - install with: pip install angr"
            )
        
        try:
            # Create Angr project
            project = angr.Project(str(binary_path), auto_load_libs=False)
            
            # Set up symbolic execution
            state = project.factory.entry_state()
            simgr = project.factory.simulation_manager(state)
            
            # Track execution steps
            execution_steps = 0
            memory_dumps = []
            
            # Symbolic execution loop
            while simgr.active and execution_steps < self.max_execution_steps:
                simgr.step()
                execution_steps += 1
                
                # Check for unpacking completion
                if self._check_unpacking_complete(simgr, project):
                    logger.info("Unpacking appears complete")
                    break
                
                # Dump memory periodically to look for unpacked code
                if execution_steps % 1000 == 0:
                    self._dump_memory_regions(simgr, memory_dumps)
            
            # Final memory dump
            self._dump_memory_regions(simgr, memory_dumps)
            
            # Extract unpacked binary
            unpacked_data = self._extract_unpacked_binary(simgr, project)
            
            if unpacked_data:
                # Save unpacked binary
                if output_path is None:
                    output_path = binary_path.parent / f"{binary_path.stem}_unpacked{binary_path.suffix}"
                
                with open(output_path, 'wb') as f:
                    f.write(unpacked_data)
                
                logger.info(f"Successfully unpacked binary to {output_path}")
                
                return UnpackingResult(
                    success=True,
                    unpacked_path=output_path,
                    original_path=binary_path,
                    packer_detected=packer,
                    unpacking_method="symbolic_execution",
                    execution_steps=execution_steps,
                    memory_dumps=memory_dumps,
                    metadata={
                        "angr_version": getattr(angr, '__version__', 'unknown'),
                        "project_arch": str(project.arch),
                        "entry_point": hex(project.entry),
                    }
                )
            else:
                return UnpackingResult(
                    success=False,
                    original_path=binary_path,
                    packer_detected=packer,
                    execution_steps=execution_steps,
                    error_message="Failed to extract unpacked binary"
                )
                
        except Exception as e:
            logger.error(f"Error during symbolic unpacking: {e}")
            return UnpackingResult(
                success=False,
                original_path=binary_path,
                packer_detected=packer,
                error_message=f"Unpacking failed: {str(e)}"
            )
    
    def _check_unpacking_complete(self, simgr, project) -> bool:
        """
        Check if unpacking appears to be complete.
        
        This is a heuristic check - in practice, you'd look for specific
        patterns that indicate unpacking is done.
        """
        # Look for common unpacking completion patterns
        for state in simgr.active:
            # Check if we're in a region that looks like unpacked code
            if hasattr(state, 'addr') and state.addr:
                # Simple heuristic: if we're executing in a region with
                # typical executable characteristics, unpacking might be complete
                try:
                    # This is a simplified check - real implementation would
                    # analyze memory regions and instruction patterns
                    return False  # Placeholder
                except:
                    pass
        return False
    
    def _dump_memory_regions(self, simgr, memory_dumps: List[Tuple[int, int, bytes]]):
        """Dump interesting memory regions during execution."""
        for state in simgr.active:
            try:
                # Dump executable memory regions
                if hasattr(state, 'memory') and hasattr(state.memory, 'regions'):
                    for region in state.memory.regions:
                        if region.is_executable and region.size < self.memory_dump_threshold:
                            try:
                                data = state.memory.load(region.start, region.size)
                                if isinstance(data, claripy.ast.BV):
                                    # Convert symbolic data to concrete if possible
                                    concrete_data = state.solver.eval(data, cast_to=bytes)
                                    memory_dumps.append((region.start, region.size, concrete_data))
                            except:
                                pass
            except:
                pass
    
    def _extract_unpacked_binary(self, simgr, project) -> Optional[bytes]:
        """
        Extract the unpacked binary from memory.
        
        This is a simplified implementation - a real unpacker would
        need to identify the correct memory regions and reconstruct
        the binary format.
        """
        # For now, return a placeholder
        # Real implementation would:
        # 1. Identify the unpacked code region
        # 2. Extract the code and data sections
        # 3. Reconstruct the binary format (PE/ELF)
        # 4. Fix up imports and relocations
        
        logger.warning("Unpacked binary extraction not fully implemented")
        return None
    
    def is_available(self) -> bool:
        """Check if Angr is available for symbolic execution."""
        try:
            import angr
            return True
        except ImportError:
            return False
    
    def get_unpacker_info(self) -> Dict[str, Any]:
        """Get information about the unpacker."""
        return {
            "name": "SymbolicUnpacker",
            "available": self.is_available(),
            "max_execution_steps": self.max_execution_steps,
            "timeout_seconds": self.timeout_seconds,
            "supported_packers": list(self.packer_signatures.keys()),
        }
