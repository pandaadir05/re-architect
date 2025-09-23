"""
IDA Pro decompiler implementation for RE-Architect.

This module provides the integration with IDA Pro for decompilation.
"""

import logging
import os
import subprocess
import tempfile
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode, DecompiledFunction

logger = logging.getLogger("re-architect.decompilers.ida")

class IDADecompiler(BaseDecompiler):
    """
    IDA Pro decompiler implementation.
    
    This class provides integration with IDA Pro using IDAPython scripts
    and IDA's headless mode for automated decompilation.
    """
    
    def __init__(self, ida_path: Optional[str] = None):
        """
        Initialize the IDA Pro decompiler.
        
        Args:
            ida_path: Path to IDA Pro installation directory (optional)
        """
        super().__init__()
        self.name = "IDADecompiler"
        
        # Try to find IDA path if not provided
        self.ida_path = ida_path or self._find_ida_path()
        
        # Cache decompiler info
        self._decompiler_info = None
    
    def _find_ida_path(self) -> Optional[str]:
        """
        Find the IDA Pro installation directory.
        
        Looks for IDA Pro in common installation locations.
        
        Returns:
            Path to IDA Pro installation directory, or None if not found
        """
        # Check environment variable
        if "IDADIR" in os.environ:
            path = os.environ["IDADIR"]
            if os.path.exists(path):
                return path
        
        # Check common installation locations
        common_paths = []
        
        if os.name == "nt":  # Windows
            common_paths.extend([
                "C:/Program Files/IDA Pro 8.4",
                "C:/Program Files/IDA Pro 8.3", 
                "C:/Program Files/IDA Pro 8.2",
                "C:/Program Files/IDA Pro 8.1",
                "C:/Program Files/IDA Pro 8.0",
                "C:/Program Files/IDA Pro 7.7",
                "C:/Program Files (x86)/IDA Pro 8.4",
                "C:/Program Files (x86)/IDA Pro 8.3",
                "C:/Program Files (x86)/IDA Pro 8.2",
                "C:/Program Files (x86)/IDA Pro 8.1", 
                "C:/Program Files (x86)/IDA Pro 8.0",
                "C:/Program Files (x86)/IDA Pro 7.7",
                "C:/IDA",
                os.path.expanduser("~/IDA")
            ])
        else:  # Unix-like
            common_paths.extend([
                "/opt/ida",
                "/usr/local/ida",
                os.path.expanduser("~/ida"),
                os.path.expanduser("~/idapro")
            ])
        
        for path in common_paths:
            if os.path.exists(path):
                # Look for ida64 or idaq executable
                if self._find_ida_executable(path):
                    return path
        
        return None
    
    def _find_ida_executable(self, ida_dir: str) -> Optional[str]:
        """
        Find the IDA executable in the given directory.
        
        Args:
            ida_dir: IDA Pro installation directory
            
        Returns:
            Path to IDA executable, or None if not found
        """
        if os.name == "nt":  # Windows
            executables = ["ida64.exe", "idaq64.exe", "ida.exe", "idaq.exe"]
        else:  # Unix-like
            executables = ["ida64", "idaq64", "ida", "idaq"]
        
        for exe in executables:
            exe_path = os.path.join(ida_dir, exe)
            if os.path.exists(exe_path):
                return exe_path
        
        return None
    
    def is_available(self) -> bool:
        """
        Check if IDA Pro is available on the system.
        
        Returns:
            True if IDA Pro is available, False otherwise
        """
        if not self.ida_path:
            logger.warning("IDA Pro path not found")
            return False
        
        ida_exe = self._find_ida_executable(self.ida_path)
        if not ida_exe:
            logger.warning(f"IDA Pro executable not found in {self.ida_path}")
            return False
        
        return True
    
    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        """
        Decompile a binary using IDA Pro.
        
        Args:
            binary_info: Information about the binary to decompile
            
        Returns:
            Object containing the decompiled code
            
        Raises:
            RuntimeError: If decompilation fails or IDA Pro is not available
        """
        if not self.is_available():
            raise RuntimeError("IDA Pro is not available")
        
        logger.info(f"Decompiling {binary_info.path} using IDA Pro")
        
        # Create a temporary directory for IDA output
        with tempfile.TemporaryDirectory(prefix="re-architect-ida-") as temp_dir:
            output_dir = os.path.join(temp_dir, "output")
            os.makedirs(output_dir, exist_ok=True)
            
            # Create IDAPython script
            script_path = self._create_ida_script(temp_dir, output_dir)
            
            # Run IDA in headless mode
            ida_exe = self._find_ida_executable(self.ida_path)
            binary_path = str(binary_info.path)
            
            cmd = [
                ida_exe,
                "-A",  # Autonomous mode
                "-S" + script_path,  # Run script
                "-L" + os.path.join(temp_dir, "ida.log"),  # Log file
                binary_path
            ]
            
            logger.debug(f"Running IDA command: {cmd}")
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    cwd=temp_dir
                )
                
                # Wait for the process to complete with a timeout
                try:
                    stdout, stderr = process.communicate(timeout=600)  # 10-minute timeout
                    
                    if process.returncode != 0:
                        logger.error(f"IDA decompilation failed with code {process.returncode}")
                        logger.error(f"Stdout: {stdout}")
                        logger.error(f"Stderr: {stderr}")
                        raise RuntimeError(f"IDA decompilation failed with code {process.returncode}")
                    
                except subprocess.TimeoutExpired:
                    process.kill()
                    logger.error("IDA decompilation timed out")
                    raise RuntimeError("IDA decompilation timed out after 10 minutes")
                
                # Parse the output files
                return self._parse_output(binary_info, output_dir)
                
            except Exception as e:
                logger.exception(f"Error running IDA Pro: {e}")
                raise RuntimeError(f"Error running IDA Pro: {str(e)}")
    
    def _create_ida_script(self, script_dir: str, output_dir: str) -> str:
        """
        Create an IDAPython script to export decompiled code.
        
        Args:
            script_dir: Directory to write the script to
            output_dir: Directory to write the output to
            
        Returns:
            Path to the created script
        """
        script_path = os.path.join(script_dir, "export_decompiled.py")
        
        # Generate IDAPython script content
        script_template = '''
import idaapi
import idautils
import idc
import ida_hexrays
import ida_funcs
import ida_name
import ida_bytes
import ida_struct
import json
import os

OUTPUT_DIR = r"{output_dir}"

def main():
    """Main decompilation export function."""
    print("Starting IDA Pro decompilation export")
    
    # Wait for analysis to complete
    idaapi.auto_wait()
    
    # Ensure output directory exists
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    
    # Export program information
    export_program_info()
    
    # Export functions
    export_functions()
    
    # Export strings
    export_strings()
    
    # Export structures
    export_structures()
    
    print("Export complete")
    idc.qexit(0)

def export_program_info():
    """Export basic program information."""
    print("Exporting program info")
    
    info = {{
        "name": idc.get_root_filename(),
        "imagebase": idc.get_imagebase(),
        "entry_point": idc.get_inf_attr(idc.INF_START_IP),
        "architecture": idaapi.get_inf_structure().procName,
        "creation_date": idaapi.get_file_type_name()
    }}
    
    # Export memory segments
    segments = []
    for seg in idautils.Segments():
        seg_info = {{
            "name": idc.get_segm_name(seg),
            "start": seg,
            "end": idc.get_segm_end(seg),
            "size": idc.get_segm_end(seg) - seg,
            "class": idc.get_segm_attr(seg, idc.SEGATTR_CLASS)
        }}
        segments.append(seg_info)
    
    info["segments"] = segments
    
    # Write to file
    with open(os.path.join(OUTPUT_DIR, "program_info.json"), "w") as f:
        json.dump(info, f, indent=2)

def export_functions():
    """Export decompiled functions."""
    print("Exporting functions")
    
    functions = []
    functions_dir = os.path.join(OUTPUT_DIR, "functions")
    if not os.path.exists(functions_dir):
        os.makedirs(functions_dir)
    
    # Initialize decompiler
    if not ida_hexrays.init_hexrays_plugin():
        print("Hex-Rays decompiler not available")
        return
    
    count = 0
    for func_addr in idautils.Functions():
        func_name = idc.get_func_name(func_addr)
        if not func_name:
            func_name = "sub_" + format(func_addr, 'X')
        
        print("Processing function: " + func_name + " at 0x" + format(func_addr, 'X'))
        
        func_info = {{
            "address": "0x" + format(func_addr, 'X'),
            "name": func_name,
            "start": func_addr,
            "end": idc.get_func_attr(func_addr, idc.FUNCATTR_END),
            "size": idc.get_func_attr(func_addr, idc.FUNCATTR_END) - func_addr
        }}
        
        # Get function signature
        func_type = idc.get_type(func_addr)
        if func_type:
            func_info["signature"] = func_type
        
        # Get function parameters and return type
        tif = idaapi.tinfo_t()
        if idaapi.get_tinfo(tif, func_addr):
            func_details = idaapi.func_type_data_t()
            if tif.get_func_details(func_details):
                # Return type
                ret_type = str(func_details.rettype)
                func_info["return_type"] = ret_type
                
                # Parameters
                params = []
                for i in range(func_details.size()):
                    param = func_details[i]
                    param_info = {{
                        "name": param.name if param.name else "arg_" + str(i),
                        "type": str(param.type)
                    }}
                    params.append(param_info)
                func_info["parameters"] = params
        
        # Get function calls (outgoing references)
        calls = []
        for ref in idautils.CodeRefsFrom(func_addr, True):
            ref_name = idc.get_func_name(ref)
            if ref_name:
                calls.append({{
                    "address": "0x" + format(ref, 'X'),
                    "name": ref_name
                }})
        func_info["calls"] = calls
        
        # Attempt to decompile the function
        try:
            cfunc = ida_hexrays.decompile(func_addr)
            if cfunc:
                # Get the decompiled C code
                decompiled_code = str(cfunc)
                func_info["code"] = decompiled_code
                
                # Save to individual file
                safe_name = func_name.replace(":", "_").replace("?", "_")
                func_file = os.path.join(functions_dir, safe_name + ".c")
                with open(func_file, "w") as f:
                    f.write(decompiled_code)
            else:
                func_info["decompilation_error"] = "Failed to decompile"
                
        except Exception as e:
            func_info["decompilation_error"] = str(e)
        
        functions.append(func_info)
        count += 1
    
    print("Processed " + str(count) + " functions")
    
    # Write all functions info
    with open(os.path.join(OUTPUT_DIR, "functions.json"), "w") as f:
        json.dump(functions, f, indent=2)

def export_strings():
    """Export string constants."""
    print("Exporting strings")
    
    strings = []
    
    # Get all strings
    for string_addr in idautils.Strings():
        string_info = {{
            "address": "0x" + format(string_addr.ea, 'X'),
            "value": str(string_addr),
            "length": string_addr.length,
            "type": string_addr.strtype
        }}
        strings.append(string_info)
    
    print("Found " + str(len(strings)) + " strings")
    
    # Write strings to file
    with open(os.path.join(OUTPUT_DIR, "strings.json"), "w") as f:
        json.dump(strings, f, indent=2)

def export_structures():
    """Export structure definitions."""
    print("Exporting structures")
    
    structures = []
    
    # Get all structures
    for struct_idx in range(ida_struct.get_struc_qty()):
        struct_id = ida_struct.get_struc_by_idx(struct_idx)
        if struct_id != idaapi.BADADDR:
            struct_ptr = ida_struct.get_struc(struct_id)
            if struct_ptr:
                struct_name = ida_struct.get_struc_name(struct_id)
                struct_size = ida_struct.get_struc_size(struct_id)
                
                struct_info = {{
                    "name": struct_name,
                    "size": struct_size,
                    "id": struct_id
                }}
                
                # Get structure members
                members = []
                for member_idx in range(struct_ptr.memqty):
                    member = struct_ptr.get_member(member_idx)
                    if member:
                        member_info = {{
                            "name": ida_struct.get_member_name(member.id),
                            "offset": member.soff,
                            "size": ida_struct.get_member_size(member),
                            "type": idc.get_type(member.id) or "unknown"
                        }}
                        members.append(member_info)
                
                struct_info["members"] = members
                structures.append(struct_info)
    
    print("Found " + str(len(structures)) + " structures")
    
    # Write structures to file
    with open(os.path.join(OUTPUT_DIR, "structures.json"), "w") as f:
        json.dump(structures, f, indent=2)

if __name__ == "__main__":
    main()
'''
        
        script_content = script_template.format(output_dir=output_dir)
        
        with open(script_path, "w") as f:
            f.write(script_content)
        
        return script_path
    
    def _parse_output(self, binary_info: BinaryInfo, output_dir: str) -> DecompiledCode:
        """
        Parse the output files from IDA Pro.
        
        Args:
            binary_info: Information about the decompiled binary
            output_dir: Directory containing the output files
            
        Returns:
            DecompiledCode object containing decompilation results
        """
        logger.info("Parsing IDA Pro output")
        
        decompiled_code = DecompiledCode(binary_info)
        
        # Parse functions
        functions_file = os.path.join(output_dir, "functions.json")
        if os.path.exists(functions_file):
            try:
                with open(functions_file, "r") as f:
                    functions_data = json.load(f)
                    
                    for func_data in functions_data:
                        address = int(func_data["address"], 16)
                        name = func_data["name"]
                        code = func_data.get("code", "// Decompilation failed")
                        
                        # Extract metadata
                        metadata = {
                            "signature": func_data.get("signature", ""),
                            "return_type": func_data.get("return_type", ""),
                            "parameters": func_data.get("parameters", []),
                            "calls": func_data.get("calls", []),
                            "size": func_data.get("size", 0),
                            "decompilation_error": func_data.get("decompilation_error", None)
                        }
                        
                        decompiled_code.add_function(address, code, name, metadata)
                    
                    logger.info(f"Loaded {len(functions_data)} functions")
            except Exception as e:
                logger.error(f"Error parsing functions.json: {{e}}")
        
        # Parse strings
        strings_file = os.path.join(output_dir, "strings.json")
        if os.path.exists(strings_file):
            try:
                with open(strings_file, "r") as f:
                    strings_data = json.load(f)
                    
                    for string_data in strings_data:
                        address = int(string_data["address"], 16)
                        value = string_data["value"]
                        decompiled_code.add_string(address, value)
                    
                    logger.info(f"Loaded {len(strings_data)} strings")
            except Exception as e:
                logger.error(f"Error parsing strings.json: {{e}}")
        
        # Parse structures
        structures_file = os.path.join(output_dir, "structures.json")
        if os.path.exists(structures_file):
            try:
                with open(structures_file, "r") as f:
                    structures_data = json.load(f)
                    
                    for struct_data in structures_data:
                        name = struct_data["name"]
                        definition = self._convert_to_c_struct(struct_data)
                        decompiled_code.add_type(name, definition)
                    
                    logger.info(f"Loaded {len(structures_data)} structures")
            except Exception as e:
                logger.error(f"Error parsing structures.json: {{e}}")
        
        return decompiled_code
    
    def _convert_to_c_struct(self, struct_data: Dict) -> str:
        """
        Convert a struct definition from IDA's JSON format to C code.
        
        Args:
            struct_data: Structure data from IDA
            
        Returns:
            C structure definition
        """
        name = struct_data["name"]
        members = struct_data.get("members", [])
        
        lines = [f"struct {{name}} {{"]
        
        for member in members:
            member_name = member.get("name", "field")
            member_type = member.get("type", "undefined")
            lines.append(f"    {member_type} {member_name};")
        
        lines.append("}};")
        
        return "\n".join(lines)
    
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the IDA Pro decompiler.
        
        Returns:
            Dictionary containing decompiler information
        """
        if self._decompiler_info is not None:
            return self._decompiler_info
        
        info = {
            "name": self.name,
            "available": self.is_available(),
            "path": self.ida_path,
            "executable": self._find_ida_executable(self.ida_path) if self.ida_path else None,
            "version": "unknown"
        }
        
        self._decompiler_info = info
        return info
        
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the decompiler.
        
        Returns:
            Dictionary containing decompiler information
        """
        return {
            "name": self.name,
            "version": "Not available",
            "capabilities": []
        }