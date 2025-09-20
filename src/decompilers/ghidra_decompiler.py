"""
Ghidra decompiler integration for RE-Architect.

This module provides integration with the Ghidra decompiler.
"""

import logging
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Dict, List, Optional, Union, Any
import json

from src.core.binary_loader import BinaryInfo
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode

logger = logging.getLogger("re-architect.decompilers.ghidra")

class GhidraDecompiler(BaseDecompiler):
    """
    Ghidra decompiler integration.
    
    This class provides integration with the Ghidra decompiler,
    using Ghidra's headless analyzer and decompiler.
    """
    
    def __init__(self, ghidra_path: Optional[str] = None):
        """
        Initialize the Ghidra decompiler.
        
        Args:
            ghidra_path: Path to Ghidra installation directory (optional)
        """
        super().__init__()
        self.name = "GhidraDecompiler"
        
        # Try to find Ghidra path if not provided
        self.ghidra_path = ghidra_path or self._find_ghidra_path()
        
        # Cache decompiler info
        self._decompiler_info = None
    
    def _find_ghidra_path(self) -> Optional[str]:
        """
        Find the Ghidra installation directory.
        
        Looks for Ghidra in common installation locations or via environment variables.
        
        Returns:
            Path to Ghidra installation directory, or None if not found
        """
        # Check environment variable
        if "GHIDRA_INSTALL_DIR" in os.environ:
            path = os.environ["GHIDRA_INSTALL_DIR"]
            if os.path.exists(path):
                return path
        
        # Check common installation locations
        common_paths = [
            # Windows paths
            "C:/Program Files/Ghidra",
            "C:/Ghidra",
            os.path.expanduser("~/Ghidra"),
            
            # Unix paths
            "/opt/ghidra",
            "/usr/local/ghidra",
            os.path.expanduser("~/ghidra")
        ]
        
        for base_path in common_paths:
            if os.path.exists(base_path):
                # Look for support/analyzeHeadless script
                if os.path.exists(os.path.join(base_path, "support", "analyzeHeadless")):
                    return base_path
                
                # Check subdirectories (for versioned installs)
                for item in os.listdir(base_path):
                    sub_path = os.path.join(base_path, item)
                    if os.path.isdir(sub_path) and os.path.exists(os.path.join(sub_path, "support", "analyzeHeadless")):
                        return sub_path
        
        return None
    
    def is_available(self) -> bool:
        """
        Check if Ghidra is available for use.
        
        Returns:
            True if Ghidra is available, False otherwise
        """
        if not self.ghidra_path:
            logger.warning("Ghidra path not found")
            return False
        
        headless_script = self._get_headless_script_path()
        if not os.path.exists(headless_script):
            logger.warning(f"Ghidra headless script not found at {headless_script}")
            return False
        
        return True
    
    def _get_headless_script_path(self) -> str:
        """
        Get the path to the Ghidra headless script.
        
        Returns:
            Path to the analyzeHeadless script
        """
        if os.name == "nt":  # Windows
            return os.path.join(self.ghidra_path, "support", "analyzeHeadless.bat")
        else:  # Unix-like
            return os.path.join(self.ghidra_path, "support", "analyzeHeadless")
    
    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        """
        Decompile a binary file using Ghidra.
        
        Args:
            binary_info: Information about the binary to decompile
            
        Returns:
            DecompiledCode object containing decompilation results
            
        Raises:
            RuntimeError: If decompilation fails
        """
        if not self.is_available():
            raise RuntimeError("Ghidra is not available")
        
        logger.info(f"Decompiling {binary_info.path} using Ghidra")
        
        # Create a temporary project directory
        with tempfile.TemporaryDirectory(prefix="re-architect-ghidra-") as temp_dir:
            project_dir = os.path.join(temp_dir, "project")
            project_name = "re-architect"
            
            # Create output directory
            output_dir = os.path.join(temp_dir, "output")
            os.makedirs(output_dir, exist_ok=True)
            
            # Path to the export script
            export_script = self._create_export_script(temp_dir, output_dir)
            
            # Run Ghidra headless analyzer
            headless_script = self._get_headless_script_path()
            binary_path = str(binary_info.path)
            
            cmd = [
                headless_script,
                project_dir,
                project_name,
                "-import", binary_path,
                "-postScript", export_script,
                "-scriptPath", temp_dir,
                "-deleteProject"
            ]
            
            logger.debug(f"Running Ghidra command: {cmd}")
            
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                # Wait for the process to complete with a timeout
                try:
                    stdout, stderr = process.communicate(timeout=600)  # 10-minute timeout
                    
                    if process.returncode != 0:
                        logger.error(f"Ghidra decompilation failed with code {process.returncode}")
                        logger.error(f"Stdout: {stdout}")
                        logger.error(f"Stderr: {stderr}")
                        raise RuntimeError(f"Ghidra decompilation failed with code {process.returncode}")
                    
                except subprocess.TimeoutExpired:
                    process.kill()
                    logger.error("Ghidra decompilation timed out")
                    raise RuntimeError("Ghidra decompilation timed out after 10 minutes")
                
                # Parse the output files
                return self._parse_output(binary_info, output_dir)
                
            except Exception as e:
                logger.exception(f"Error running Ghidra: {e}")
                raise RuntimeError(f"Error running Ghidra: {str(e)}")
    
    def _create_export_script(self, script_dir: str, output_dir: str) -> str:
        """
        Create a Ghidra script to export decompiled code.
        
        Args:
            script_dir: Directory to write the script to
            output_dir: Directory to write the output to
            
        Returns:
            Path to the created script
        """
        script_path = os.path.join(script_dir, "ExportDecompiledCode.java")
        
        script_content = f"""
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;
import java.io.*;
import java.util.*;
import com.google.gson.*;

public class ExportDecompiledCode extends GhidraScript {{
    private static final String OUTPUT_DIR = "{output_dir.replace(os.sep, '/')}";
    
    
    @Override
    public void run() throws Exception {{
        println("Starting decompilation export script");
        
        // Create output directory if it doesn't exist
        File outDir = new File(OUTPUT_DIR);
        if (!outDir.exists()) {{
            outDir.mkdirs();
        }}
        
        // Export program info
        exportProgramInfo();
        
        // Export functions
        exportFunctions();
        
        // Export strings
        exportStrings();
        
        // Export data types
        exportDataTypes();
        
        println("Export complete");
    }}
    
    private void exportProgramInfo() throws Exception {{
        println("Exporting program info");
        
        JsonObject json = new JsonObject();
        json.addProperty("name", currentProgram.getName());
        json.addProperty("language", currentProgram.getLanguage().getLanguageID().toString());
        json.addProperty("compiler", currentProgram.getCompiler());
        json.addProperty("creationDate", new Date().toString());
        
        // Add memory layout info
        JsonArray memoryArray = new JsonArray();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {{
            JsonObject memBlock = new JsonObject();
            memBlock.addProperty("name", block.getName());
            memBlock.addProperty("start", block.getStart().toString());
            memBlock.addProperty("end", block.getEnd().toString());
            memBlock.addProperty("size", block.getSize());
            memBlock.addProperty("readable", block.isRead());
            memBlock.addProperty("writable", block.isWrite());
            memBlock.addProperty("executable", block.isExecute());
            memoryArray.add(memBlock);
        }}
        json.add("memoryBlocks", memoryArray);
        
        // Write to file
        try (FileWriter writer = new FileWriter(new File(OUTPUT_DIR, "program_info.json"))) {{
            writer.write(json.toString());
        }}
    }}
    
    private void exportFunctions() throws Exception {{
        println("Exporting functions");
        
        // Create functions directory
        File functionsDir = new File(OUTPUT_DIR, "functions");
        if (!functionsDir.exists()) {{
            functionsDir.mkdirs();
        }}
        
        DecompileOptions options = new DecompileOptions();
        DecompInterface decompInterface = new DecompInterface();
        decompInterface.setOptions(options);
        
        if (!decompInterface.openProgram(currentProgram)) {{
            println("Decompiler error: " + decompInterface.getLastMessage());
            return;
        }}
        
        // Create a JSON array for all functions
        JsonArray allFunctionsArray = new JsonArray();
        
        // Process all functions
        FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        
        for (Function function : functions) {{
            monitor.checkCancelled();
            
            Address entryPoint = function.getEntryPoint();
            String address = entryPoint.toString();
            String name = function.getName();
            
            println("Decompiling function: " + name + " at " + address);
            
            // Create JSON object for function info
            JsonObject functionJson = new JsonObject();
            functionJson.addProperty("address", address);
            functionJson.addProperty("name", name);
            functionJson.addProperty("signature", function.getSignature().toString());
            functionJson.addProperty("entryPoint", entryPoint.toString());
            
            // Add parameter info
            JsonArray paramsArray = new JsonArray();
            for (Parameter param : function.getParameters()) {{
                JsonObject paramJson = new JsonObject();
                paramJson.addProperty("name", param.getName());
                paramJson.addProperty("dataType", param.getDataType().toString());
                paramJson.addProperty("length", param.getLength());
                paramJson.addProperty("ordinal", param.getOrdinal());
                paramsArray.add(paramJson);
            }}
            functionJson.add("parameters", paramsArray);
            
            // Add return type info
            functionJson.addProperty("returnType", function.getReturnType().toString());
            
            // Add calling convention
            functionJson.addProperty("callingConvention", function.getCallingConvention().toString());
            
            // Add references (calls made by this function)
            JsonArray referencesArray = new JsonArray();
            ReferenceIterator refs = currentProgram.getReferenceManager().getReferences(function.getBody());
            for (Reference ref : refs) {{
                if (ref.getReferenceType().isCall()) {{
                    Function calledFunction = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
                    if (calledFunction != null) {{
                        JsonObject refJson = new JsonObject();
                        refJson.addProperty("fromAddress", ref.getFromAddress().toString());
                        refJson.addProperty("toAddress", ref.getToAddress().toString());
                        refJson.addProperty("toFunction", calledFunction.getName());
                        referencesArray.add(refJson);
                    }}
                }}
            }}
            functionJson.add("calls", referencesArray);
            
            // Decompile the function
            DecompileResults results = decompInterface.decompileFunction(function, 30, monitor);
            if (results.decompileCompleted()) {{
                // Get the C code
                ClangTokenGroup tokens = results.getCCodeMarkup();
                String code = tokens.toString();
                functionJson.addProperty("code", code);
                
                // Export to individual file
                String safeAddress = address.replace(":", "_");
                try (FileWriter writer = new FileWriter(new File(functionsDir, safeAddress + ".c"))) {{
                    writer.write(code);
                }}
            }} else {{
                println("Failed to decompile function: " + name);
                functionJson.addProperty("decompilationError", results.getErrorMessage());
            }}
            
            allFunctionsArray.add(functionJson);
            count++;
        }}
        
        println("Decompiled " + count + " functions");
        
        // Write all function info to a single file
        try (FileWriter writer = new FileWriter(new File(OUTPUT_DIR, "functions.json"))) {{
            writer.write(allFunctionsArray.toString());
        }}
    }}
    
    private void exportStrings() throws Exception {{
        println("Exporting strings");
        
        DataIterator dataIterator = currentProgram.getListing().getDefinedData(true);
        JsonArray stringsArray = new JsonArray();
        int count = 0;
        
        while (dataIterator.hasNext()) {{
            Data data = dataIterator.next();
            if (data.isString()) {{
                monitor.checkCancelled();
                
                JsonObject stringJson = new JsonObject();
                stringJson.addProperty("address", data.getAddress().toString());
                stringJson.addProperty("value", data.getValue().toString());
                stringJson.addProperty("length", data.getLength());
                stringJson.addProperty("dataType", data.getDataType().getName());
                
                stringsArray.add(stringJson);
                count++;
            }}
        }}
        
        println("Found " + count + " strings");
        
        // Write strings to file
        try (FileWriter writer = new FileWriter(new File(OUTPUT_DIR, "strings.json"))) {{
            writer.write(stringsArray.toString());
        }}
    }}
    
    private void exportDataTypes() throws Exception {{
        println("Exporting data types");
        
        DataTypeManager dtm = currentProgram.getDataTypeManager();
        JsonArray typesArray = new JsonArray();
        int count = 0;
        
        // Export structures
        CategoryPath structPath = new CategoryPath("/Structure");
        if (dtm.containsCategory(structPath)) {{
            Category structCategory = dtm.getCategory(structPath);
            exportCategory(structCategory, typesArray);
            count += typesArray.size();
        }}
        
        println("Exported " + count + " data types");
        
        // Write data types to file
        try (FileWriter writer = new FileWriter(new File(OUTPUT_DIR, "data_types.json"))) {{
            writer.write(typesArray.toString());
        }}
    }}
    
    private void exportCategory(Category category, JsonArray typesArray) {{
        for (DataType dt : category.getDataTypes()) {{
            if (dt instanceof Structure) {{
                Structure struct = (Structure) dt;
                JsonObject structJson = new JsonObject();
                structJson.addProperty("name", struct.getName());
                structJson.addProperty("path", struct.getCategoryPath().getPath());
                structJson.addProperty("size", struct.getLength());
                
                JsonArray fieldsArray = new JsonArray();
                for (int i = 0; i < struct.getNumComponents(); i++) {{
                    DataTypeComponent component = struct.getComponent(i);
                    JsonObject fieldJson = new JsonObject();
                    fieldJson.addProperty("name", component.getFieldName());
                    fieldJson.addProperty("dataType", component.getDataType().getName());
                    fieldJson.addProperty("offset", component.getOffset());
                    fieldJson.addProperty("size", component.getLength());
                    fieldsArray.add(fieldJson);
                }}
                structJson.add("fields", fieldsArray);
                
                typesArray.add(structJson);
            }}
        }}
        
        // Process subcategories
        for (Category subCategory : category.getCategories()) {{
            exportCategory(subCategory, typesArray);
        }}
    }}
}}
"""
        
        with open(script_path, "w") as f:
            f.write(script_content)
        
        return script_path
    
    def _parse_output(self, binary_info: BinaryInfo, output_dir: str) -> DecompiledCode:
        """
        Parse the output files from Ghidra.
        
        Args:
            binary_info: Information about the decompiled binary
            output_dir: Directory containing the output files
            
        Returns:
            DecompiledCode object containing decompilation results
        """
        logger.info("Parsing Ghidra output")
        
        decompiled_code = DecompiledCode(binary_info)
        
        # Parse program info
        program_info_file = os.path.join(output_dir, "program_info.json")
        if os.path.exists(program_info_file):
            with open(program_info_file, "r") as f:
                program_info = json.load(f)
                logger.debug(f"Loaded program info: {program_info}")
        
        # Parse functions
        functions_file = os.path.join(output_dir, "functions.json")
        if os.path.exists(functions_file):
            with open(functions_file, "r") as f:
                functions_data = json.load(f)
                
                for func_data in functions_data:
                    address = int(func_data["address"].split(":")[-1], 16)
                    name = func_data["name"]
                    
                    # Get the function code
                    if "code" in func_data:
                        code = func_data["code"]
                    else:
                        # Try to load from individual file
                        safe_address = func_data["address"].replace(":", "_")
                        func_file = os.path.join(output_dir, "functions", f"{safe_address}.c")
                        if os.path.exists(func_file):
                            with open(func_file, "r") as func_f:
                                code = func_f.read()
                        else:
                            code = "// Decompilation failed"
                    
                    # Extract metadata
                    metadata = {
                        "signature": func_data.get("signature", ""),
                        "returnType": func_data.get("returnType", ""),
                        "callingConvention": func_data.get("callingConvention", ""),
                        "parameters": func_data.get("parameters", []),
                        "calls": func_data.get("calls", []),
                        "decompilationError": func_data.get("decompilationError", None)
                    }
                    
                    decompiled_code.add_function(address, code, name, metadata)
                
                logger.info(f"Loaded {len(functions_data)} functions")
        
        # Parse strings
        strings_file = os.path.join(output_dir, "strings.json")
        if os.path.exists(strings_file):
            with open(strings_file, "r") as f:
                strings_data = json.load(f)
                
                for string_data in strings_data:
                    address = int(string_data["address"].split(":")[-1], 16)
                    value = string_data["value"]
                    decompiled_code.add_string(address, value)
                
                logger.info(f"Loaded {len(strings_data)} strings")
        
        # Parse data types
        data_types_file = os.path.join(output_dir, "data_types.json")
        if os.path.exists(data_types_file):
            with open(data_types_file, "r") as f:
                types_data = json.load(f)
                
                for type_data in types_data:
                    name = type_data["name"]
                    # Convert to C-like structure definition
                    definition = self._convert_to_c_struct(type_data)
                    decompiled_code.add_type(name, definition)
                
                logger.info(f"Loaded {len(types_data)} data types")
        
        return decompiled_code
    
    def _convert_to_c_struct(self, struct_data: Dict) -> str:
        """
        Convert a struct definition from Ghidra's JSON format to C code.
        
        Args:
            struct_data: Structure data from Ghidra
            
        Returns:
            C structure definition
        """
        name = struct_data["name"]
        fields = struct_data.get("fields", [])
        
        lines = [f"struct {name} {{"]
        
        for field in fields:
            field_name = field.get("name", "field")
            field_type = field.get("dataType", "undefined")
            lines.append(f"    {field_type} {field_name};")
        
        lines.append("};")
        
        return "\n".join(lines)
    
    def get_decompiler_info(self) -> Dict:
        """
        Get information about the Ghidra decompiler.
        
        Returns:
            Dictionary containing decompiler information
        """
        if self._decompiler_info is not None:
            return self._decompiler_info
        
        info = {
            "name": self.name,
            "available": self.is_available(),
            "path": self.ghidra_path,
            "version": "unknown"
        }
        
        # Try to get version information
        if self.is_available():
            try:
                # Version file is usually in the Ghidra root directory
                version_file = os.path.join(self.ghidra_path, "Ghidra", "application.properties")
                if os.path.exists(version_file):
                    with open(version_file, "r") as f:
                        for line in f:
                            if line.startswith("application.version="):
                                info["version"] = line.split("=")[1].strip()
                                break
            except Exception as e:
                logger.warning(f"Error getting Ghidra version: {e}")
        
        self._decompiler_info = info
        return info
