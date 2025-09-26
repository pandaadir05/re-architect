# API Reference# API Reference



## Basic Usage## Python API



```python```python

from src.core.pipeline import ReversePipelinefrom src.core.pipeline import ReversePipeline

from src.core.config import Configfrom src.core.config import Config



# Initialize# Initialize

config = Config.from_file("config.yaml")config = Config.from_file("config.yaml")

pipeline = ReversePipeline(config)pipeline = ReversePipeline(config)



# Analyze binary# Analyze binary

results = pipeline.analyze("binary.exe")results = pipeline.analyze(

    binary_path="path/to/binary.exe",

# Access results    output_dir="./output",

functions = results["functions"]    decompiler="ghidra",

metadata = results["metadata"]    generate_tests=True

```)

```

## Configuration

#### Methods

```python

# Load config from file##### `__init__(config: Config)`

config = Config.from_file("config.yaml")

Initialize the pipeline with configuration.

# Access settings

decompiler_path = config.get("decompilers.ghidra.path")**Parameters:**

```- `config`: Configuration object containing analysis settings

##### `analyze(binary_path, output_dir=None, decompiler="auto", generate_tests=False)`

Perform complete analysis of a binary file.

**Parameters:**
- `binary_path` (str or Path): Path to the binary file
- `output_dir` (str or Path, optional): Output directory for results
- `decompiler` (str): Decompiler to use ("ghidra", "ida", "binja", "auto")
- `generate_tests` (bool): Whether to generate test harnesses

**Returns:**
- `dict`: Analysis results containing functions, data structures, and metadata

**Example:**
```python
results = pipeline.analyze(
    "binary.exe",
    output_dir="./analysis",
    decompiler="ghidra",
    generate_tests=True
)

# Access results
functions = results["functions"]
metadata = results["metadata"]
data_structures = results["data_structures"]
```

### Configuration

#### Config Class

```python
from src.core.config import Config

# Load from file
config = Config.from_file("config.yaml")

# Load from dictionary
config = Config({
    "decompiler": {"default": "ghidra"},
    "llm": {"enable": True, "provider": "openai"}
})

# Access values
decompiler = config.get("decompiler.default")
llm_enabled = config.get("llm.enable")
```

##### Methods

##### `from_file(path: str) -> Config`

Load configuration from YAML file.

##### `get(key: str, default=None)`

Get configuration value using dot notation.

##### `set(key: str, value)`

Set configuration value using dot notation.

##### `disable_llm()`

Disable LLM-based analysis.

## Decompiler Integration

### DecompilerFactory

Factory for creating decompiler instances.

```python
from src.decompilers.decompiler_factory import DecompilerFactory

factory = DecompilerFactory()
decompiler = factory.get_decompiler("ghidra")

if decompiler.is_available():
    results = decompiler.decompile(binary_info)
```

### BaseDecompiler

Abstract base class for all decompilers.

#### Methods

##### `is_available() -> bool`

Check if the decompiler is available on the system.

##### `decompile(binary_info: BinaryInfo) -> DecompiledCode`

Decompile a binary file.

##### `get_decompiler_info() -> dict`

Get information about the decompiler.

### Specific Decompilers

#### GhidraDecompiler

```python
from src.decompilers.ghidra_decompiler import GhidraDecompiler

decompiler = GhidraDecompiler(ghidra_path="/path/to/ghidra")
```

#### IDADecompiler

```python
from src.decompilers.ida_decompiler import IDADecompiler

decompiler = IDADecompiler(ida_path="/path/to/ida")
```

#### BinaryNinjaDecompiler

```python
from src.decompilers.binary_ninja_decompiler import BinaryNinjaDecompiler

decompiler = BinaryNinjaDecompiler(binja_path="/path/to/binaryninja")
```

## Binary Loading

### BinaryLoader

Handles loading and parsing binary files.

```python
from src.core.binary_loader import BinaryLoader

loader = BinaryLoader()
binary_info = loader.load("binary.exe")

print(f"Format: {binary_info.format}")
print(f"Architecture: {binary_info.architecture}")
```

### BinaryInfo

Container for binary file information.

**Attributes:**
- `path`: Path to the binary file
- `format`: Binary format (PE, ELF, Mach-O)
- `architecture`: Target architecture (x86, x64, ARM)
- `entry_point`: Entry point address
- `sections`: List of binary sections

## Analysis Components

### StaticAnalyzer

Performs static analysis of decompiled code.

```python
from src.analysis.static_analyzer import StaticAnalyzer

analyzer = StaticAnalyzer(config)
results = analyzer.analyze(decompiled_code)
```

### DataStructureAnalyzer

Recovers data structures from binary analysis.

```python
from src.analysis.data_structure_analyzer import DataStructureAnalyzer

analyzer = DataStructureAnalyzer(config)
structures = analyzer.analyze(decompiled_code, static_analysis)
```

### EnhancedStaticAnalyzer

Advanced static analysis with detailed function information.

```python
from src.analysis.enhanced_static_analyzer import EnhancedStaticAnalyzer

analyzer = EnhancedStaticAnalyzer()
functions = analyzer.analyze_functions(binary_info)
```

## LLM Integration

### FunctionSummarizer

Generates human-readable function summaries using LLMs.

```python
from src.llm.function_summarizer import FunctionSummarizer

config = {
    "provider": "openai",
    "model": "gpt-4-turbo", 
    "api_key": "your-key-here",
    "max_tokens": 8192
}

summarizer = FunctionSummarizer(config)

# Analyze single function (enhanced)
summary = summarizer.analyze_function_enhanced(func_info, context)

# Batch analysis
results = summarizer.analyze_batch_enhanced(functions, context)

# Legacy analysis
text_summary = summarizer.summarize_function(function_code)
```

#### FunctionSummary Class

Result object from enhanced analysis.

**Attributes:**
- `name`: Function name
- `purpose`: Brief description of function purpose
- `behavior`: Detailed behavior analysis
- `complexity_analysis`: Complexity assessment
- `arguments`: List of function arguments
- `return_value`: Return value description
- `side_effects`: List of side effects
- `security_notes`: Security-related observations
- `optimization_suggestions`: Performance improvement suggestions
- `confidence_score`: Confidence in the analysis (0.0-1.0)

## Test Generation

### TestGenerator

Generates test harnesses for analyzed functions.

```python
from src.test_generation.test_generator import TestGenerator

generator = TestGenerator(config)
test_harnesses = generator.generate(functions, data_structures)
```

## Visualization

### VisualizationServer

Web server for interactive result exploration.

```python
from src.visualization.server import VisualizationServer

server = VisualizationServer(host="localhost", port=5000)
server.load_results(analysis_results)
server.start()
```

### Mock Data Generation

For testing and development.

```python
from src.visualization.mock_data import generate_mock_analysis_results

mock_results = generate_mock_analysis_results(
    num_functions=50,
    num_data_structures=15
)
```

## Data Models

### DecompiledCode

Container for decompilation results.

```python
decompiled = DecompiledCode(binary_info)

# Add function
decompiled.add_function(address, code, name, metadata)

# Add string
decompiled.add_string(address, value)

# Add data type
decompiled.add_type(name, definition)

# Access data
functions = decompiled.functions
strings = decompiled.strings
types = decompiled.types
```

### FunctionInfo (Enhanced Analysis)

Detailed function information from enhanced static analysis.

**Attributes:**
- `name`: Function name
- `address`: Start address
- `size`: Function size in bytes
- `instructions`: List of Instruction objects
- `complexity`: Complexity score
- `has_loops`: Whether function contains loops
- `entry_point`: Entry point address
- `calls`: List of function calls made

### Instruction

Individual assembly instruction.

**Attributes:**
- `address`: Instruction address
- `mnemonic`: Instruction mnemonic
- `op_str`: Operand string
- `bytes`: Raw instruction bytes

## Error Handling

### Common Exceptions

#### `DecompilerError`

Raised when decompiler operations fail.

```python
from src.core.exceptions import DecompilerError

try:
    results = decompiler.decompile(binary_info)
except DecompilerError as e:
    print(f"Decompilation failed: {e}")
```

#### `AnalysisError`

Raised when analysis operations fail.

```python
from src.core.exceptions import AnalysisError

try:
    analysis = analyzer.analyze(decompiled_code)
except AnalysisError as e:
    print(f"Analysis failed: {e}")
```

## Logging

RE-Architect uses Python's logging module. Configure logging levels:

```python
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)

# Get RE-Architect logger
logger = logging.getLogger("re-architect")
logger.setLevel(logging.DEBUG)
```

## Examples

### Complete Analysis Example

```python
import logging
from pathlib import Path
from src.core.pipeline import ReversePipeline
from src.core.config import Config

# Setup logging
logging.basicConfig(level=logging.INFO)

# Load configuration
config = Config.from_file("config.yaml")

# Customize configuration
config.set("llm.enable", True)
config.set("llm.provider", "openai")
config.set("llm.api_key", "your-api-key")

# Create pipeline
pipeline = ReversePipeline(config)

# Analyze binary
binary_path = Path("sample_binary.exe")
output_dir = Path("./analysis_results")

results = pipeline.analyze(
    binary_path=binary_path,
    output_dir=output_dir,
    decompiler="ghidra",
    generate_tests=True
)

# Process results
print(f"Analysis completed:")
print(f"Functions analyzed: {len(results['functions'])}")
print(f"Data structures found: {len(results['data_structures'])}")
print(f"Test harnesses generated: {len(results['test_harnesses'])}")

# Access specific function
main_func = results['functions'].get('main')
if main_func:
    print(f"Main function summary: {main_func['summary']}")
```

### Custom Decompiler Integration

```python
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode
from src.core.binary_loader import BinaryInfo

class CustomDecompiler(BaseDecompiler):
    def __init__(self):
        super().__init__()
        self.name = "CustomDecompiler"
    
    def is_available(self) -> bool:
        # Check if custom decompiler is available
        return True
    
    def decompile(self, binary_info: BinaryInfo) -> DecompiledCode:
        # Implement custom decompilation logic
        decompiled = DecompiledCode(binary_info)
        
        # Add functions, strings, types, etc.
        decompiled.add_function(
            address=0x401000,
            code="int main() { return 0; }",
            name="main",
            metadata={"signature": "int main(void)"}
        )
        
        return decompiled
    
    def get_decompiler_info(self) -> dict:
        return {
            "name": self.name,
            "version": "1.0",
            "available": self.is_available()
        }

# Use custom decompiler
decompiler = CustomDecompiler()
binary_info = BinaryLoader().load("binary.exe")
results = decompiler.decompile(binary_info)
```

### Batch Processing

```python
from pathlib import Path
from src.core.pipeline import ReversePipeline
from src.core.config import Config

def analyze_directory(binary_dir: Path, output_dir: Path):
    """Analyze all binaries in a directory."""
    config = Config.from_file("config.yaml")
    pipeline = ReversePipeline(config)
    
    results = {}
    
    for binary_file in binary_dir.glob("*.exe"):
        print(f"Analyzing {binary_file.name}...")
        
        try:
            analysis_output = output_dir / binary_file.stem
            result = pipeline.analyze(
                binary_path=binary_file,
                output_dir=analysis_output,
                decompiler="auto"
            )
            results[binary_file.name] = result
            print(f"✓ {binary_file.name} analyzed successfully")
            
        except Exception as e:
            print(f"✗ {binary_file.name} failed: {e}")
            results[binary_file.name] = {"error": str(e)}
    
    return results

# Use batch processing
binary_directory = Path("./binaries")
output_directory = Path("./batch_analysis")
results = analyze_directory(binary_directory, output_directory)
```

## Version Compatibility

This API reference is for RE-Architect version 1.0+. For version-specific features:

- Enhanced static analysis: v1.0+
- LLM integration: v1.0+
- Web visualization: v1.0+
- Test generation: v1.0+

## Support

For API-related questions:
- Check the source code in the `src/` directory
- Review unit tests in `tests/` for usage examples
- File issues on the GitHub repository
- Consult the user manual for high-level concepts