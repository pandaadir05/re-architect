# RE-Architect API Reference

This document provides detailed reference documentation for the RE-Architect Python API.

---

## Table of Contents

1. [Core Pipeline](#core-pipeline)
2. [Configuration](#configuration)
3. [Decompiler Integration](#decompiler-integration)
4. [Binary Loading](#binary-loading)
5. [Analysis Components](#analysis-components)
6. [LLM Integration](#llm-integration)
7. [Test Generation](#test-generation)
8. [Visualization](#visualization)
9. [Data Models](#data-models)
10. [Error Handling](#error-handling)
11. [Examples](#examples)
12. [Version Compatibility](#version-compatibility)
13. [Support](#support)

---

## Core Pipeline

### `ReversePipeline` Class

Main entry point for binary analysis.

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

config = Config.from_file("config.yaml")
pipeline = ReversePipeline(config)

results = pipeline.analyze(
    binary_path="path/to/binary.exe",
    output_dir="./output",
    decompiler="ghidra",
    generate_tests=True
)
```

#### Constructor

`__init__(config: Config)`
Initialize the pipeline with a configuration.

* **Parameters:**

  * `config` (Config): Analysis configuration

#### Methods

`analyze(binary_path, output_dir=None, decompiler="auto", generate_tests=False)`
Perform complete analysis of a binary.

* **Parameters:**

  * `binary_path` (str | Path): Path to binary
  * `output_dir` (str | Path, optional): Output directory
  * `decompiler` (str): `"ghidra" | "ida" | "binja" | "auto"`
  * `generate_tests` (bool): Whether to generate test harnesses

* **Returns:**

  * `dict`: Results with functions, data structures, and metadata

* **Raises:**

  * `DecompilerError`, `AnalysisError`, `FileNotFoundError`

---

## Configuration

### `Config` Class

Manages configuration from YAML or dictionaries.

```python
from src.core.config import Config

# Load from file
config = Config.from_file("config.yaml")

# Load from dict
config = Config({
    "decompiler": {"default": "ghidra"},
    "llm": {"enable": True, "provider": "openai"}
})
```

#### Methods

* `from_file(path: str) -> Config` — load from YAML
* `get(key: str, default=None)` — retrieve using dot notation
* `set(key: str, value)` — update value
* `disable_llm()` / `enable_llm()` — toggle LLM features

---

## Decompiler Integration

### `DecompilerFactory`

Factory for decompiler instances.

```python
from src.decompilers.decompiler_factory import DecompilerFactory

factory = DecompilerFactory()
decompiler = factory.create("ghidra")
if decompiler.is_available():
    results = decompiler.decompile(binary_info)
```

* `create(name: str) -> BaseDecompiler`
* Returns a decompiler instance (`ghidra`, `ida`, `binja`, or `auto`)

### `BaseDecompiler`

Abstract base class for all decompilers.

* `is_available() -> bool`
* `decompile(binary_info: BinaryInfo) -> DecompiledCode`
* `get_decompiler_info() -> dict`

---

## Binary Loading

### `BinaryLoader`

Loads and parses binaries.

```python
from src.core.binary_loader import BinaryLoader

loader = BinaryLoader()
binary_info = loader.load("binary.exe", auto_unpack=True)

print(binary_info.format, binary_info.architecture)
```

### `BinaryInfo`

Container with attributes:

* `path`, `format`, `architecture`, `bit_width`, `endianness`
* `entry_point`, `sections`, `symbols`, `imports`, `exports`
* `compiler`, `stripped`

---

## Analysis Components

* **StaticAnalyzer** — static analysis of code
* **DataStructureAnalyzer** — recover structs
* **EnhancedStaticAnalyzer** — deeper function analysis

```python
from src.analysis.static_analyzer import StaticAnalyzer

analyzer = StaticAnalyzer(config)
results = analyzer.analyze(decompiled_code)
```

---

## LLM Integration

### `FunctionSummarizer`

Generates LLM-based summaries.

```python
from src.llm.function_summarizer import FunctionSummarizer

summarizer = FunctionSummarizer(config)
summary = summarizer.analyze_function_enhanced(func_info, context)
batch = summarizer.analyze_batch_enhanced(functions, context)
```

**Outputs:** `FunctionSummary` objects with attributes:

* `name`, `purpose`, `behavior`, `complexity_analysis`
* `arguments`, `return_value`, `side_effects`, `security_notes`
* `optimization_suggestions`, `confidence_score`

---

## Test Generation

### `TestGenerator`

Generates per-function harnesses.

```python
from src.test_generation.test_generator import TestGenerator

generator = TestGenerator(config)
tests = generator.generate(functions, data_structures)
```

---

## Visualization

### Start Web Server

```bash
python -m src.visualization.server --host 0.0.0.0 --port 8080
```

### From Code

```python
from src.visualization.server import app
app.run(host="localhost", port=5000, debug=True)
```

---

## Data Models

* **DecompiledCode**: container for functions, strings, types
* **FunctionInfo**: function attributes (name, address, size, calls, etc.)
* **Instruction**: assembly instruction details

---

## Error Handling

Custom exceptions:

* `DecompilerError` — decompilation failure
* `AnalysisError` — analysis failure

```python
from src.core.exceptions import DecompilerError, AnalysisError
```

---

## Examples

### Full Pipeline

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

config = Config.from_file("config.yaml")
pipeline = ReversePipeline(config)

results = pipeline.analyze("sample_binary.exe", "./analysis", "ghidra", True)

print(f"Functions: {len(results['functions'])}")
print(f"Data structures: {len(results['data_structures'])}")
```

### Custom Decompiler

```python
from src.decompilers.base_decompiler import BaseDecompiler, DecompiledCode

class CustomDecompiler(BaseDecompiler):
    def is_available(self): return True
    def decompile(self, binary_info):
        dc = DecompiledCode(binary_info)
        dc.add_function(address=0x401000, code="int main(){return 0;}", name="main")
        return dc
```

---

## Version Compatibility

* **v1.0+**: Static analysis, LLM integration, web UI
* **v1.1+**: Dynamic analysis, batch mode
* **v1.2+**: Custom decompiler plugins, advanced test generation

---

## Support

* Source code: `src/` directory
* Examples: `tests/` directory
* Issues: [GitHub Issues](https://github.com/pandaadir05/re-architect/issues)
* Docs: [User Manual](user_manual.md)

---
