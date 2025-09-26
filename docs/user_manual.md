# User Manual# User Manual# User Manual



## Introduction



RE-Architect is a comprehensive automated reverse engineering platform that transforms binary files into human-readable function summaries, data structure definitions, and executable test harnesses. This manual provides detailed guidance on using all features of the platform.## Command Line Usage## Introduction



## Getting Started



### PrerequisitesBasic analysis:RE-Architect is a comprehensive automated reverse engineering platform that transforms binary files into human-readable function summaries, data structure definitions, and executable test harnesses.



Before using RE-Architect, ensure you have:```bash



- Python 3.11 or higherpython main.py binary_file.exe## Getting Started

- At least 8GB RAM (16GB recommended for large binaries)

- One or more supported decompilers:```

  - Ghidra (recommended, free)

  - IDA Pro (commercial)### Prerequisites

  - Binary Ninja (commercial)

Specify output directory:

### Installation

```bashBefore using RE-Architect, ensure you have:

See the [Installation Guide](installation.md) for detailed setup instructions.

python main.py binary_file.exe --output results/- Python 3.11 or higher

### Configuration

```- At least 16GB RAM (recommended for large binaries)

RE-Architect uses a YAML configuration file (`config.yaml`) to manage settings:

- One of the supported decompilers:

```yaml

# Decompiler settingsUse specific decompiler:  - Ghidra (recommended, free)

decompilers:

  default: "ghidra"```bash  - IDA Pro (commercial)

  ghidra:

    path: "/path/to/ghidra"python main.py binary_file.exe --decompiler ghidra  - Binary Ninja (commercial)

    headless: true

  ida:```

    path: "/path/to/ida"

  binary_ninja:### Basic Usage

    path: "/path/to/binaryninja"

## Configuration File

# Analysis settings

analysis:1. **Analyze a binary file:**

  static:

    enable: trueThe config.yaml file contains decompiler paths and analysis settings:   ```bash

  dynamic:

    enable: false   python main.py /path/to/binary.exe

  data_structures:

    enable: true```yaml   ```



# LLM settings (optional)decompilers:

llm:

  enable: true  ghidra:2. **Specify output directory:**

  provider: "openai"

  model: "gpt-4-turbo"    enabled: true   ```bash

  api_key: "your-api-key"

  max_tokens: 8192    path: "/opt/ghidra"   python main.py /path/to/binary.exe --output-dir ./my_analysis



# Output settings  ida:   ```

output:

  format: "json"    enabled: false

  include_source: true

  generate_reports: true    path: "/opt/ida"3. **Use a specific decompiler:**

```

   ```bash

## Command Line Usage

analysis:   python main.py /path/to/binary.exe --decompiler ghidra

### Basic Analysis

  max_functions: 1000   ```

Analyze a binary with default settings:

  timeout: 300

```bash

python main.py binary_file.exe```4. **Generate test harnesses:**

```

   ```bash

### Advanced Options

## Output Files   python main.py /path/to/binary.exe --generate-tests

```bash

# Specify configuration file   ```

python main.py binary_file.exe --config custom_config.yaml

Analysis results are saved to the output directory:

# Set output directory

python main.py binary_file.exe --output ./analysis_results5. **Start web visualization:**



# Choose specific decompiler- functions.json - Extracted function information   ```bash

python main.py binary_file.exe --decompiler ghidra

- structures.json - Data structure definitions   python main.py /path/to/binary.exe --serve

# Enable test generation

python main.py binary_file.exe --generate-tests- decompiled/ - Decompiled source code   ```



# Verbose output

python main.py binary_file.exe --verbose

## Web Interface## Command Line Options

# Analyze multiple files

python main.py file1.exe file2.exe file3.exe

```

Start the web interface to view results:| Option | Description | Default |

### Full Command Reference

|--------|-------------|---------|

```bash

python main.py [OPTIONS] BINARY_FILES...```bash| `binary_path` | Path to the binary file to analyze | Required |



Options:python -m src.visualization.server| `--output-dir` | Directory to store output files | `./output` |

  --config PATH          Configuration file path (default: config.yaml)

  --output PATH          Output directory (default: ./output)```| `--config` | Path to configuration file | `./config.yaml` |

  --decompiler TEXT      Decompiler to use (ghidra|ida|binja|auto)

  --generate-tests       Generate test harnesses| `--decompiler` | Decompiler to use (ghidra/ida/binja/auto) | `auto` |

  --no-llm              Disable LLM analysis

  --format TEXT         Output format (json|html|text)Access at http://localhost:5000| `--verbose` | Increase verbosity (-v, -vv) | `false` |

  --verbose, -v         Enable verbose logging| `--no-llm` | Disable LLM-based analysis | `false` |

  --help               Show help message| `--generate-tests` | Generate test harnesses | `false` |

```| `--serve` | Start web server after analysis | `false` |



## Python API## Configuration



### Basic UsageRE-Architect uses a YAML configuration file to customize analysis behavior. The default configuration file is `config.yaml`.



```python### Key Configuration Sections

from src.core.pipeline import ReversePipeline

from src.core.config import Config#### Decompiler Settings

```yaml

# Load configurationdecompiler:

config = Config.from_file("config.yaml")  default: ghidra

  ghidra:

# Create pipeline    path: /path/to/ghidra  # Optional, auto-detected if null

pipeline = ReversePipeline(config)    headless: true

    timeout: 600

# Analyze binary  ida:

results = pipeline.analyze(    path: /path/to/ida

    binary_path="sample.exe",    headless: true 

    output_dir="./output",    timeout: 600

    decompiler="ghidra"  binary_ninja:

)    path: /path/to/binaryninja

    timeout: 600

# Process results```

print(f"Functions found: {len(results['functions'])}")

for func_name, func_info in results['functions'].items():#### Analysis Settings

    print(f"- {func_name}: {func_info['summary']}")```yaml

```analysis:

  static:

### Configuration Management    function_analysis_depth: medium  # basic, medium, deep

    data_flow_analysis: true

```python    control_flow_analysis: true

from src.core.config import Config    string_analysis: true

  dynamic:

# Load from file    enable: false

config = Config.from_file("config.yaml")    max_execution_time: 60

    memory_limit: 2048

# Create programmatically```

config = Config({

    "decompilers": {"default": "ghidra"},#### LLM Settings

    "llm": {"enable": False}```yaml

})llm:

  enable: true

# Modify settings  provider: openai  # openai, anthropic

config.set("output.format", "html")  model: gpt-4-turbo

config.set("analysis.dynamic.enable", True)  api_key: your_api_key_here  # Or set OPENAI_API_KEY env var

  max_tokens: 8192

# Access settings  temperature: 0.2

llm_enabled = config.get("llm.enable")```

default_decompiler = config.get("decompilers.default")

```## Understanding Results



## Analysis Features### Output Structure



### Static AnalysisAfter analysis, RE-Architect creates the following output structure:



RE-Architect performs comprehensive static analysis including:```

output/

- **Function Detection**: Identifies all functions and their boundaries├── metadata.json          # Analysis metadata and statistics

- **Control Flow Analysis**: Maps execution paths and decision points  ├── functions/            # Individual function analysis

- **Data Flow Analysis**: Tracks variable usage and dependencies│   ├── functions.json    # All functions summary

- **Call Graph Construction**: Shows relationships between functions│   └── 0x401000.json    # Individual function details

- **Complexity Analysis**: Calculates cyclomatic complexity metrics├── data_structures/      # Recovered data structures

│   ├── structures.json   # All structures summary

### Data Structure Recovery│   └── struct_1.json    # Individual structure details

├── test_harnesses/       # Generated test harnesses

The platform can automatically recover:│   ├── tests.json        # Test harnesses summary

│   └── func_401000.c    # Individual test files

- **Struct Definitions**: C-style structures with field types└── reports/             # Analysis reports

- **Class Hierarchies**: Object-oriented relationships    ├── summary.html      # Web report

- **Array Types**: Multi-dimensional arrays and their access patterns    └── analysis.md       # Markdown report

- **Pointer Relationships**: Complex pointer chains and indirection```

- **Union Types**: Discriminated and non-discriminated unions

### Function Analysis Results

### LLM-Enhanced Analysis

Each analyzed function includes:

When enabled, LLM integration provides:

- **Basic Information**: Name, address, size, complexity score

- **Function Summaries**: Natural language descriptions of function behavior- **Decompiled Code**: Human-readable C-like code

- **Variable Naming**: Meaningful names for variables and parameters- **LLM Summary**: Natural language description of functionality

- **Algorithm Detection**: Identification of common algorithms and patterns- **Parameters**: Identified function parameters and types

- **Security Assessment**: Potential vulnerabilities and security issues- **Return Values**: Return type and description

- **Optimization Suggestions**: Performance improvement recommendations- **Security Analysis**: Potential vulnerabilities and concerns

- **Call Graph**: Functions called and calling functions

## Decompiler Integration

### Data Structure Recovery

### Ghidra

RE-Architect identifies and recovers:

**Pros**: Free, excellent analysis, active development

**Cons**: Can be slower than commercial alternatives- **Structure Definitions**: Field names, types, and offsets

- **Union Types**: Overlapping data representations

Configuration:- **Array Structures**: Fixed-size and dynamic arrays

```yaml- **Pointer Relationships**: References between structures

decompilers:

  ghidra:### Test Harness Generation

    path: "/Applications/ghidra_10.3.2_PUBLIC"

    headless: trueWhen enabled, RE-Architect generates:

    java_args: ["-Xmx4G"]

    analysis_timeout: 300- **Standalone Test Files**: Compilable C code for individual functions

```- **Input Generation**: Realistic test inputs based on function analysis

- **Safety Constraints**: Memory safety checks and bounds validation

### IDA Pro- **Coverage Reports**: Analysis of code paths exercised



**Pros**: Industry standard, fastest analysis, extensive plugin ecosystem## Advanced Features

**Cons**: Expensive licensing

### Dynamic Analysis

Configuration:

```yamlEnable dynamic analysis for enhanced results:

decompilers:

  ida:```yaml

    path: "/Applications/IDA Pro 7.7/ida64.app/Contents/MacOS"analysis:

    batch_mode: true  dynamic:

    plugins: ["hex_rays"]    enable: true

```    sandbox_type: container  # container, vm, none

    max_execution_time: 120

### Binary Ninja    record_syscalls: true

    record_network: true

**Pros**: Modern interface, excellent API, reasonable pricing```

**Cons**: Smaller community, fewer plugins

Dynamic analysis provides:

Configuration:- Runtime behavior observation

```yaml- System call tracing

decompilers:- Network activity monitoring

  binary_ninja:- Memory access patterns

    path: "/Applications/Binary Ninja.app"

    headless: true### Custom LLM Providers

    license_file: "/path/to/license"

```Configure different LLM providers:



## Web Interface**OpenAI:**

```yaml

### Starting the Serverllm:

  provider: openai

```bash  model: gpt-4-turbo

python -m src.visualization.server  api_key: sk-...

``````



Options:**Anthropic:**

```bash```yaml

python -m src.visualization.server --host 0.0.0.0 --port 8080llm:

```  provider: anthropic  

  model: claude-3-opus-20240229

### Features  api_key: sk-ant-...

```

The web interface provides:

### Batch Processing

- **Interactive Function Explorer**: Browse and search functions

- **Call Graph Visualization**: Interactive call relationship diagrams  Process multiple binaries:

- **Data Structure Browser**: Explore recovered data types

- **Source Code Viewer**: Syntax-highlighted decompiled code```bash

- **Analysis Reports**: Detailed analysis summaries# Process all binaries in a directory

- **Export Options**: Save results in various formatsfor binary in /path/to/binaries/*; do

    python main.py "$binary" --output-dir "./analysis/$(basename "$binary")"

### Navigationdone

```

- **Dashboard**: Overview of analysis results and statistics

- **Functions**: Detailed function listings with search and filters## Performance Optimization

- **Data Types**: Recovered structures, classes, and type definitions

- **Graphs**: Visual representations of call graphs and dependencies### Memory Management

- **Reports**: Generated documentation and summaries

For large binaries:

## Output Formats```yaml

performance:

### JSON Output  memory_limit: 16384  # MB

  parallelism: 4       # Number of threads

Structured data suitable for programmatic processing:  disk_cache: true     # Enable disk caching

```

```json

{### Analysis Optimization

  "metadata": {

    "binary_path": "sample.exe",Balance speed vs. accuracy:

    "analysis_date": "2025-09-26T14:30:00Z",```yaml

    "decompiler": "ghidra"analysis:

  },  static:

  "functions": {    function_analysis_depth: basic  # Faster analysis

    "main": {  llm:

      "address": "0x401000",    max_tokens: 4000  # Reduce token usage

      "size": 156,    temperature: 0.1  # More consistent results

      "summary": "Program entry point that initializes application",```

      "complexity": 3.2,

      "calls": ["init_config", "run_main_loop"]## Troubleshooting

    }

  }### Common Issues

}

```**Decompiler not found:**

- Set the path explicitly in config.yaml

### HTML Reports- Check that the decompiler is installed and executable

- Verify PATH environment variable includes decompiler location

Human-readable documentation with:

- Executive summary**LLM API errors:**

- Function documentation  - Verify API key is set correctly

- Data structure definitions- Check network connectivity

- Code snippets with syntax highlighting- Monitor API rate limits and quotas

- Interactive elements

**Memory errors:**

### Text Format- Reduce memory limit in configuration

- Use basic analysis depth for large binaries

Plain text summaries suitable for documentation:- Enable disk caching

```

FUNCTION ANALYSIS REPORT**Slow analysis:**

========================- Use faster decompiler (Ghidra is typically fastest)

- Reduce LLM token limits

Binary: sample.exe- Disable dynamic analysis for faster results

Analyzed: 2025-09-26 14:30:00

### Log Analysis

FUNCTIONS (15 total):

  main (0x401000) - Program entry point [Complexity: 3.2]Enable detailed logging:

  init_config (0x401200) - Configuration initialization [Complexity: 1.8]```bash

  ...python main.py binary.exe --verbose --verbose

``````



## Test GenerationCheck log files:

- `re-architect.log` - Main application log

### Automatic Test Harnesses- `decompiler.log` - Decompiler-specific logs



RE-Architect can generate test harnesses for analyzed functions:## Integration



```python### CI/CD Integration

# Enable test generation

results = pipeline.analyze(Example GitHub Actions workflow:

    binary_path="sample.exe",

    generate_tests=True```yaml

)name: Binary Analysis

on: [push]

# Access generated testsjobs:

test_harnesses = results['test_harnesses']  analyze:

for function_name, test_code in test_harnesses.items():    runs-on: ubuntu-latest

    print(f"Test for {function_name}:")    steps:

    print(test_code)    - uses: actions/checkout@v3

```    - name: Setup Python

      uses: actions/setup-python@v4

### Test Types      with:

        python-version: '3.11'

- **Unit Tests**: Individual function testing with mock inputs    - name: Install RE-Architect

- **Integration Tests**: Multi-function workflow validation        run: pip install -r requirements.txt

- **Fuzzing Templates**: Input generation for security testing    - name: Analyze Binary

- **Performance Tests**: Benchmarking and profiling code      run: python main.py test_binary.exe --output-dir results

      env:

## Troubleshooting        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}

    - name: Upload Results

### Common Issues      uses: actions/upload-artifact@v3

      with:

**Decompiler Not Found**        name: analysis-results

```        path: results/

Error: Ghidra not found at specified path```

Solution: Update config.yaml with correct decompiler path

```### API Integration



**Analysis Timeout**Use RE-Architect programmatically:

```

Error: Analysis timed out after 300 seconds```python

Solution: Increase timeout in config or use simpler analysisfrom src.core.pipeline import ReversePipeline

```from src.core.config import Config



**Memory Issues**# Load configuration

```config = Config.from_file("config.yaml")

Error: Out of memory during analysis

Solution: Increase system RAM or reduce analysis scope# Create pipeline

```pipeline = ReversePipeline(config)



**Permission Errors**# Analyze binary

```results = pipeline.analyze(

Error: Cannot write to output directory    binary_path="path/to/binary.exe",

Solution: Check directory permissions and disk space    output_dir="./output",

```    decompiler="ghidra"

)

### Debug Mode

# Access results

Enable detailed logging for troubleshooting:functions = results["functions"]

data_structures = results["data_structures"]

```bashtest_harnesses = results["test_harnesses"]

python main.py binary_file.exe --verbose```

```

## Best Practices

Or in Python:

```python### Security Considerations

import logging

logging.basicConfig(level=logging.DEBUG)- **Isolated Environment**: Run analysis in containers or VMs

```- **Network Isolation**: Disable network access during analysis

- **Input Validation**: Verify binary integrity before analysis

### Performance Optimization- **Output Sanitization**: Review generated code before execution



For large binaries:### Analysis Workflow

- Use `--no-llm` to disable LLM analysis

- Increase system RAM1. **Initial Analysis**: Start with basic static analysis

- Use SSD storage for temporary files2. **Iterative Refinement**: Use results to guide deeper analysis

- Configure decompiler memory limits3. **Validation**: Cross-reference with multiple decompilers

4. **Documentation**: Document findings and analysis decisions

## Advanced Usage

### Performance Guidelines

### Batch Processing

- **Resource Planning**: Allocate sufficient memory and CPU

Analyze multiple binaries:- **Batch Processing**: Group similar binaries for efficient analysis

- **Result Caching**: Reuse analysis results where possible

```python- **Monitoring**: Track analysis performance and optimize accordingly

from pathlib import Path

from src.core.pipeline import ReversePipeline## Support



def analyze_directory(binary_dir, output_dir):For additional help:

    config = Config.from_file("config.yaml")- Check the GitHub repository for issues and discussions

    pipeline = ReversePipeline(config)- Review the API reference for programmatic usage

    - Consult the installation guide for setup problems

    for binary_file in Path(binary_dir).glob("*.exe"):- Join the community forums for user support
        try:
            result = pipeline.analyze(
                binary_path=binary_file,
                output_dir=output_dir / binary_file.stem
            )
            print(f"✓ Analyzed {binary_file.name}")
        except Exception as e:
            print(f"✗ Failed {binary_file.name}: {e}")
```

### Custom Analysis Pipelines

Create specialized analysis workflows:

```python
from src.analysis.static_analyzer import StaticAnalyzer
from src.analysis.data_structure_analyzer import DataStructureAnalyzer

# Custom pipeline with specific analyzers
def custom_analysis(binary_path):
    # Load binary
    loader = BinaryLoader()
    binary_info = loader.load(binary_path)
    
    # Decompile
    decompiler = DecompilerFactory().get_decompiler("ghidra")
    decompiled = decompiler.decompile(binary_info)
    
    # Custom static analysis
    static_analyzer = StaticAnalyzer(config)
    functions = static_analyzer.analyze(decompiled)
    
    # Data structure recovery
    ds_analyzer = DataStructureAnalyzer(config)
    structures = ds_analyzer.analyze(decompiled, functions)
    
    return {
        'functions': functions,
        'data_structures': structures
    }
```

## Integration

### CI/CD Integration

Example GitHub Actions workflow:

```yaml
name: Binary Analysis
on: [push]

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Python
        uses: actions/setup-python@v3
        with:
          python-version: '3.11'
      - name: Install RE-Architect
        run: |
          pip install -r requirements.txt
          pip install -e .
      - name: Analyze Binaries
        run: |
          python main.py binaries/*.exe --output reports/
      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: analysis-reports
          path: reports/
```

### IDE Integration

For VS Code, create a task in `.vscode/tasks.json`:

```json
{
    "version": "2.0.0",
    "tasks": [
        {
            "label": "Analyze Binary",
            "type": "shell",
            "command": "python",
            "args": ["main.py", "${input:binaryPath}"],
            "group": "build",
            "presentation": {
                "echo": true,
                "reveal": "always"
            }
        }
    ],
    "inputs": [
        {
            "id": "binaryPath",
            "description": "Path to binary file",
            "type": "promptString"
        }
    ]
}
```

## Support and Contributing

### Getting Help

- Check the [API Reference](api_reference.md) for detailed technical information
- Review example code in the `tests/` directory
- File issues on the GitHub repository
- Join community discussions

### Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality  
4. Submit a pull request with clear description

### Development Setup

```bash
# Clone repository
git clone https://github.com/pandaadir05/re-architect.git
cd re-architect

# Install development dependencies
pip install -r requirements-dev.txt
pip install -e .

# Run tests
pytest

# Run linting
flake8 src/ tests/
```

For more information, see the project's GitHub repository and documentation.