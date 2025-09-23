# User Manual

## Introduction

RE-Architect is a comprehensive automated reverse engineering platform that transforms binary files into human-readable function summaries, data structure definitions, and executable test harnesses.

## Getting Started

### Prerequisites

Before using RE-Architect, ensure you have:
- Python 3.11 or higher
- At least 16GB RAM (recommended for large binaries)
- One of the supported decompilers:
  - Ghidra (recommended, free)
  - IDA Pro (commercial)
  - Binary Ninja (commercial)

### Basic Usage

1. **Analyze a binary file:**
   ```bash
   python main.py /path/to/binary.exe
   ```

2. **Specify output directory:**
   ```bash
   python main.py /path/to/binary.exe --output-dir ./my_analysis
   ```

3. **Use a specific decompiler:**
   ```bash
   python main.py /path/to/binary.exe --decompiler ghidra
   ```

4. **Generate test harnesses:**
   ```bash
   python main.py /path/to/binary.exe --generate-tests
   ```

5. **Start web visualization:**
   ```bash
   python main.py /path/to/binary.exe --serve
   ```

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `binary_path` | Path to the binary file to analyze | Required |
| `--output-dir` | Directory to store output files | `./output` |
| `--config` | Path to configuration file | `./config.yaml` |
| `--decompiler` | Decompiler to use (ghidra/ida/binja/auto) | `auto` |
| `--verbose` | Increase verbosity (-v, -vv) | `false` |
| `--no-llm` | Disable LLM-based analysis | `false` |
| `--generate-tests` | Generate test harnesses | `false` |
| `--serve` | Start web server after analysis | `false` |

## Configuration

RE-Architect uses a YAML configuration file to customize analysis behavior. The default configuration file is `config.yaml`.

### Key Configuration Sections

#### Decompiler Settings
```yaml
decompiler:
  default: ghidra
  ghidra:
    path: /path/to/ghidra  # Optional, auto-detected if null
    headless: true
    timeout: 600
  ida:
    path: /path/to/ida
    headless: true 
    timeout: 600
  binary_ninja:
    path: /path/to/binaryninja
    timeout: 600
```

#### Analysis Settings
```yaml
analysis:
  static:
    function_analysis_depth: medium  # basic, medium, deep
    data_flow_analysis: true
    control_flow_analysis: true
    string_analysis: true
  dynamic:
    enable: false
    max_execution_time: 60
    memory_limit: 2048
```

#### LLM Settings
```yaml
llm:
  enable: true
  provider: openai  # openai, anthropic
  model: gpt-4-turbo
  api_key: your_api_key_here  # Or set OPENAI_API_KEY env var
  max_tokens: 8192
  temperature: 0.2
```

## Understanding Results

### Output Structure

After analysis, RE-Architect creates the following output structure:

```
output/
├── metadata.json          # Analysis metadata and statistics
├── functions/            # Individual function analysis
│   ├── functions.json    # All functions summary
│   └── 0x401000.json    # Individual function details
├── data_structures/      # Recovered data structures
│   ├── structures.json   # All structures summary
│   └── struct_1.json    # Individual structure details
├── test_harnesses/       # Generated test harnesses
│   ├── tests.json        # Test harnesses summary
│   └── func_401000.c    # Individual test files
└── reports/             # Analysis reports
    ├── summary.html      # Web report
    └── analysis.md       # Markdown report
```

### Function Analysis Results

Each analyzed function includes:

- **Basic Information**: Name, address, size, complexity score
- **Decompiled Code**: Human-readable C-like code
- **LLM Summary**: Natural language description of functionality
- **Parameters**: Identified function parameters and types
- **Return Values**: Return type and description
- **Security Analysis**: Potential vulnerabilities and concerns
- **Call Graph**: Functions called and calling functions

### Data Structure Recovery

RE-Architect identifies and recovers:

- **Structure Definitions**: Field names, types, and offsets
- **Union Types**: Overlapping data representations
- **Array Structures**: Fixed-size and dynamic arrays
- **Pointer Relationships**: References between structures

### Test Harness Generation

When enabled, RE-Architect generates:

- **Standalone Test Files**: Compilable C code for individual functions
- **Input Generation**: Realistic test inputs based on function analysis
- **Safety Constraints**: Memory safety checks and bounds validation
- **Coverage Reports**: Analysis of code paths exercised

## Advanced Features

### Dynamic Analysis

Enable dynamic analysis for enhanced results:

```yaml
analysis:
  dynamic:
    enable: true
    sandbox_type: container  # container, vm, none
    max_execution_time: 120
    record_syscalls: true
    record_network: true
```

Dynamic analysis provides:
- Runtime behavior observation
- System call tracing
- Network activity monitoring
- Memory access patterns

### Custom LLM Providers

Configure different LLM providers:

**OpenAI:**
```yaml
llm:
  provider: openai
  model: gpt-4-turbo
  api_key: sk-...
```

**Anthropic:**
```yaml
llm:
  provider: anthropic  
  model: claude-3-opus-20240229
  api_key: sk-ant-...
```

### Batch Processing

Process multiple binaries:

```bash
# Process all binaries in a directory
for binary in /path/to/binaries/*; do
    python main.py "$binary" --output-dir "./analysis/$(basename "$binary")"
done
```

## Performance Optimization

### Memory Management

For large binaries:
```yaml
performance:
  memory_limit: 16384  # MB
  parallelism: 4       # Number of threads
  disk_cache: true     # Enable disk caching
```

### Analysis Optimization

Balance speed vs. accuracy:
```yaml
analysis:
  static:
    function_analysis_depth: basic  # Faster analysis
  llm:
    max_tokens: 4000  # Reduce token usage
    temperature: 0.1  # More consistent results
```

## Troubleshooting

### Common Issues

**Decompiler not found:**
- Set the path explicitly in config.yaml
- Check that the decompiler is installed and executable
- Verify PATH environment variable includes decompiler location

**LLM API errors:**
- Verify API key is set correctly
- Check network connectivity
- Monitor API rate limits and quotas

**Memory errors:**
- Reduce memory limit in configuration
- Use basic analysis depth for large binaries
- Enable disk caching

**Slow analysis:**
- Use faster decompiler (Ghidra is typically fastest)
- Reduce LLM token limits
- Disable dynamic analysis for faster results

### Log Analysis

Enable detailed logging:
```bash
python main.py binary.exe --verbose --verbose
```

Check log files:
- `re-architect.log` - Main application log
- `decompiler.log` - Decompiler-specific logs

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
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    - name: Install RE-Architect
      run: pip install -r requirements.txt
    - name: Analyze Binary
      run: python main.py test_binary.exe --output-dir results
      env:
        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
    - name: Upload Results
      uses: actions/upload-artifact@v3
      with:
        name: analysis-results
        path: results/
```

### API Integration

Use RE-Architect programmatically:

```python
from src.core.pipeline import ReversePipeline
from src.core.config import Config

# Load configuration
config = Config.from_file("config.yaml")

# Create pipeline
pipeline = ReversePipeline(config)

# Analyze binary
results = pipeline.analyze(
    binary_path="path/to/binary.exe",
    output_dir="./output",
    decompiler="ghidra"
)

# Access results
functions = results["functions"]
data_structures = results["data_structures"]
test_harnesses = results["test_harnesses"]
```

## Best Practices

### Security Considerations

- **Isolated Environment**: Run analysis in containers or VMs
- **Network Isolation**: Disable network access during analysis
- **Input Validation**: Verify binary integrity before analysis
- **Output Sanitization**: Review generated code before execution

### Analysis Workflow

1. **Initial Analysis**: Start with basic static analysis
2. **Iterative Refinement**: Use results to guide deeper analysis
3. **Validation**: Cross-reference with multiple decompilers
4. **Documentation**: Document findings and analysis decisions

### Performance Guidelines

- **Resource Planning**: Allocate sufficient memory and CPU
- **Batch Processing**: Group similar binaries for efficient analysis
- **Result Caching**: Reuse analysis results where possible
- **Monitoring**: Track analysis performance and optimize accordingly

## Support

For additional help:
- Check the GitHub repository for issues and discussions
- Review the API reference for programmatic usage
- Consult the installation guide for setup problems
- Join the community forums for user support